package cliproxy

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// compatCatalogTestConfig builds a configuration with one Ollama Cloud provider
// that has a configured model list.
func compatCatalogTestConfig() *config.Config {
	return &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{
				Name:    "ollama-cloud",
				BaseURL: "https://ollama.com/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{
					{APIKey: "ollama-key"},
				},
				Models: []config.OpenAICompatibilityModel{
					{Name: "deepseek-v4.1-flash", Alias: "deepseek-v4.1-flash"},
				},
			},
		},
	}
}

func TestCompatCatalogProvidersOnlyTargetsSupportedProviders(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{Name: "ollama-cloud", BaseURL: "https://ollama.com/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "k"}}},
			{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "k"}}},
			{Name: "unknown", BaseURL: "https://api.example.com/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "k"}}},
			{Name: "disabled", BaseURL: "https://ollama.com/v1", Disabled: true,
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "k"}}},
		},
	}

	targets := compatCatalogProviders(cfg)
	if len(targets) != 2 {
		t.Fatalf("targets len = %d, want 2: %+v", len(targets), targets)
	}
	for _, target := range targets {
		if target.name == "unknown" || target.name == "disabled" {
			t.Fatalf("an unsupported or disabled provider was targeted: %+v", target)
		}
	}
}

func TestCompatCatalogRefreshKeepsTheConfiguredListWhenTheProviderFails(t *testing.T) {
	t.Parallel()

	service := &Service{cfg: compatCatalogTestConfig()}
	manager := newCompatCatalogManager(service)
	manager.fetcher = func(_ context.Context, _ string, _ string) ([]byte, int, error) {
		return nil, http.StatusInternalServerError, nil
	}

	manager.Refresh(context.Background())

	if live := manager.LiveModels("ollama-cloud"); len(live) != 0 {
		t.Fatalf("a failed refresh stored a model list: %+v", live)
	}
	// The configured list is untouched, so the proxy still serves it.
	if len(service.cfg.OpenAICompatibility[0].Models) != 1 {
		t.Fatalf("the configured list was changed: %+v", service.cfg.OpenAICompatibility[0].Models)
	}
}

func TestCompatCatalogRefreshStoresTheLiveList(t *testing.T) {
	t.Parallel()

	service := &Service{cfg: compatCatalogTestConfig()}
	manager := newCompatCatalogManager(service)
	manager.fetcher = func(_ context.Context, _ string, _ string) ([]byte, int, error) {
		body := `{"data":[{"id":"deepseek-v4.1-flash"},{"id":"kimi-k3"}]}`
		return []byte(body), http.StatusOK, nil
	}

	manager.Refresh(context.Background())

	live := manager.LiveModels("ollama-cloud")
	if len(live) != 2 {
		t.Fatalf("live models = %+v", live)
	}
}

func TestCompatCatalogRefreshDoesNotStoreAnUnchangedListAsChanged(t *testing.T) {
	t.Parallel()

	service := &Service{cfg: compatCatalogTestConfig()}
	manager := newCompatCatalogManager(service)
	manager.fetcher = func(_ context.Context, _ string, _ string) ([]byte, int, error) {
		body := `{"data":[{"id":"kimi-k3"}]}`
		return []byte(body), http.StatusOK, nil
	}

	// The first refresh stores the list and reports a change.
	if !manager.refreshProvider(context.Background(), compatCatalogProviderTarget{
		name:    "ollama-cloud",
		baseURL: "https://ollama.com/v1",
		apiKey:  "ollama-key",
	}) {
		t.Fatal("the first refresh should report a change")
	}
	// The second refresh sees the same list and reports no change, so the proxy does
	// not re-register the credentials for nothing.
	if manager.refreshProvider(context.Background(), compatCatalogProviderTarget{
		name:    "ollama-cloud",
		baseURL: "https://ollama.com/v1",
		apiKey:  "ollama-key",
	}) {
		t.Fatal("an unchanged list should not report a change")
	}
}

func TestCompatCatalogApplyLiveModelsMergesIntoTheConfiguredList(t *testing.T) {
	t.Parallel()

	service := &Service{cfg: compatCatalogTestConfig()}
	manager := newCompatCatalogManager(service)
	manager.fetcher = func(_ context.Context, _ string, _ string) ([]byte, int, error) {
		body := `{"data":[{"id":"kimi-k3"}]}`
		return []byte(body), http.StatusOK, nil
	}

	manager.Refresh(context.Background())

	models := service.cfg.OpenAICompatibility[0].Models
	if len(models) != 2 {
		t.Fatalf("models = %+v, want the configured model plus the live one", models)
	}
	if models[0].Name != "deepseek-v4.1-flash" {
		t.Fatalf("the configured model changed: %+v", models[0])
	}
	if models[1].Name != "kimi-k3" {
		t.Fatalf("the live model was not added: %+v", models[1])
	}
}

func TestCompatCatalogApplyLiveModelsKeepsAnExcludedModelOut(t *testing.T) {
	t.Parallel()

	cfg := compatCatalogTestConfig()
	cfg.OpenAICompatibility[0].ExcludedModels = []string{"kimi-*"}
	service := &Service{cfg: cfg}
	manager := newCompatCatalogManager(service)
	manager.fetcher = func(_ context.Context, _ string, _ string) ([]byte, int, error) {
		body := `{"data":[{"id":"kimi-k3"},{"id":"glm-5.3"}]}`
		return []byte(body), http.StatusOK, nil
	}

	manager.Refresh(context.Background())

	for _, model := range service.cfg.OpenAICompatibility[0].Models {
		if model.Name == "kimi-k3" {
			t.Fatalf("an excluded model was added: %+v", service.cfg.OpenAICompatibility[0].Models)
		}
	}
}

func TestCompatCatalogRefreshIsBounded(t *testing.T) {
	t.Parallel()

	service := &Service{cfg: compatCatalogTestConfig()}
	manager := newCompatCatalogManager(service)
	manager.fetcher = func(ctx context.Context, _ string, _ string) ([]byte, int, error) {
		// The provider never answers in time. The refresh must give up on it.
		<-ctx.Done()
		return nil, 0, ctx.Err()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		manager.Refresh(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the refresh did not respect the context deadline")
	}
}
