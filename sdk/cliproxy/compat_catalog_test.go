package cliproxy

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// TestCompatCatalogTargetsOnlySupportedProviders asserts that only the providers
// whose live model list is supported are targeted, and that a disabled provider is
// not.
func TestCompatCatalogTargetsOnlySupportedProviders(t *testing.T) {
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

	targets := compatCatalogTargets(cfg)
	if len(targets) != 2 {
		t.Fatalf("targets len = %d, want 2: %+v", len(targets), targets)
	}
	for _, target := range targets {
		if target.name == "unknown" || target.name == "disabled" {
			t.Fatalf("an unsupported or disabled provider was targeted: %+v", target)
		}
	}
}

// TestCompatCatalogLiveModelsAreMatchedByTheFullTargetIdentity asserts that a
// discovered list is only returned for the entry it was read for.
//
// Two entries can share a name, and a reload can change an entry's base URL, so
// the name alone does not identify what a list belongs to.
func TestCompatCatalogLiveModelsAreMatchedByTheFullTargetIdentity(t *testing.T) {
	t.Parallel()

	service := &Service{cfg: &config.Config{}}
	manager := newCompatCatalogManager(service)

	first := compatCatalogTarget{entryIndex: 0, name: "shared", baseURL: "https://openrouter.ai/api/v1", apiKey: "k"}
	second := compatCatalogTarget{entryIndex: 1, name: "shared", baseURL: "https://openrouter.ai/api/v1", apiKey: "k"}
	third := compatCatalogTarget{entryIndex: 0, name: "shared", baseURL: "https://api.example.com/v1", apiKey: "k"}

	manager.mu.Lock()
	manager.state[first.key()] = &compatCatalogState{
		target: first,
		models: []config.CompatCatalogModel{{ID: "model-a"}},
	}
	manager.mu.Unlock()

	if live := manager.liveModelsFor(first); len(live) != 1 {
		t.Fatalf("live models = %+v, want one", live)
	}
	// A different entry with the same name must not see the list.
	if live := manager.liveModelsFor(second); len(live) != 0 {
		t.Fatalf("live models = %+v, want none for a different entry", live)
	}
	// A different base URL must not see the list either.
	if live := manager.liveModelsFor(third); len(live) != 0 {
		t.Fatalf("live models = %+v, want none for a different base URL", live)
	}
}

// TestCompatCatalogRefreshDoesNotQueryAnUnsupportedProvider asserts that a
// provider with no supported live model list is never queried.
func TestCompatCatalogRefreshDoesNotQueryAnUnsupportedProvider(t *testing.T) {
	t.Parallel()

	service := &Service{cfg: &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{Name: "unknown", BaseURL: "https://api.example.com/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "k"}}},
		},
	}}
	manager := newCompatCatalogManager(service)
	manager.fetcher = func(_ context.Context, _ string, _ string, _ string) ([]byte, int, error) {
		t.Fatal("the reader must not query an unsupported provider")
		return nil, 0, nil
	}

	manager.Refresh(context.Background())
}

// TestOpenAICompatibilityExclusionMatchesTheUpstreamName asserts that an exclusion
// is matched against the upstream model name, not the public alias.
//
// An alias can be anything, so an exclusion written for the upstream model must
// still keep that model from being published and routed.
func TestOpenAICompatibilityExclusionMatchesTheUpstreamName(t *testing.T) {
	t.Parallel()

	compat := &config.OpenAICompatibility{
		Name:           "ollama-cloud",
		BaseURL:        "https://ollama.com/v1",
		ExcludedModels: []string{"anthropic/claude-sonnet-4.5"},
		Models: []config.OpenAICompatibilityModel{
			{Name: "anthropic/claude-sonnet-4.5", Alias: "claude-sonnet-4.5"},
			{Name: "deepseek-v4.1-flash", Alias: "deepseek-v4.1-flash"},
		},
	}

	models := buildOpenAICompatibilityConfigModels(compat)
	for _, model := range models {
		if model.ID == "claude-sonnet-4.5" {
			t.Fatalf("the excluded model was published under its alias: %+v", models)
		}
	}
	if len(models) != 1 || models[0].ID != "deepseek-v4.1-flash" {
		t.Fatalf("models = %+v, want only the non-excluded model", models)
	}
}

// TestCompatCatalogModelsForKeepsTheConfigurationUntouched asserts that the
// models a provider's live list contributed are merged into a copy, never into the
// configuration the operator wrote.
//
// The configuration is handed to the management API and a supported configuration
// write saves it back to the file. A discovered row written back would become a
// permanent pin that the live list could never take back.
func TestCompatCatalogModelsForKeepsTheConfigurationUntouched(t *testing.T) {
	t.Parallel()

	service := &Service{cfg: &config.Config{}}
	manager := newCompatCatalogManager(service)

	operator := []config.OpenAICompatibilityModel{{Name: "operator-model", Alias: "operator-model"}}
	compat := &config.OpenAICompatibility{
		Name:    "ollama-cloud",
		BaseURL: "https://ollama.com/v1",
		Models:  operator,
	}

	target := compatCatalogTarget{
		entryIndex: 0,
		name:       compat.Name,
		baseURL:    compat.BaseURL,
		apiKey:     "k",
	}
	manager.mu.Lock()
	manager.state[target.key()] = &compatCatalogState{
		target: target,
		models: []config.CompatCatalogModel{{ID: "discovered-model"}},
	}
	manager.mu.Unlock()

	merged := manager.modelsFor(compat)
	if len(merged.Models) != 2 {
		t.Fatalf("merged models = %+v, want the operator's row and the discovered one", merged.Models)
	}
	// The configuration the operator wrote is unchanged.
	if len(compat.Models) != 1 || compat.Models[0].Name != "operator-model" {
		t.Fatalf("the configuration was changed: %+v", compat.Models)
	}
	// The merged entry is a copy.
	if merged == compat {
		t.Fatal("the merged entry must be a copy")
	}
}

// TestCompatCatalogRefreshIsolatesProviders asserts that a provider which never
// completes its response does not stop the other providers from being read.
//
// The providers are read on their own goroutines, so one stalled provider cannot
// block the others or prevent the results they did return from being published.
func TestCompatCatalogRefreshIsolatesProviders(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{Name: "ollama-cloud", BaseURL: "https://ollama.com/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "k"}}},
			{Name: "openrouter", BaseURL: "https://openrouter.ai/api/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "k"}}},
		},
	}
	service := &Service{cfg: cfg}
	manager := newCompatCatalogManager(service)

	stalled := make(chan struct{})
	var stalledOnce sync.Once
	manager.fetcher = func(_ context.Context, endpoint, _, _ string) ([]byte, int, error) {
		if strings.Contains(endpoint, "ollama.com") {
			stalledOnce.Do(func() { close(stalled) })
			<-stalled
			return nil, 0, context.Canceled
		}
		return []byte(`{"data":[{"id":"openrouter-model"}]}`), 200, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		manager.Refresh(ctx)
		close(done)
	}()

	// The stalled provider is reached, and the other one has still answered.
	select {
	case <-stalled:
	case <-time.After(10 * time.Second):
		t.Fatal("the stalled provider was never reached")
	}

	// The answered provider's list is available even though the other one has not
	// returned. The state is read under the manager's lock, because the refresh
	// writes it.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		manager.mu.Lock()
		found := false
		for _, state := range manager.state {
			if state != nil && state.target.name == "openrouter" && len(state.models) == 1 {
				found = true
				break
			}
		}
		manager.mu.Unlock()
		if found {
			cancel()
			<-done
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	t.Fatal("the answered provider's result was not recorded while the other one stalled")
}

// TestCompatCatalogPublishDoesNotChangeTheConfiguration asserts that publishing the
// live model lists leaves the configuration alone.
//
// The configuration is handed to the management API, and a supported configuration
// write saves it back to the file. A discovered row written back would lose its
// origin and become a permanent operator pin the live list could never take back.
func TestCompatCatalogPublishDoesNotChangeTheConfiguration(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{
				Name:    "ollama-cloud",
				BaseURL: "https://ollama.com/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{
					{APIKey: "k"},
				},
				Models: []config.OpenAICompatibilityModel{{Name: "operator-model", Alias: "operator-model"}},
			},
		},
	}
	service := &Service{cfg: cfg}
	manager := newCompatCatalogManager(service)

	target := compatCatalogTarget{
		entryIndex: 0,
		name:       "ollama-cloud",
		baseURL:    "https://ollama.com/v1",
		apiKey:     "k",
	}
	manager.mu.Lock()
	manager.state[target.key()] = &compatCatalogState{
		target: target,
		models: []config.CompatCatalogModel{{ID: "discovered-model"}},
	}
	manager.mu.Unlock()

	manager.publishLiveModels(context.Background())

	// The configuration still holds only the operator's row.
	if len(cfg.OpenAICompatibility[0].Models) != 1 {
		t.Fatalf("the configuration was changed: %+v", cfg.OpenAICompatibility[0].Models)
	}
	if cfg.OpenAICompatibility[0].Models[0].Name != "operator-model" {
		t.Fatalf("the configuration was changed: %+v", cfg.OpenAICompatibility[0].Models)
	}
}
