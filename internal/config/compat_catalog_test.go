package config

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestCompatCatalogProviderForRecognizesSupportedHosts(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"https://ollama.com/v1":           "ollama-cloud",
		"https://openrouter.ai/api/v1":    "openrouter",
		"https://ai-gateway.vercel.sh/v1": "vercel",
	}
	for baseURL, wantID := range cases {
		provider := CompatCatalogProviderFor(baseURL)
		if provider == nil {
			t.Fatalf("CompatCatalogProviderFor(%q) = nil, want %q", baseURL, wantID)
		}
		if provider.ID != wantID {
			t.Fatalf("CompatCatalogProviderFor(%q).ID = %q, want %q", baseURL, provider.ID, wantID)
		}
	}
}

func TestCompatCatalogProviderForRejectsUnsafeOrUnknownHosts(t *testing.T) {
	t.Parallel()

	for _, baseURL := range []string{
		"http://ollama.com/v1",
		"https://user@ollama.com/v1",
		"https://ollama.com:8443/v1",
		"https://ollama.com/v1?x=1",
		"https://ollama.com.evil.example/v1",
		"https://api.example.com/v1",
		"",
	} {
		if got := CompatCatalogProviderFor(baseURL); got != nil {
			t.Fatalf("CompatCatalogProviderFor(%q) = %+v, want nil", baseURL, got)
		}
	}
}

func TestCompatCatalogModelListReadsTheProviderList(t *testing.T) {
	t.Parallel()

	var requestedEndpoint string
	var requestedKey string
	fetcher := func(_ context.Context, endpoint, apiKey string) ([]byte, int, error) {
		requestedEndpoint = endpoint
		requestedKey = apiKey
		body := `{"data":[{"id":"deepseek-v4.1-flash","name":"DeepSeek V4.1 Flash","context_length":131072},{"id":"glm-5.3"}]}`
		return []byte(body), http.StatusOK, nil
	}

	models, errList := CompatCatalogModelList(context.Background(), "https://ollama.com/v1", "ollama-key", fetcher)
	if errList != nil {
		t.Fatalf("CompatCatalogModelList: %v", errList)
	}
	if len(models) != 2 {
		t.Fatalf("models len = %d, want 2", len(models))
	}
	if models[0].ID != "deepseek-v4.1-flash" {
		t.Fatalf("models[0].ID = %q", models[0].ID)
	}
	if models[0].DisplayName != "DeepSeek V4.1 Flash" {
		t.Fatalf("models[0].DisplayName = %q", models[0].DisplayName)
	}
	if models[0].ContextLength != 131072 {
		t.Fatalf("models[0].ContextLength = %d", models[0].ContextLength)
	}
	if requestedEndpoint != "https://ollama.com/v1/models" {
		t.Fatalf("endpoint = %q", requestedEndpoint)
	}
	if requestedKey != "ollama-key" {
		t.Fatalf("wrong key was sent: %q", requestedKey)
	}
}

func TestCompatCatalogModelListUsesTheProviderEndpointNotTheConfiguredPath(t *testing.T) {
	t.Parallel()

	var requestedEndpoint string
	fetcher := func(_ context.Context, endpoint, _ string) ([]byte, int, error) {
		requestedEndpoint = endpoint
		return []byte(`{"data":[{"id":"m1"}]}`), http.StatusOK, nil
	}

	// The configured base URL carries a different path; the endpoint must be the
	// provider's own model list endpoint, so the key only ever reaches the origin
	// it was configured for.
	if _, errList := CompatCatalogModelList(context.Background(), "https://openrouter.ai/api/v1", "", fetcher); errList != nil {
		t.Fatalf("CompatCatalogModelList: %v", errList)
	}
	if requestedEndpoint != "https://openrouter.ai/api/v1/models" {
		t.Fatalf("endpoint = %q", requestedEndpoint)
	}
}

func TestCompatCatalogModelListRequiresAKeyWhereTheProviderNeedsOne(t *testing.T) {
	t.Parallel()

	fetcher := func(_ context.Context, _ string, _ string) ([]byte, int, error) {
		t.Fatal("the reader must not query a provider that needs a key without one")
		return nil, 0, nil
	}
	if _, errList := CompatCatalogModelList(context.Background(), "https://ollama.com/v1", "", fetcher); errList == nil {
		t.Fatal("expected an error when the required key is missing")
	}
}

func TestCompatCatalogModelListRejectsBadResponses(t *testing.T) {
	t.Parallel()

	upstreamError := func(_ context.Context, _ string, _ string) ([]byte, int, error) {
		return []byte(`{"error":"nope"}`), http.StatusForbidden, nil
	}
	if _, errList := CompatCatalogModelList(context.Background(), "https://ollama.com/v1", "k", upstreamError); errList == nil {
		t.Fatal("expected an error for a non-2xx response")
	}

	emptyList := func(_ context.Context, _ string, _ string) ([]byte, int, error) {
		return []byte(`{"data":[]}`), http.StatusOK, nil
	}
	if _, errList := CompatCatalogModelList(context.Background(), "https://ollama.com/v1", "k", emptyList); errList == nil {
		t.Fatal("expected an error for an empty model list")
	}

	malformed := func(_ context.Context, _ string, _ string) ([]byte, int, error) {
		return []byte(`not json`), http.StatusOK, nil
	}
	if _, errList := CompatCatalogModelList(context.Background(), "https://ollama.com/v1", "k", malformed); errList == nil {
		t.Fatal("expected an error for a malformed model list")
	}
}

func TestCompatCatalogModelListSkipsEntriesWithoutAnID(t *testing.T) {
	t.Parallel()

	fetcher := func(_ context.Context, _ string, _ string) ([]byte, int, error) {
		return []byte(`{"data":[{"id":""},{"id":"  "},{"id":"good"}]}`), http.StatusOK, nil
	}
	models, errList := CompatCatalogModelList(context.Background(), "https://ollama.com/v1", "k", fetcher)
	if errList != nil {
		t.Fatalf("CompatCatalogModelList: %v", errList)
	}
	if len(models) != 1 || models[0].ID != "good" {
		t.Fatalf("models = %+v", models)
	}
}

func TestMergeCompatCatalogModelsKeepsConfiguredModelsAndAddsLiveOnes(t *testing.T) {
	t.Parallel()

	configured := []OpenAICompatibilityModel{
		{Name: "deepseek-v4.1-flash", Alias: "deepseek-v4.1-flash"},
		{Name: "glm-5.3", Alias: "glm-5.3"},
	}
	live := []CompatCatalogModel{
		{ID: "deepseek-v4.1-flash"},
		{ID: "kimi-k3"},
	}

	merged := MergeCompatCatalogModels(configured, live, nil)
	if len(merged) != 3 {
		t.Fatalf("merged len = %d, want 3: %+v", len(merged), merged)
	}
	// The configured models keep their order and their identity.
	if merged[0].Name != "deepseek-v4.1-flash" || merged[1].Name != "glm-5.3" {
		t.Fatalf("configured models changed order or identity: %+v", merged)
	}
	// The live model that is new is added.
	if merged[2].Name != "kimi-k3" || merged[2].Alias != "kimi-k3" {
		t.Fatalf("live model not added: %+v", merged[2])
	}
}

func TestMergeCompatCatalogModelsNeverRemovesAPinnedModel(t *testing.T) {
	t.Parallel()

	// The operator pinned a model the live list does not carry.
	configured := []OpenAICompatibilityModel{
		{Name: "pinned-model", Alias: "pinned-alias"},
	}
	live := []CompatCatalogModel{{ID: "other-model"}}

	merged := MergeCompatCatalogModels(configured, live, nil)
	if len(merged) != 2 {
		t.Fatalf("merged len = %d, want 2: %+v", len(merged), merged)
	}
	if merged[0].Name != "pinned-model" || merged[0].Alias != "pinned-alias" {
		t.Fatalf("the pinned model was changed: %+v", merged[0])
	}
}

func TestMergeCompatCatalogModelsDoesNotResurrectAnExcludedModel(t *testing.T) {
	t.Parallel()

	// The operator excluded "gone-model". It must not come back from the live list.
	configured := []OpenAICompatibilityModel{
		{Name: "kept-model", Alias: "kept-model"},
	}
	live := []CompatCatalogModel{
		{ID: "gone-model"},
		{ID: "kept-model"},
	}

	merged := MergeCompatCatalogModels(configured, live, []string{"gone-model"})
	for _, model := range merged {
		if model.Name == "gone-model" {
			t.Fatalf("an excluded model came back: %+v", merged)
		}
	}
	if len(merged) != 1 {
		t.Fatalf("merged len = %d, want 1: %+v", len(merged), merged)
	}
}

func TestCompatCatalogModelExcludedMatchesWildcards(t *testing.T) {
	t.Parallel()

	cases := []struct {
		model    string
		excluded []string
		want     bool
	}{
		{model: "gemini-2.5-pro", excluded: []string{"gemini-2.5-pro"}, want: true},
		{model: "gemini-2.5-pro", excluded: []string{"gemini-2.5-flash"}, want: false},
		{model: "gemini-2.5-flash", excluded: []string{"gemini-2.5-*"}, want: true},
		{model: "gemini-3-pro-preview", excluded: []string{"*-preview"}, want: true},
		{model: "gemini-2.5-flash-lite", excluded: []string{"*flash*"}, want: true},
		{model: "gemini-2.5-pro", excluded: []string{"*flash*"}, want: false},
		{model: "GEMINI-2.5-PRO", excluded: []string{"gemini-2.5-pro"}, want: true},
		{model: "anything", excluded: nil, want: false},
	}
	for _, testCase := range cases {
		got := CompatCatalogModelExcluded(testCase.model, testCase.excluded)
		if got != testCase.want {
			t.Fatalf("CompatCatalogModelExcluded(%q, %v) = %v, want %v",
				testCase.model, testCase.excluded, got, testCase.want)
		}
	}
}

func TestMergeCompatCatalogModelsWithNoLiveListKeepsTheConfiguredList(t *testing.T) {
	t.Parallel()

	configured := []OpenAICompatibilityModel{
		{Name: "only-model", Alias: "only-model"},
	}
	merged := MergeCompatCatalogModels(configured, nil, nil)
	if len(merged) != 1 || merged[0].Name != "only-model" {
		t.Fatalf("merged = %+v", merged)
	}
}

func TestMergeCompatCatalogModelsDoesNotDuplicateAConfiguredModel(t *testing.T) {
	t.Parallel()

	// The configured model is identified by its upstream name; a live entry with
	// the same name must not create a second row.
	configured := []OpenAICompatibilityModel{
		{Name: "deepseek-v4.1-flash", Alias: "friendly-name"},
	}
	live := []CompatCatalogModel{{ID: "deepseek-v4.1-flash"}}

	merged := MergeCompatCatalogModels(configured, live, nil)
	if len(merged) != 1 {
		t.Fatalf("merged len = %d, want 1: %+v", len(merged), merged)
	}
	if merged[0].Alias != "friendly-name" {
		t.Fatalf("the configured alias was replaced: %+v", merged[0])
	}
}

func TestCompatCatalogModelListNeverReturnsTheKeyInAModelName(t *testing.T) {
	t.Parallel()

	fetcher := func(_ context.Context, _ string, _ string) ([]byte, int, error) {
		return []byte(`{"data":[{"id":"model-a"}]}`), http.StatusOK, nil
	}
	models, errList := CompatCatalogModelList(context.Background(), "https://ollama.com/v1", "super-secret", fetcher)
	if errList != nil {
		t.Fatalf("CompatCatalogModelList: %v", errList)
	}
	for _, model := range models {
		if strings.Contains(model.ID, "super-secret") || strings.Contains(model.DisplayName, "super-secret") {
			t.Fatal("the model list carries the API key")
		}
	}
}
