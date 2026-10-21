package cliproxy

import (
	"context"
	"testing"

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
