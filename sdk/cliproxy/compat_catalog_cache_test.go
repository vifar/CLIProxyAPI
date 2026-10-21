package cliproxy

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// TestCompatCatalogCacheIsDiscardedWhenTheLiveListsChange asserts that a
// registration cache is discarded once the live model lists have changed.
//
// A registration batch that started before a discovery would otherwise resume
// with its cached rows and overwrite the discovery's models.
func TestCompatCatalogCacheIsDiscardedWhenTheLiveListsChange(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{
				Name:    "ollama-cloud",
				BaseURL: "https://ollama.com/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{
					{APIKey: "k"},
				},
			},
		},
	}
	service := &Service{cfg: cfg}
	manager := newCompatCatalogManager(service)
	service.compatCatalog = manager

	cache := newOpenAICompatibilityRegistrationCacheForConfig(cfg, manager)
	if !service.compatCatalogCacheIsCurrent(cache) {
		t.Fatal("a cache built at the current generation must be current")
	}

	// A discovery changes the live lists. The reader is replaced, so the test
	// does not reach the provider and does not need a credential.
	manager.fetcher = func(_ context.Context, _ string, _ string, _ string) ([]byte, int, error) {
		return []byte(`{"data":[{"id":"discovered-model"}]}`), 200, nil
	}
	target := compatCatalogTarget{
		entryIndex: 0,
		name:       "ollama-cloud",
		baseURL:    "https://ollama.com/v1",
		apiKey:     "k",
	}
	manager.refreshProvider(context.Background(), target)

	if service.compatCatalogCacheIsCurrent(cache) {
		t.Fatal("a cache built before the change must be discarded")
	}

	// A cache built after the change is current again.
	fresh := newOpenAICompatibilityRegistrationCacheForConfig(cfg, manager)
	if !service.compatCatalogCacheIsCurrent(fresh) {
		t.Fatal("a cache built after the change must be current")
	}
}

// TestCompatCatalogEffectiveProxyPrefersThePerKeyProxy asserts that the proxy a
// live model list is read through is the same one in the refresh and in the
// registration.
//
// A provider read through its per-key proxy would otherwise never publish its
// models, because the registration looked the list up with the global proxy.
func TestCompatCatalogEffectiveProxyPrefersThePerKeyProxy(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}
	cfg.ProxyURL = "http://global-proxy.example.com:8080"
	provider := &config.OpenAICompatibility{
		Name:    "ollama-cloud",
		BaseURL: "https://ollama.com/v1",
		APIKeyEntries: []config.OpenAICompatibilityAPIKey{
			{APIKey: "k", ProxyURL: "http://key-proxy.example.com:8080"},
		},
	}

	if got := compatCatalogEffectiveProxy(cfg, provider); got != "http://key-proxy.example.com:8080" {
		t.Fatalf("proxy = %q, want the per-key proxy", got)
	}

	// The target the refresh uses carries the same proxy.
	cfg.OpenAICompatibility = []config.OpenAICompatibility{*provider}
	targets := compatCatalogTargets(cfg)
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(targets))
	}
	if targets[0].proxyURL != "http://key-proxy.example.com:8080" {
		t.Fatalf("target proxy = %q, want the per-key proxy", targets[0].proxyURL)
	}

	// Without a per-key proxy the global one is used.
	provider.APIKeyEntries[0].ProxyURL = ""
	if got := compatCatalogEffectiveProxy(cfg, provider); got != "http://global-proxy.example.com:8080" {
		t.Fatalf("proxy = %q, want the global proxy", got)
	}
	targets = compatCatalogTargets(cfg)
	if len(targets) != 1 || targets[0].proxyURL != "http://global-proxy.example.com:8080" {
		t.Fatalf("target proxy = %q, want the global proxy", targets[0].proxyURL)
	}
}

// TestCompatCatalogDiscoversAnUnnamedProvider asserts that a provider entry
// without a name is still discovered.
//
// A provider entry may be unnamed: the credential synthesis falls back to
// "openai-compatibility" for it. Discovery used to skip an unnamed entry
// silently, so its models were never published.
func TestCompatCatalogDiscoversAnUnnamedProvider(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{
				BaseURL: "https://openrouter.ai/api/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{
					{APIKey: "k"},
				},
			},
		},
	}
	service := &Service{cfg: cfg}
	manager := newCompatCatalogManager(service)
	service.compatCatalog = manager

	// The entry is a target: it is not skipped for having no name.
	targets := compatCatalogTargets(cfg)
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(targets))
	}
	if targets[0].name != "openai-compatibility" {
		t.Fatalf("target name = %q, want the fallback name", targets[0].name)
	}

	// And the entry is read.
	var read bool
	manager.fetcher = func(_ context.Context, _ string, _ string, _ string) ([]byte, int, error) {
		read = true
		return []byte(`{"data":[{"id":"unnamed-provider-model"}]}`), 200, nil
	}
	manager.refreshProvider(context.Background(), targets[0])
	if !read {
		t.Fatal("an unnamed provider was not read")
	}

	// And its models reach the registration projection.
	compat := &cfg.OpenAICompatibility[0]
	merged := manager.modelsFor(0, compat, "")
	if len(merged.Models) != 1 || merged.Models[0].Name != "unnamed-provider-model" {
		t.Fatalf("merged models = %+v, want the discovered model", merged.Models)
	}
}

// TestModelRegistrationFenceDetectsAProviderExclusionChange asserts that a
// registration captured under one configuration does not publish under a later
// one that excludes a different model.
//
// The compatible provider carries its own excluded-models list, which is not
// part of the global OAuth exclusions. A registration that captured one
// configuration must not publish under a later one, or an excluded model would
// be republished.
func TestModelRegistrationFenceDetectsAProviderExclusionChange(t *testing.T) {
	t.Parallel()

	auth := &coreauth.Auth{
		ID:         "compat-fence-auth",
		Provider:   "openai-compatibility",
		Status:     coreauth.StatusActive,
		Attributes: map[string]string{"compat_name": "ollama-cloud", "config_index": "0"},
	}

	cfg := &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{
				Name:           "ollama-cloud",
				BaseURL:        "https://ollama.com/v1",
				ExcludedModels: []string{"excluded-model"},
			},
		},
	}
	fence := newModelRegistrationFence(auth, cfg)

	// A reload that changes the provider's own exclusions is detected.
	cfg.OpenAICompatibility[0].ExcludedModels = []string{"other-model"}
	if fence.compatExclusions == compatExcludedModelsSummaryForConfig(cfg, auth) {
		t.Fatal("the fence must not match a changed exclusion list")
	}

	// A reload that leaves it unchanged is not.
	cfg.OpenAICompatibility[0].ExcludedModels = []string{"excluded-model"}
	if fence.compatExclusions != compatExcludedModelsSummaryForConfig(cfg, auth) {
		t.Fatal("the fence must match an unchanged exclusion list")
	}
}

// TestModelRegistrationFenceAppliesToAnAPIKeyCredential asserts that the
// compatible provider's exclusion fence applies to an API-key credential.
//
// A compatible provider's credential is an API key, and the fence's exclusion
// checks for the global OAuth exclusions are restricted to the credentials those
// apply to. The provider's own excluded-models list applies to every credential,
// so its check must not be nested under that restriction.
func TestModelRegistrationFenceAppliesToAnAPIKeyCredential(t *testing.T) {
	t.Parallel()

	auth := &coreauth.Auth{
		ID:       "compat-fence-apikey-auth",
		Provider: "openai-compatibility",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"compat_name":  "ollama-cloud",
			"config_index": "0",
			"auth_kind":    coreauth.AuthKindAPIKey,
		},
	}
	if auth.AuthKind() != coreauth.AuthKindAPIKey {
		t.Fatalf("auth kind = %q, want an API key", auth.AuthKind())
	}

	cfg := &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{
				Name:           "ollama-cloud",
				BaseURL:        "https://ollama.com/v1",
				ExcludedModels: []string{"excluded-model"},
			},
		},
	}
	fence := newModelRegistrationFence(auth, cfg)
	if fence.compatExclusions == "" {
		t.Fatal("the fence must carry the provider's own exclusion list")
	}

	// A reload that changes the list is detected for this credential too.
	cfg.OpenAICompatibility[0].ExcludedModels = []string{"other-model"}
	if fence.compatExclusions == compatExcludedModelsSummaryForConfig(cfg, auth) {
		t.Fatal("the fence must not match a changed exclusion list for an API-key credential")
	}
}
