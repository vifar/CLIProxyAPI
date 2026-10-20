package config

import (
	"os"
	"testing"
)

// TestForkConfigLoads checks that the configuration shipped in the repository root
// is valid and carries the settings the fork's documentation promises.
//
// The file carries no credentials, so a deployment that copies it and adds its own
// keys starts from a working configuration rather than an empty one.
func TestForkConfigLoads(t *testing.T) {
	data, err := os.ReadFile("../../config.yaml")
	if err != nil {
		t.Fatalf("read fork config: %v", err)
	}
	cfg, err := ParseConfigBytes(data)
	if err != nil {
		t.Fatalf("parse fork config: %v", err)
	}

	// The session-sticky round robin defaults.
	if cfg.Routing.Strategy != "round-robin" {
		t.Fatalf("routing strategy = %q, want round-robin", cfg.Routing.Strategy)
	}
	if !cfg.Routing.SessionAffinity {
		t.Fatal("session affinity should be enabled")
	}
	if cfg.Routing.SessionAffinityTTL != "1h" {
		t.Fatalf("session affinity ttl = %q, want 1h", cfg.Routing.SessionAffinityTTL)
	}

	// The native exclusion key, used directly.
	if len(cfg.OAuthExcludedModels) == 0 {
		t.Fatal("the fork config should carry oauth-excluded-models")
	}
	for provider, excluded := range cfg.OAuthExcludedModels {
		if len(excluded) == 0 {
			t.Fatalf("provider %q has an empty exclusion list", provider)
		}
	}

	// The compatible providers the fork documents.
	wantProviders := map[string]bool{
		"ollama-cloud": false,
		"openrouter":   false,
		"vercel":       false,
	}
	for _, provider := range cfg.OpenAICompatibility {
		if _, ok := wantProviders[provider.Name]; !ok {
			t.Fatalf("unexpected provider %q", provider.Name)
		}
		wantProviders[provider.Name] = true
		if len(provider.Models) == 0 {
			t.Fatalf("provider %q has no models", provider.Name)
		}
		if len(provider.APIKeyEntries) == 0 {
			t.Fatalf("provider %q has no api-key-entries", provider.Name)
		}
	}
	for name, found := range wantProviders {
		if !found {
			t.Fatalf("provider %q is missing from the fork config", name)
		}
	}

	// The documented stable default and the Kimi K3 model.
	if !forkConfigHasModel(cfg, "ollama-cloud", "deepseek-v4.1-flash") {
		t.Fatal("the fork config should carry the deepseek-v4.1-flash default")
	}
	if !forkConfigHasModel(cfg, "ollama-cloud", "kimi-k3") {
		t.Fatal("the fork config should carry kimi-k3")
	}
}

// forkConfigHasModel reports whether a provider carries a model.
func forkConfigHasModel(cfg *Config, providerName, modelName string) bool {
	for _, provider := range cfg.OpenAICompatibility {
		if provider.Name != providerName {
			continue
		}
		for _, model := range provider.Models {
			if model.Name == modelName {
				return true
			}
		}
	}
	return false
}
