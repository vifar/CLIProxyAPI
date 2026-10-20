package examples

import (
	"os"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// TestFallbackConfigLoads checks that the shipped static fallback configuration is
// valid and carries the providers it documents. The fallback is the offline floor
// for the providers whose live model list the proxy can read, so a typo in it would
// leave a deployment with no models at all.
func TestFallbackConfigLoads(t *testing.T) {
	data, err := os.ReadFile("config.yaml")
	if err != nil {
		t.Fatalf("read fallback config: %v", err)
	}
	cfg, err := config.ParseConfigBytes(data)
	if err != nil {
		t.Fatalf("parse fallback config: %v", err)
	}

	if len(cfg.OpenAICompatibility) != 3 {
		t.Fatalf("providers = %d, want 3", len(cfg.OpenAICompatibility))
	}
	wantProviders := map[string]bool{
		"ollama-cloud": false,
		"openrouter":   false,
		"vercel":       false,
	}
	for _, provider := range cfg.OpenAICompatibility {
		name := provider.Name
		if _, ok := wantProviders[name]; !ok {
			t.Fatalf("unexpected provider %q in the fallback config", name)
		}
		wantProviders[name] = true
		if len(provider.Models) == 0 {
			t.Fatalf("provider %q has no models", name)
		}
		if len(provider.APIKeyEntries) == 0 {
			t.Fatalf("provider %q has no api-key-entries", name)
		}
	}
	for name, found := range wantProviders {
		if !found {
			t.Fatalf("provider %q is missing from the fallback config", name)
		}
	}

	// The fallback carries the session-sticky routing defaults.
	if !cfg.Routing.SessionAffinity {
		t.Fatal("the fallback config should enable session affinity")
	}
	if cfg.Routing.Strategy != "round-robin" {
		t.Fatalf("routing strategy = %q, want round-robin", cfg.Routing.Strategy)
	}
}
