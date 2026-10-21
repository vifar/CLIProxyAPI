package auth

import (
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// TestResolveUpstreamModelForOpenAICompatExcludedAlias asserts that a configured
// alias of an excluded model does not resolve to the excluded upstream.
//
// The alias consumers read the configured rows, so an unfiltered read would
// resolve the alias to the excluded model even when the model was never
// published.
func TestResolveUpstreamModelForOpenAICompatExcludedAlias(t *testing.T) {
	cfg := &internalconfig.Config{
		OpenAICompatibility: []internalconfig.OpenAICompatibility{
			{
				Name:           "compat-fixture",
				BaseURL:        "https://compat.example.com/v1",
				ExcludedModels: []string{"m"},
				APIKeyEntries:  []internalconfig.OpenAICompatibilityAPIKey{{APIKey: "test-key"}},
				Models: []internalconfig.OpenAICompatibilityModel{
					{Name: "m", Alias: "m"},
					{Name: "m", Alias: "friendly"},
					{Name: "n", Alias: "n"},
				},
			},
		},
	}
	auth := &Auth{
		ID:       "alias-fixture",
		Provider: "openai-compatibility",
		Attributes: map[string]string{
			"compat_name":  "compat-fixture",
			"config_index": "0",
		},
	}

	if got := resolveUpstreamModelForOpenAICompatAPIKey(cfg, auth, "friendly"); got == "m" {
		t.Fatalf("the alias of the excluded model resolved to %q", got)
	}
	if got := resolveUpstreamModelForOpenAICompatAPIKey(cfg, auth, "n"); got != "n" {
		t.Fatalf("the allowed alias resolved to %q, want %q", got, "n")
	}
}
