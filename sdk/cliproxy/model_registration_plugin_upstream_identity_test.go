package cliproxy

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// upstreamIdentityModelProvider publishes a single model for the compatible
// provider, under the identifier the test chooses.
type upstreamIdentityModelProvider struct {
	provider string
	models   []pluginapi.ModelInfo
}

func (p *upstreamIdentityModelProvider) StaticModels(context.Context, pluginapi.StaticModelRequest) (pluginapi.ModelResponse, error) {
	return pluginapi.ModelResponse{Provider: p.provider, Models: p.models}, nil
}

func (p *upstreamIdentityModelProvider) ModelsForAuth(context.Context, pluginapi.AuthModelRequest) (pluginapi.ModelResponse, error) {
	return pluginapi.ModelResponse{Provider: p.provider, Models: p.models}, nil
}

// TestModelRegistrationPluginProviderExclusionsByUpstreamIdentity asserts that a
// compatible provider's exclusion is matched against the identity the upstream
// actually sees, not the identifier the plugin happened to publish.
//
// A thinking suffix selects a reasoning effort and the executor strips it before
// the request is sent, and a configured alias names a different model. Either way
// the excluded upstream must stay unreachable.
func TestModelRegistrationPluginProviderExclusionsByUpstreamIdentity(t *testing.T) {
	const provider = "openai-compatibility"

	for _, tc := range []struct {
		name      string
		published string
		rows      []config.OpenAICompatibilityModel
		wantKept  bool
	}{
		{
			name:      "the excluded name",
			published: "m",
			rows:      []config.OpenAICompatibilityModel{{Name: "m", Alias: "m"}},
			wantKept:  false,
		},
		{
			name:      "the excluded name with a thinking suffix",
			published: "m(high)",
			rows:      []config.OpenAICompatibilityModel{{Name: "m", Alias: "m"}},
			wantKept:  false,
		},
		{
			name:      "a configured alias of the excluded name",
			published: "friendly",
			rows:      []config.OpenAICompatibilityModel{{Name: "m", Alias: "friendly"}},
			wantKept:  false,
		},
		{
			name:      "a model the provider does not exclude",
			published: "n",
			rows:      []config.OpenAICompatibilityModel{{Name: "m", Alias: "m"}, {Name: "n", Alias: "n"}},
			wantKept:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := pluginhost.New()
			modelProvider := &upstreamIdentityModelProvider{
				provider: provider,
				models:   []pluginapi.ModelInfo{{ID: tc.published}},
			}
			pluginID := t.Name()
			host.RegisterPluginForTest(pluginID, pluginapi.Plugin{Capabilities: pluginapi.Capabilities{ModelProvider: modelProvider}})
			host.RegisterModels(t.Context(), registry.GetGlobalRegistry())

			cfg := &config.Config{
				OpenAICompatibility: []config.OpenAICompatibility{
					{
						Name:           "compat-fixture",
						BaseURL:        "https://compat.example.com/v1",
						ExcludedModels: []string{"m"},
						APIKeyEntries:  []config.OpenAICompatibilityAPIKey{{APIKey: "test-key"}},
						Models:         tc.rows,
					},
				},
			}
			manager := coreauth.NewManager(nil, nil, nil)
			service := &Service{cfg: cfg, coreManager: manager, pluginHost: host}

			reg := GlobalModelRegistry()
			auth := &coreauth.Auth{
				ID:       t.Name(),
				Provider: provider,
				Attributes: map[string]string{
					"compat_name":  "compat-fixture",
					"config_index": "0",
				},
			}
			registered, errRegister := manager.Register(t.Context(), auth)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			t.Cleanup(func() { reg.UnregisterClient(auth.ID) })

			service.registerModelsForAuth(t.Context(), registered)

			if got := reg.ClientSupportsModel(auth.ID, tc.published); got != tc.wantKept {
				t.Fatalf("%q published = %t, want %t; models = %v", tc.published, got, tc.wantKept, reg.GetModelsForClient(auth.ID))
			}
		})
	}
}

// TestPluginStaticModelsForProviderFollowUpstreamIdentityExclusions asserts that
// the static plugin models of a compatible provider are filtered against the
// upstream identity too.
//
// The static path is a second registration boundary, so a fix that only covers
// the per-credential path would leave the excluded upstream reachable.
func TestPluginStaticModelsForProviderFollowUpstreamIdentityExclusions(t *testing.T) {
	const provider = "openai-compatibility"

	for _, tc := range []struct {
		name      string
		published string
		rows      []config.OpenAICompatibilityModel
		wantKept  bool
	}{
		{
			name:      "the excluded name",
			published: "m",
			rows:      []config.OpenAICompatibilityModel{{Name: "m", Alias: "m"}},
			wantKept:  false,
		},
		{
			name:      "the excluded name with a thinking suffix",
			published: "m(high)",
			rows:      []config.OpenAICompatibilityModel{{Name: "m", Alias: "m"}},
			wantKept:  false,
		},
		{
			name:      "a configured alias of the excluded name",
			published: "friendly",
			rows:      []config.OpenAICompatibilityModel{{Name: "m", Alias: "friendly"}},
			wantKept:  false,
		},
		{
			name:      "a model the provider does not exclude",
			published: "n",
			rows:      []config.OpenAICompatibilityModel{{Name: "m", Alias: "m"}, {Name: "n", Alias: "n"}},
			wantKept:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := pluginhost.New()
			modelProvider := &upstreamIdentityModelProvider{
				provider: provider,
				models:   []pluginapi.ModelInfo{{ID: tc.published}},
			}
			pluginID := t.Name()
			host.RegisterPluginForTest(pluginID, pluginapi.Plugin{Capabilities: pluginapi.Capabilities{ModelProvider: modelProvider}})
			host.RegisterModels(t.Context(), registry.GetGlobalRegistry())
			t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient("plugin:" + pluginID + ":" + provider) })

			cfg := &config.Config{
				OpenAICompatibility: []config.OpenAICompatibility{
					{
						Name:           "compat-fixture",
						BaseURL:        "https://compat.example.com/v1",
						ExcludedModels: []string{"m"},
						APIKeyEntries:  []config.OpenAICompatibilityAPIKey{{APIKey: "test-key"}},
						Models:         tc.rows,
					},
				},
			}
			manager := coreauth.NewManager(nil, nil, nil)
			service := &Service{cfg: cfg, coreManager: manager, pluginHost: host}

			reg := GlobalModelRegistry()
			auth := &coreauth.Auth{
				ID:       t.Name(),
				Provider: provider,
				Attributes: map[string]string{
					"compat_name":  "compat-fixture",
					"config_index": "0",
				},
			}
			registered, errRegister := manager.Register(t.Context(), auth)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			t.Cleanup(func() { reg.UnregisterClient(auth.ID) })

			service.registerModelsForAuth(t.Context(), registered)

			if got := reg.ClientSupportsModel(auth.ID, tc.published); got != tc.wantKept {
				t.Fatalf("%q published = %t, want %t; models = %v", tc.published, got, tc.wantKept, reg.GetModelsForClient(auth.ID))
			}
		})
	}
}

// TestApplyExcludedModelsKeepsTheNativeBehaviour asserts that the shared
// exclusion helper keeps the behaviour a native provider has always had.
//
// The suffix-aware matching belongs to the compatible providers: the executor
// strips a thinking suffix before it sends the request upstream, so an
// exclusion written for the upstream name has to match the model without the
// suffix. A native provider's exclusion has never matched that way, and the
// compatible-provider work does not change it.
func TestApplyExcludedModelsKeepsTheNativeBehaviour(t *testing.T) {
	models := []*ModelInfo{{ID: "model-a"}, {ID: "model-a(high)"}, {ID: "model-b"}}

	filtered := applyExcludedModels(models, []string{"model-a"})
	present := make(map[string]bool, len(filtered))
	for _, model := range filtered {
		present[model.ID] = true
	}
	if present["model-a"] {
		t.Fatalf("the excluded model was published: %v", present)
	}
	if !present["model-a(high)"] {
		t.Fatalf("the native provider's own behaviour changed: %v", present)
	}
}
