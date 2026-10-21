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

type exclusionFenceModelProvider struct {
	provider string
	onModels func() pluginapi.ModelResponse
}

func (p *exclusionFenceModelProvider) StaticModels(context.Context, pluginapi.StaticModelRequest) (pluginapi.ModelResponse, error) {
	return pluginapi.ModelResponse{Provider: p.provider, Models: []pluginapi.ModelInfo{{ID: "model-a"}, {ID: "model-b"}}}, nil
}

func (p *exclusionFenceModelProvider) ModelsForAuth(context.Context, pluginapi.AuthModelRequest) (pluginapi.ModelResponse, error) {
	return p.onModels(), nil
}

func TestModelRegistrationPluginExclusionSources(t *testing.T) {
	const provider = "exclusion-fixture"
	for _, tc := range []struct {
		name       string
		compat     bool
		addPrimary bool
		updateAuth bool
	}{
		{name: "compat fallback changed", compat: true},
		{name: "compat primary added", compat: true, addPrimary: true},
		{name: "plugin auth update", updateAuth: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			channel := provider
			if tc.compat {
				channel = "openai-compatibility"
			}
			oldCfg := &config.Config{OAuthExcludedModels: map[string][]string{channel: {"model-a"}}}
			newCfg := &config.Config{OAuthExcludedModels: map[string][]string{channel: {"model-b"}}}
			if tc.addPrimary {
				newCfg.OAuthExcludedModels[channel] = []string{"model-a"}
				newCfg.OAuthExcludedModels[provider] = []string{"model-b"}
			}
			manager := coreauth.NewManager(nil, nil, nil)
			host := pluginhost.New()
			service := &Service{cfg: oldCfg, coreManager: manager, pluginHost: host}
			calls := 0
			modelProvider := &exclusionFenceModelProvider{provider: provider, onModels: func() pluginapi.ModelResponse {
				calls++
				if calls == 1 {
					if commit := service.commitConfigUpdate(newCfg); commit.cfg != newCfg {
						t.Fatal("config update was rejected")
					}
				}
				response := pluginapi.ModelResponse{Provider: provider, Models: []pluginapi.ModelInfo{{ID: "model-a"}, {ID: "model-b"}}}
				if tc.updateAuth {
					response.AuthUpdate = pluginapi.AuthData{Label: "updated by plugin"}
				}
				return response
			}}
			pluginID := t.Name()
			host.RegisterPluginForTest(pluginID, pluginapi.Plugin{Capabilities: pluginapi.Capabilities{ModelProvider: modelProvider}})
			host.RegisterModels(t.Context(), registry.GetGlobalRegistry())
			reg := GlobalModelRegistry()
			t.Cleanup(func() { reg.UnregisterClient("plugin:" + pluginID + ":" + provider) })
			auth := &coreauth.Auth{ID: t.Name(), Provider: provider, Attributes: map[string]string{"auth_kind": "oauth"}}
			if tc.compat {
				auth.Attributes["compat_name"] = "compat-fixture"
			}
			registered, errRegister := manager.Register(t.Context(), auth)
			if errRegister != nil {
				t.Fatal(errRegister)
			}
			reg.RegisterClient(auth.ID, provider, []*ModelInfo{{ID: "model-old"}})
			t.Cleanup(func() { reg.UnregisterClient(auth.ID) })
			epoch := reg.ClientRegistrationEpoch(auth.ID)
			service.registerModelsForAuth(t.Context(), registered)
			if calls != 1 {
				t.Fatalf("plugin calls = %d, want 1", calls)
			}
			if got := reg.ClientRegistrationEpoch(auth.ID); got != epoch {
				t.Fatalf("obsolete plugin result advanced epoch from %d to %d", epoch, got)
			}
			current, ok := manager.GetByID(auth.ID)
			if !ok {
				t.Fatal("credential disappeared")
			}
			if tc.updateAuth && current.Label != "updated by plugin" {
				t.Fatal("test did not exercise the plugin auth update path")
			}
			service.registerModelsForAuth(t.Context(), current)
			if !reg.ClientSupportsModel(auth.ID, "model-a") || reg.ClientSupportsModel(auth.ID, "model-b") {
				t.Fatalf("final plugin models = %v, want only model-a", reg.GetModelsForClient(auth.ID))
			}
		})
	}
}

// TestModelRegistrationPluginProviderExclusions asserts that a compatible
// provider's own exclusions filter the models a plugin publishes for it.
//
// The plugin path returns before the configured rows are filtered, so without the
// provider's own list reaching it an excluded model would still be published and
// a request could route to it.
func TestModelRegistrationPluginProviderExclusions(t *testing.T) {
	const pluginID = "provider-exclusion-fixture"
	// A compatible credential is registered under the compatible provider key.
	const provider = "openai-compatibility"

	host := pluginhost.New()
	modelProvider := &exclusionFenceModelProvider{
		provider: provider,
		onModels: func() pluginapi.ModelResponse {
			// The plugin publishes for the compatible provider, so its models are
			// published onto the compatible credential.
			return pluginapi.ModelResponse{Provider: provider, Models: []pluginapi.ModelInfo{{ID: "m"}, {ID: "n"}}}
		},
	}
	host.RegisterPluginForTest(pluginID, pluginapi.Plugin{Capabilities: pluginapi.Capabilities{ModelProvider: modelProvider}})
	host.RegisterModels(t.Context(), registry.GetGlobalRegistry())

	cfg := &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{
				Name:           "compat-fixture",
				BaseURL:        "https://compat.example.com/v1",
				ExcludedModels: []string{"m"},
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{
					{APIKey: "test-key"},
				},
			},
		},
	}
	manager := coreauth.NewManager(nil, nil, nil)
	service := &Service{cfg: cfg, coreManager: manager, pluginHost: host}

	reg := GlobalModelRegistry()
	auth := &coreauth.Auth{
		ID:       t.Name(),
		Provider: "openai-compatibility",
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

	if reg.ClientSupportsModel(auth.ID, "m") {
		t.Fatalf("the excluded model was published: %v", reg.GetModelsForClient(auth.ID))
	}
	if !reg.ClientSupportsModel(auth.ID, "n") {
		t.Fatalf("the allowed model was not published: %v", reg.GetModelsForClient(auth.ID))
	}
}
