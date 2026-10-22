package cliproxy

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// TestCompatCatalogRefreshPublishesWhileAnotherProviderIsBlocked asserts that a
// provider that answers publishes its models to the registry even while another
// provider never completes its response.
//
// The settled requirement is an independent publication: storing the response
// without publishing anything would not satisfy it, so the test asserts the
// registry, not the manager's internal state.
func TestCompatCatalogRefreshPublishesWhileAnotherProviderIsBlocked(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{
				Name:    "ollama-cloud",
				BaseURL: "https://ollama.com/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{
					{APIKey: "ollama-key"},
				},
			},
			{
				Name:    "openrouter",
				BaseURL: "https://openrouter.ai/api/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{
					{APIKey: "openrouter-key"},
				},
			},
		},
	}

	coreManager := coreauth.NewManager(nil, nil, nil)
	service := &Service{
		cfg:         cfg,
		coreManager: coreManager,
	}
	manager := newCompatCatalogManager(service)
	service.compatCatalog = manager

	// The OpenRouter credential is registered, so its models reach the registry.
	auth := &coreauth.Auth{
		ID:       "compat-openrouter-1",
		Provider: "openai-compatibility",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"compat_name":  "openrouter",
			"provider_key": "openai-compatibility",
			"config_index": "1",
			"base_url":     "https://openrouter.ai/api/v1",
		},
	}
	if _, errRegister := coreManager.Register(coreauth.WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatalf("Register: %v", errRegister)
	}
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })

	// The Ollama provider never completes its response.
	blocked := make(chan struct{})
	released := make(chan struct{})
	var blockedOnce sync.Once
	manager.fetcher = func(_ context.Context, endpoint, _, _ string) ([]byte, int, error) {
		if strings.Contains(endpoint, "ollama.com") {
			blockedOnce.Do(func() { close(blocked) })
			<-released
			return nil, 0, context.Canceled
		}
		return []byte(`{"data":[{"id":"openrouter-live-model"}]}`), http.StatusOK, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go manager.Refresh(ctx)

	select {
	case <-blocked:
	case <-time.After(10 * time.Second):
		close(released)
		t.Fatal("the blocked provider was never reached")
	}
	// The blocked provider is released so the pass can finish.
	defer close(released)

	// The answered provider's models reach the registry while the other one is
	// still blocked.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if registry.GetGlobalRegistry().ClientSupportsModel(auth.ID, "openrouter-live-model") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the answered provider's model was not published to the registry while the other provider was blocked")
}
