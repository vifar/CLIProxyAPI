package cliproxy

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestShippedConfigRuntimeSessionBinding(t *testing.T) {
	cfg, err := internalconfig.LoadConfig(filepath.Join("..", "..", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	state := normalizedRoutingRuntimeState(cfg)
	if state.strategy != "round-robin" || !state.sessionAffinity || state.sessionAffinityTTL != time.Hour {
		t.Fatal("shipped routing must reach the runtime as sticky round-robin with a one-hour TTL")
	}
	selector := newRoutingSelector(state)
	affinity, ok := selector.(*coreauth.SessionAffinitySelector)
	if !ok {
		t.Fatalf("runtime selector = %T, want session affinity", selector)
	}
	t.Cleanup(affinity.Stop)
	manager := coreauth.NewManager(nil, selector, nil)
	mixed := manager.MixedSelector()
	credentials := []*coreauth.Auth{
		{ID: "shipped-a-1", Provider: "shipped-a"},
		{ID: "shipped-a-2", Provider: "shipped-a"},
		{ID: "shipped-b-1", Provider: "shipped-b"},
	}
	options := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Id": {"shipped-session"}}}
	first, err := mixed.Pick(context.Background(), "mixed", "shipped-model", options, credentials)
	if err != nil || first == nil {
		t.Fatalf("initial session selection: %v", err)
	}
	for i := 0; i < 6; i++ {
		// Exercise cold selection between bound requests so a missing binding
		// cannot pass just because the provider cursor happened to wrap around.
		cold := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Id": {"cold-session-" + string(rune('a'+i))}}}
		if _, errPick := mixed.Pick(context.Background(), "mixed", "shipped-model", cold, credentials); errPick != nil {
			t.Fatal(errPick)
		}
		again, errPick := mixed.Pick(context.Background(), "mixed", "shipped-model", options, credentials)
		if errPick != nil || again == nil || again.ID != first.ID || again.Provider != first.Provider {
			t.Fatal("shipped defaults did not retain the session's provider and credential")
		}
	}
}
