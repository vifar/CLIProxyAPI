package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// providerScopedAffinityFixture holds a manager with two providers that both serve
// one model, plus the affinity selector so the test can inspect the binding scope.
type providerScopedAffinityFixture struct {
	manager   *Manager
	affinity  *SessionAffinitySelector
	providerA string
	providerB string
	model     string
}

func newProviderScopedAffinityFixture(t *testing.T) providerScopedAffinityFixture {
	t.Helper()

	ctx := context.Background()
	providerA := "scoped-p1"
	providerB := "scoped-p2"
	model := "scoped-model"

	manager := NewManager(nil, nil, nil)
	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Hour,
	})
	t.Cleanup(affinity.Stop)
	manager.SetSelector(affinity)
	manager.RegisterExecutor(&successExecutor{provider: providerA})
	manager.RegisterExecutor(&successExecutor{provider: providerB})

	for _, auth := range []*Auth{
		{ID: "scoped-auth-1", Provider: providerA, Status: StatusActive, Metadata: map[string]any{"disable_cooling": true}},
		{ID: "scoped-auth-2", Provider: providerB, Status: StatusActive, Metadata: map[string]any{"disable_cooling": true}},
	} {
		if _, errRegister := manager.Register(WithSkipPersist(ctx), auth); errRegister != nil {
			t.Fatalf("Register(%s): %v", auth.ID, errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	}

	return providerScopedAffinityFixture{
		manager:   manager,
		affinity:  affinity,
		providerA: providerA,
		providerB: providerB,
		model:     model,
	}
}

// TestSessionAffinityNamespaceScopesMixedRouteByProviderSet asserts that the mixed
// affinity namespace carries the canonical eligible provider set, so that two
// provider sets produce two distinct binding scopes.
func TestSessionAffinityNamespaceScopesMixedRouteByProviderSet(t *testing.T) {
	t.Parallel()

	scopeBoth := sessionAffinityNamespace("mixed", map[string]any{
		cliproxyexecutor.SessionAffinityProviderSetMetadataKey: "scoped-p1,scoped-p2",
	})
	scopeOne := sessionAffinityNamespace("mixed", map[string]any{
		cliproxyexecutor.SessionAffinityProviderSetMetadataKey: "scoped-p1",
	})
	scopeThree := sessionAffinityNamespace("mixed", map[string]any{
		cliproxyexecutor.SessionAffinityProviderSetMetadataKey: "scoped-p1,scoped-p2,scoped-p3",
	})

	if scopeBoth == scopeOne {
		t.Fatalf("provider set scope not applied: %q", scopeBoth)
	}
	if scopeBoth == scopeThree {
		t.Fatalf("provider set scope not applied: %q", scopeBoth)
	}
	if scopeBoth != "mixed[scoped-p1,scoped-p2]" {
		t.Fatalf("namespace = %q, want mixed[scoped-p1,scoped-p2]", scopeBoth)
	}

	// A single-provider route keeps its plain provider namespace.
	if got := sessionAffinityNamespace("claude", map[string]any{
		cliproxyexecutor.SessionAffinityProviderSetMetadataKey: "claude",
	}); got != "claude" {
		t.Fatalf("single provider namespace = %q, want claude", got)
	}

	// A missing scope keeps the legacy namespace.
	if got := sessionAffinityNamespace("mixed", nil); got != "mixed" {
		t.Fatalf("namespace without scope = %q, want mixed", got)
	}
	if got := sessionAffinityNamespace("mixed", map[string]any{
		cliproxyexecutor.SessionAffinityProviderSetMetadataKey: "  ",
	}); got != "mixed" {
		t.Fatalf("namespace with blank scope = %q, want mixed", got)
	}
}

// TestCanonicalProviderSetScopeIsOrderIndependent asserts that two provider sets that
// differ only in order produce the same scope, and that the scope is stable.
func TestCanonicalProviderSetScopeIsOrderIndependent(t *testing.T) {
	t.Parallel()

	first := canonicalProviderSetScope(map[string]struct{}{"b": {}, "a": {}})
	second := canonicalProviderSetScope(map[string]struct{}{"a": {}, "b": {}})
	if first != second {
		t.Fatalf("scope is order dependent: %q vs %q", first, second)
	}
	if first != "a,b" {
		t.Fatalf("scope = %q, want a,b", first)
	}
	if got := canonicalProviderSetScope(map[string]struct{}{}); got != "" {
		t.Fatalf("empty scope = %q, want empty", got)
	}
}

// TestSessionAffinityMixedRouteBindsUnderProviderSetScope asserts that a mixed-route
// session binding is stored under the provider-set scoped namespace, and that a
// different eligible provider set produces a different binding scope.
func TestSessionAffinityMixedRouteBindsUnderProviderSetScope(t *testing.T) {
	t.Parallel()

	fixture := newProviderScopedAffinityFixture(t)
	ctx := context.Background()
	sessionID := "scoped-session-1"
	model := fixture.model

	// The manager computes the eligible provider set and scopes the binding.
	opts := cliproxyexecutor.Options{
		Headers: http.Header{"X-Session-Id": []string{sessionID}},
	}
	_, errExec := fixture.manager.Execute(ctx, []string{fixture.providerA, fixture.providerB},
		cliproxyexecutor.Request{Model: model}, opts)
	if errExec != nil {
		t.Fatalf("Execute under two-provider set: %v", errExec)
	}

	bothKey := "mixed[" + fixture.providerA + "," + fixture.providerB + "]::header:" + sessionID + "::" + model
	if _, ok := fixture.affinity.cache.Get(bothKey); !ok {
		t.Fatalf("expected binding under %q", bothKey)
	}

	// The same session under a different eligible provider set must not reuse the
	// binding created for the two-provider set.
	oneKey := "mixed[" + fixture.providerA + "]::header:" + sessionID + "::" + model
	if _, ok := fixture.affinity.cache.Get(oneKey); ok {
		t.Fatalf("binding leaked across provider sets under %q", oneKey)
	}

	// A single-provider route keeps its own namespace and is likewise unaffected.
	if _, ok := fixture.affinity.cache.Get(fixture.providerA + "::header:" + sessionID + "::" + model); ok {
		t.Fatal("mixed binding leaked into the single-provider namespace")
	}
}

// TestSessionAffinityMixedRouteProviderSetScopeIsOrderIndependent asserts that the
// same provider set supplied in a different order binds under the same scope.
func TestSessionAffinityMixedRouteProviderSetScopeIsOrderIndependent(t *testing.T) {
	t.Parallel()

	fixture := newProviderScopedAffinityFixture(t)
	ctx := context.Background()
	sessionID := "scoped-session-2"
	model := fixture.model

	auths := []*Auth{
		{ID: "scoped-auth-1", Provider: fixture.providerA},
		{ID: "scoped-auth-2", Provider: fixture.providerB},
	}

	opts := cliproxyexecutor.Options{
		Headers: http.Header{"X-Session-Id": []string{sessionID}},
		Metadata: map[string]any{
			cliproxyexecutor.SessionAffinityProviderSetMetadataKey: fixture.providerA + "," + fixture.providerB,
		},
	}
	if _, errPick := fixture.affinity.Pick(ctx, "mixed", model, opts, auths); errPick != nil {
		t.Fatalf("Pick: %v", errPick)
	}

	bothKey := "mixed[" + fixture.providerA + "," + fixture.providerB + "]::header:" + sessionID + "::" + model
	if _, ok := fixture.affinity.cache.Get(bothKey); !ok {
		t.Fatalf("expected binding under %q", bothKey)
	}
}
