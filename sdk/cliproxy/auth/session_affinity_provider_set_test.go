package auth

import (
	"context"
	"net/http"
	"strings"
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
	authA     string
	authB     string
}

func newProviderScopedAffinityFixture(t *testing.T) providerScopedAffinityFixture {
	t.Helper()

	ctx := context.Background()
	providerA := "scoped-p1"
	providerB := "scoped-p2"
	model := "scoped-model"

	// The model registry is global, so the credential IDs must be unique per
	// fixture invocation. A shared ID would let one test unregister a credential
	// that another test still believes is registered, and the other test's
	// manager would then reject its own credentials as not supporting the model.
	unique := uniqueFixtureSuffix(t)
	authA := "scoped-auth-1-" + unique
	authB := "scoped-auth-2-" + unique

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
		{ID: authA, Provider: providerA, Status: StatusActive, Metadata: map[string]any{"disable_cooling": true}},
		{ID: authB, Provider: providerB, Status: StatusActive, Metadata: map[string]any{"disable_cooling": true}},
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
		authA:     authA,
		authB:     authB,
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
		{ID: fixture.authA, Provider: fixture.providerA},
		{ID: fixture.authB, Provider: fixture.providerB},
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

// TestSessionAffinityLookupFindsScopedMixedBindings asserts that the affinity
// lookup finds a binding stored under a scoped mixed namespace.
//
// The scoped key is "mixed[<providers>]::<session>::<model>": the provider set
// comes first, and the session and model follow it. Matching the scope as part of
// a literal prefix would never find those keys, so the lookup would report
// "unbound" for a live mixed-route session.
func TestSessionAffinityLookupFindsScopedMixedBindings(t *testing.T) {
	t.Parallel()

	fixture := newProviderScopedAffinityFixture(t)
	ctx := context.Background()
	sessionID := "scoped-lookup-1"
	model := fixture.model

	opts := cliproxyexecutor.Options{
		Headers: http.Header{"X-Session-Id": []string{sessionID}},
	}
	_, errExec := fixture.manager.Execute(ctx, []string{fixture.providerA, fixture.providerB},
		cliproxyexecutor.Request{Model: model}, opts)
	if errExec != nil {
		t.Fatalf("Execute: %v", errExec)
	}

	// The explicit binding is stored under the scoped namespace.
	scopedKey := "mixed[" + fixture.providerA + "," + fixture.providerB + "]::header:" + sessionID + "::" + model
	if _, ok := fixture.affinity.cache.Get(scopedKey); !ok {
		t.Fatalf("expected a binding under %q", scopedKey)
	}

	// The lookup must find it.
	authID, status := fixture.affinity.LookupAffinity("mixed", model, sessionID)
	if status != "bound" {
		t.Fatalf("LookupAffinity status = %q, want bound", status)
	}
	if authID == "" {
		t.Fatal("LookupAffinity returned no auth")
	}
}

// TestSessionAffinityScopedNamespaceSuffixMatching asserts that the scoped
// namespace is matched on its own and the session and model as an exact suffix.
func TestSessionAffinityScopedNamespaceSuffixMatching(t *testing.T) {
	t.Parallel()

	cache := NewSessionCache(time.Hour)
	defer cache.Stop()

	cache.Set("mixed[a,b]::header:s1::model-1", "auth-1")
	cache.Set("mixed::header:s1::model-1", "auth-2")
	cache.Set("mixed[a,b]::header:s2::model-1", "auth-3")
	cache.Set("other[a,b]::header:s1::model-1", "auth-4")
	cache.Set("mixed[a,b]::header:s1::model-2", "auth-5")

	found := cache.GetByScopeSuffixes("mixed", []string{"::header:s1::model-1"})
	if len(found) != 2 {
		t.Fatalf("found = %v, want the two mixed bindings", found)
	}
	if _, ok := found["auth-1"]; !ok {
		t.Fatal("the scoped binding was not found")
	}
	if _, ok := found["auth-2"]; !ok {
		t.Fatal("the unscoped binding was not found")
	}
	if _, ok := found["auth-4"]; ok {
		t.Fatal("another namespace's binding was found")
	}
	if _, ok := found["auth-5"]; ok {
		t.Fatal("a binding for another model was found")
	}
}

// TestLCPAffinityNamespaceCarriesTheProviderSetScope asserts that the LCP
// namespace carries the same provider-set scope as the explicit binding
// namespace, so selection, success, eviction and lookup address one namespace.
func TestLCPAffinityNamespaceCarriesTheProviderSetScope(t *testing.T) {
	t.Parallel()

	metadata := map[string]any{
		cliproxyexecutor.CallerScopeMetadataKey:                "caller-1",
		cliproxyexecutor.SessionAffinityProviderSetMetadataKey: "p1,p2",
	}
	namespace := lcpAffinityNamespace("mixed", "model-1", metadata)
	if namespace == "" {
		t.Fatal("the LCP namespace must not be empty")
	}
	if !strings.Contains(namespace, "mixed[p1,p2]") {
		t.Fatalf("namespace = %q, want the provider-set scope", namespace)
	}

	// The parser must read the provider as "mixed", not as the scoped segment.
	provider, model, callerScope, ok := parseLCPNamespace(namespace)
	if !ok {
		t.Fatalf("parseLCPNamespace(%q) failed", namespace)
	}
	if provider != "mixed" {
		t.Fatalf("provider = %q, want mixed", provider)
	}
	if model != "model-1" {
		t.Fatalf("model = %q, want model-1", model)
	}
	if callerScope != "caller-1" {
		t.Fatalf("caller scope = %q, want caller-1", callerScope)
	}
}

// TestSessionAffinityScopedLookupMatchesEveryCandidateSuffix asserts that the
// batched scoped lookup finds the bindings of every candidate suffix.
//
// The suffixes are matched in one pass, so the batched result must be the union of
// the individual suffix results.
func TestSessionAffinityScopedLookupMatchesEveryCandidateSuffix(t *testing.T) {
	t.Parallel()

	cache := NewSessionCache(time.Hour)
	defer cache.Stop()

	cache.Set("mixed[a,b]::header:s1::model-1", "auth-1")
	cache.Set("mixed[a,b]::header:s2::model-1", "auth-2")
	cache.Set("mixed[a,b]::header:s1::model-2", "auth-3")
	cache.Set("other::header:s1::model-1", "auth-4")

	suffixes := []string{"::header:s1::model-1", "::header:s2::model-1"}
	found := cache.GetByScopeSuffixes("mixed", suffixes)
	if len(found) != 2 {
		t.Fatalf("found = %v, want two bindings", found)
	}
	if _, ok := found["auth-1"]; !ok {
		t.Fatal("the first candidate's binding was not found")
	}
	if _, ok := found["auth-2"]; !ok {
		t.Fatal("the second candidate's binding was not found")
	}
	if _, ok := found["auth-3"]; ok {
		t.Fatal("a binding for another model was found")
	}
	if _, ok := found["auth-4"]; ok {
		t.Fatal("another namespace's binding was found")
	}
}
