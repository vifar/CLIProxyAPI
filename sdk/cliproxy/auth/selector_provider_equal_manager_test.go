package auth

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// TestManagerMixedSelectorSurvivesAcrossRequests asserts that the manager's mixed
// selector keeps its rotation state across requests.
//
// The mixed selector is built once, when the selector is set. Building it per
// selection would reset the provider cursor on every request, so consecutive
// unbound requests would always select the same provider instead of alternating.
func TestManagerMixedSelectorSurvivesAcrossRequests(t *testing.T) {
	t.Parallel()

	unique := uniqueFixtureSuffix(t)
	providerA := "mgr-a-" + unique
	providerB := "mgr-b-" + unique
	model := "mgr-model-" + unique

	auths := []*Auth{
		{ID: "ma-1-" + unique, Provider: providerA},
		{ID: "mb-1-" + unique, Provider: providerB},
		{ID: "mb-2-" + unique, Provider: providerB},
		{ID: "mb-3-" + unique, Provider: providerB},
	}
	reg := registry.GetGlobalRegistry()
	ids := make([]string, 0, len(auths))
	for _, auth := range auths {
		ids = append(ids, auth.ID)
		reg.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
	}
	t.Cleanup(func() {
		for _, id := range ids {
			reg.UnregisterClient(id)
		}
	})

	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	manager.executors[providerA] = schedulerTestExecutor{}
	manager.executors[providerB] = schedulerTestExecutor{}
	for _, auth := range auths {
		if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
			t.Fatalf("Register(%s): %v", auth.ID, errRegister)
		}
	}

	mixed := manager.MixedSelector()
	if mixed == nil {
		t.Fatal("the manager must expose a mixed selector")
	}
	// The same instance must be returned every time.
	if again := manager.MixedSelector(); again != mixed {
		t.Fatal("the manager built a new mixed selector; its rotation state would reset")
	}

	gotProviders := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		picked, err := mixed.Pick(context.Background(), "mixed", model, cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("pick %d: %v", i, err)
		}
		if picked == nil {
			t.Fatalf("pick %d: nil auth", i)
		}
		gotProviders = append(gotProviders, executorKeyFromAuth(picked))
	}
	for i := 0; i < len(gotProviders); i += 2 {
		if gotProviders[i] == gotProviders[i+1] {
			t.Fatalf("providers = %v, want an equal share across requests", gotProviders)
		}
	}
}

// TestSessionAffinityKeepsAWeightedFallback asserts that the session affinity
// selector keeps a weighted fallback.
//
// Replacing a weighted fallback with the provider-equal one would bypass the
// affinity selector's positive-weight filtering, so a cold session could select a
// zero-weight credential.
func TestSessionAffinityKeepsAWeightedFallback(t *testing.T) {
	t.Parallel()

	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &WeightedRoundRobinSelector{},
	})
	t.Cleanup(affinity.Stop)

	mixed := newMixedSelectorFor(affinity)
	typed, ok := mixed.(*SessionAffinitySelector)
	if !ok {
		t.Fatalf("mixed selector = %T, want the affinity selector", mixed)
	}
	if _, ok := typed.fallback.(*WeightedRoundRobinSelector); !ok {
		t.Fatalf("fallback = %T, want the weighted round robin selector", typed.fallback)
	}
}

// TestSessionAffinityKeepsAFillFirstFallback asserts that the session affinity
// selector keeps a fill-first fallback, because fill-first orders by credential
// rather than by provider.
func TestSessionAffinityKeepsAFillFirstFallback(t *testing.T) {
	t.Parallel()

	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &FillFirstSelector{},
	})
	t.Cleanup(affinity.Stop)

	mixed := newMixedSelectorFor(affinity)
	typed, ok := mixed.(*SessionAffinitySelector)
	if !ok {
		t.Fatalf("mixed selector = %T, want the affinity selector", mixed)
	}
	if _, ok := typed.fallback.(*FillFirstSelector); !ok {
		t.Fatalf("fallback = %T, want the fill-first selector", typed.fallback)
	}
}
