package auth

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// TestProviderEqualSelectorBalancesProvidersOnTheLegacyPath asserts that the
// provider-equal selector used by the mixed legacy path gives two providers with
// different credential counts an equal share.
//
// The plain round-robin selector flattens every credential into one ring ordered
// by credential ID, so a provider with three credentials received three times the
// traffic of a provider with one. The mixed path must not do that, because the
// fork's own configuration enables session affinity, which routes through this
// path.
func TestProviderEqualSelectorBalancesProvidersOnTheLegacyPath(t *testing.T) {
	t.Parallel()

	unique := uniqueFixtureSuffix(t)
	providerA := "legacy-a-" + unique
	providerB := "legacy-b-" + unique
	model := "legacy-model-" + unique

	auths := []*Auth{
		{ID: "a-1-" + unique, Provider: providerA},
		{ID: "b-1-" + unique, Provider: providerB},
		{ID: "b-2-" + unique, Provider: providerB},
		{ID: "b-3-" + unique, Provider: providerB},
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

	selector := NewProviderEqualSelector()

	gotProviders := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		picked, err := selector.Pick(context.Background(), "mixed", model, cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("pick %d: %v", i, err)
		}
		if picked == nil {
			t.Fatalf("pick %d: nil auth", i)
		}
		gotProviders = append(gotProviders, executorKeyFromAuth(picked))
	}

	// The two providers must alternate one to one.
	for i := 0; i < len(gotProviders); i += 2 {
		if gotProviders[i] == gotProviders[i+1] {
			t.Fatalf("providers = %v, want an equal share", gotProviders)
		}
	}
}

// TestSessionAffinityFallbackBalancesProviders asserts that the session affinity
// selector's fallback selects providers equally, so enabling session affinity does
// not silently change the traffic distribution.
func TestSessionAffinityFallbackBalancesProviders(t *testing.T) {
	t.Parallel()

	unique := uniqueFixtureSuffix(t)
	providerA := "affinity-a-" + unique
	providerB := "affinity-b-" + unique
	model := "affinity-model-" + unique

	auths := []*Auth{
		{ID: "aa-1-" + unique, Provider: providerA},
		{ID: "bb-1-" + unique, Provider: providerB},
		{ID: "bb-2-" + unique, Provider: providerB},
		{ID: "bb-3-" + unique, Provider: providerB},
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

	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
	})
	t.Cleanup(affinity.Stop)

	mixed := newMixedSelectorFor(affinity, nil)

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
			t.Fatalf("providers = %v, want an equal share", gotProviders)
		}
	}
}

// TestProviderEqualSelectorForLeavesOtherStrategiesAlone asserts that only the
// round-robin family is replaced. fill-first and weighted round robin keep their
// own semantics.
func TestNewMixedSelectorForLeavesOtherStrategiesAlone(t *testing.T) {
	t.Parallel()

	fillFirst := &FillFirstSelector{}
	if got := newMixedSelectorFor(fillFirst, nil); got != fillFirst {
		t.Fatalf("fill-first was replaced: %T", got)
	}
	weighted := &WeightedRoundRobinSelector{}
	if got := newMixedSelectorFor(weighted, nil); got != weighted {
		t.Fatalf("weighted round robin was replaced: %T", got)
	}
}
