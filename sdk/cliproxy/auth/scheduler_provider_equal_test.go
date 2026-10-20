package auth

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// mixedProviderFixture describes a two-provider mixed route where both providers
// expose the same models but own a different number of credentials.
type mixedProviderFixture struct {
	scheduler *authScheduler
	providerA string
	providerB string
	modelA    string
	modelB    string
	authIDs   []string
}

// newUnequalMixedProviderScheduler builds a mixed-provider scheduler where the two
// providers expose the same model but own a different number of credentials.
// Provider A owns one eligible credential, provider B owns three.
//
// The expected contract is that provider selection happens before credential
// selection, so the two providers receive an equal share of new sessions
// regardless of how many credentials each one owns.
func newUnequalMixedProviderScheduler(t *testing.T) (scheduler *authScheduler, providers []string, model string) {
	t.Helper()

	fixture := newMixedProviderFixture(t)

	return fixture.scheduler, []string{fixture.providerA, fixture.providerB}, fixture.modelA
}

// newMixedProviderFixture registers both fixture models on every credential in one
// registry call. Registering a client twice would replace its model list, so both
// models must be supplied together.
func newMixedProviderFixture(t *testing.T) mixedProviderFixture {
	t.Helper()

	providerA := "openai-compatible-ollama-cloud"
	providerB := "openai-compatible-opencode-go"
	modelA := "deepseek-v4-pro"
	modelB := "glm-5.3"

	auths := []*Auth{
		{ID: "ollama-cloud-1", Provider: providerA},
		{ID: "opencode-go-1", Provider: providerB},
		{ID: "opencode-go-2", Provider: providerB},
		{ID: "opencode-go-3", Provider: providerB},
	}

	reg := registry.GetGlobalRegistry()
	authIDs := make([]string, 0, len(auths))
	for _, auth := range auths {
		authIDs = append(authIDs, auth.ID)
	}
	for _, auth := range auths {
		reg.RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{
			{ID: modelA},
			{ID: modelB},
		})
	}
	t.Cleanup(func() {
		for _, authID := range authIDs {
			reg.UnregisterClient(authID)
		}
	})

	return mixedProviderFixture{
		scheduler: newSchedulerForTest(&RoundRobinSelector{}, auths...),
		providerA: providerA,
		providerB: providerB,
		modelA:    modelA,
		modelB:    modelB,
		authIDs:   authIDs,
	}
}

// TestAuthSchedulerPickMixedRoundRobinBalancesProvidersBeforeCredentials asserts that
// mixed round robin selects the provider first and the credential second, so two
// providers owning a different number of credentials still receive an equal share
// of new sessions.
func TestAuthSchedulerPickMixedRoundRobinBalancesProvidersBeforeCredentials(t *testing.T) {
	t.Parallel()

	scheduler, providers, model := newUnequalMixedProviderScheduler(t)

	gotProviders := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		picked, provider, err := scheduler.pickMixed(
			context.Background(), providers, model,
			cliproxyexecutor.Options{}, nil,
		)
		if err != nil {
			t.Fatalf("pick %d: %v", i, err)
		}
		if picked == nil {
			t.Fatalf("pick %d: nil auth", i)
		}
		gotProviders = append(gotProviders, provider)
	}

	want := []string{
		providers[0], providers[1], providers[0], providers[1],
		providers[0], providers[1], providers[0], providers[1],
	}
	for i := range want {
		if gotProviders[i] != want[i] {
			t.Fatalf("providers = %v, want %v", gotProviders, want)
		}
	}
}

// TestAuthSchedulerPickMixedRoundRobinScopesCursors asserts that provider rotation for
// one model does not advance the provider cursor of another model, and that credential
// rotation inside one provider/model shard does not advance another shard's cursor.
func TestAuthSchedulerPickMixedRoundRobinScopesCursors(t *testing.T) {
	t.Parallel()

	fixture := newMixedProviderFixture(t)
	providers := []string{fixture.providerA, fixture.providerB}

	// Two picks for model A advance the provider cursor of model A by two.
	for i := 0; i < 2; i++ {
		if _, _, err := fixture.scheduler.pickMixed(
			context.Background(), providers, fixture.modelA,
			cliproxyexecutor.Options{}, nil,
		); err != nil {
			t.Fatalf("pick model A %d: %v", i, err)
		}
	}

	// The first pick for model B must start from that model's own cursor, so it
	// must return the first canonical provider again.
	picked, provider, err := fixture.scheduler.pickMixed(
		context.Background(), providers, fixture.modelB,
		cliproxyexecutor.Options{}, nil,
	)
	if err != nil {
		t.Fatalf("pick model B: %v", err)
	}
	if picked == nil {
		t.Fatal("pick model B: nil auth")
	}
	if provider != fixture.providerA {
		t.Fatalf("model B provider = %q, want %q (model A rotation leaked into model B)", provider, fixture.providerA)
	}
}

// TestAuthSchedulerPickMixedRoundRobinCanonicalizesProviderSet asserts that the same
// provider set supplied in a different order shares one cursor scope rather than
// creating an order-sensitive second cursor.
func TestAuthSchedulerPickMixedRoundRobinCanonicalizesProviderSet(t *testing.T) {
	t.Parallel()

	fixture := newMixedProviderFixture(t)
	providers := []string{fixture.providerA, fixture.providerB}
	reversed := []string{fixture.providerB, fixture.providerA}

	// Two picks advance the shared cursor by two.
	for i := 0; i < 2; i++ {
		if _, _, err := fixture.scheduler.pickMixed(
			context.Background(), providers, fixture.modelA,
			cliproxyexecutor.Options{}, nil,
		); err != nil {
			t.Fatalf("pick %d: %v", i, err)
		}
	}

	// The reversed order must continue the same cursor, not start a second one.
	// With two providers, a cursor of two wraps back to the first canonical provider.
	picked, provider, err := fixture.scheduler.pickMixed(
		context.Background(), reversed, fixture.modelA,
		cliproxyexecutor.Options{}, nil,
	)
	if err != nil {
		t.Fatalf("reversed pick: %v", err)
	}
	if picked == nil {
		t.Fatal("reversed pick: nil auth")
	}
	if provider != fixture.providerA {
		t.Fatalf("reversed provider = %q, want %q (provider set was not canonicalized)", provider, fixture.providerA)
	}
}

// TestAuthSchedulerPickMixedRoundRobinLowerPriorityProviderExcluded asserts that a
// provider whose ready credentials sit in a lower priority tier does not participate in
// the equal rotation while a higher priority tier is healthy.
func TestAuthSchedulerPickMixedRoundRobinLowerPriorityProviderExcluded(t *testing.T) {
	t.Parallel()

	providerA := "provider-high"
	providerB := "provider-low"
	model := "model-1"

	auths := []*Auth{
		{ID: "high-1", Provider: providerA, Attributes: map[string]string{"priority": "10"}},
		{ID: "low-1", Provider: providerB, Attributes: map[string]string{"priority": "0"}},
	}
	registerSchedulerModels(t, providerA, model, "high-1")
	registerSchedulerModels(t, providerB, model, "low-1")

	scheduler := newSchedulerForTest(&RoundRobinSelector{}, auths...)

	for i := 0; i < 4; i++ {
		picked, provider, err := scheduler.pickMixed(
			context.Background(), []string{providerA, providerB}, model,
			cliproxyexecutor.Options{}, nil,
		)
		if err != nil {
			t.Fatalf("pick %d: %v", i, err)
		}
		if picked == nil {
			t.Fatalf("pick %d: nil auth", i)
		}
		if provider != providerA {
			t.Fatalf("pick %d provider = %q, want %q (lower priority tier participated)", i, provider, providerA)
		}
	}
}
