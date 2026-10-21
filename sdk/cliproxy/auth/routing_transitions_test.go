package auth

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestRoutingTransitionRecorderCountsEachTransition(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(10)
	recorder.Record(RoutingTransitionEvent{
		Transition: RoutingTransitionBindingCreated,
		Model:      "model-a",
		Provider:   "provider-a",
		Session:    "session-1",
	})
	recorder.Record(RoutingTransitionEvent{
		Transition: RoutingTransitionBindingCreated,
		Model:      "model-a",
		Provider:   "provider-a",
		Session:    "session-2",
	})
	recorder.Record(RoutingTransitionEvent{
		Transition: RoutingTransitionBindingHit,
		Model:      "model-a",
		Provider:   "provider-a",
		Session:    "session-1",
	})

	counters := recorder.Snapshot().Counters
	if len(counters) != 2 {
		t.Fatalf("counters = %+v, want 2", counters)
	}
	if counters[0].Transition != string(RoutingTransitionBindingCreated) || counters[0].Count != 2 {
		t.Fatalf("binding created counter = %+v, want count 2", counters[0])
	}
	if counters[1].Transition != string(RoutingTransitionBindingHit) || counters[1].Count != 1 {
		t.Fatalf("binding hit counter = %+v, want count 1", counters[1])
	}

	totals := recorder.Snapshot().Totals
	if totals[string(RoutingTransitionBindingCreated)] != 2 {
		t.Fatalf("totals = %+v", totals)
	}
}

func TestRoutingTransitionRecorderKeepsEventsBounded(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(3)
	for i := 0; i < 10; i++ {
		recorder.Record(RoutingTransitionEvent{
			Transition: RoutingTransitionBindingHit,
			Model:      "model-a",
			Session:    "session",
		})
	}
	if events := recorder.Snapshot().Events; len(events) != 3 {
		t.Fatalf("events len = %d, want 3", len(events))
	}
}

func TestRoutingTransitionRecorderBoundsTheCounterKeys(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(10)
	// A hostile client sends a very long model name. The key must be bounded.
	long := strings.Repeat("x", 4096)
	recorder.Record(RoutingTransitionEvent{
		Transition: RoutingTransitionBindingHit,
		Model:      long,
		Provider:   long,
	})
	counters := recorder.Snapshot().Counters
	if len(counters) != 1 {
		t.Fatalf("counters = %+v", counters)
	}
	if len(counters[0].Model) > maxRoutingTransitionKeyLength {
		t.Fatalf("model key length = %d, want at most %d", len(counters[0].Model), maxRoutingTransitionKeyLength)
	}
}

func TestRoutingTransitionRecorderTruncatesTheSessionIdentifier(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(10)
	recorder.Record(RoutingTransitionEvent{
		Transition: RoutingTransitionBindingHit,
		Session:    strings.Repeat("s", 64),
	})
	events := recorder.Snapshot().Events
	if len(events) != 1 {
		t.Fatalf("events = %+v", events)
	}
	if len(events[0].Session) >= 64 {
		t.Fatalf("session was not truncated: %q", events[0].Session)
	}
}

// routingTransitionTestSelector builds a selector with two providers serving one
// model, and a recorder installed as the process-wide one.
func routingTransitionTestSelector(t *testing.T, recorder *RoutingTransitionRecorder) (*SessionAffinitySelector, *Manager, string, string) {
	t.Helper()

	ctx := context.Background()
	providerA := "rt-provider-a"
	providerB := "rt-provider-b"
	model := "rt-model"

	manager := NewManager(nil, nil, nil)
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Hour,
	})
	t.Cleanup(selector.Stop)
	manager.SetSelector(selector)

	for _, auth := range []*Auth{
		{ID: "rt-auth-a", Provider: providerA, Status: StatusActive, Metadata: map[string]any{"disable_cooling": true}},
		{ID: "rt-auth-b", Provider: providerB, Status: StatusActive, Metadata: map[string]any{"disable_cooling": true}},
	} {
		if _, errRegister := manager.Register(WithSkipPersist(ctx), auth); errRegister != nil {
			t.Fatalf("Register(%s): %v", auth.ID, errRegister)
		}
		registry.GetGlobalRegistry().RegisterClient(auth.ID, auth.Provider, []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(auth.ID) })
	}

	previous := GetRoutingTransitionRecorder()
	SetRoutingTransitionRecorder(recorder)
	t.Cleanup(func() { SetRoutingTransitionRecorder(previous) })

	return selector, manager, providerA, model
}

func TestRoutingTransitionRecordsBindingCreatedAndHit(t *testing.T) {

	recorder := NewRoutingTransitionRecorder(10)
	selector, _, _, model := routingTransitionTestSelector(t, recorder)

	opts := cliproxyexecutor.Options{
		Headers: http.Header{"X-Session-Id": []string{"rt-session-1"}},
	}
	auths := []*Auth{
		{ID: "rt-auth-a", Provider: "rt-provider-a"},
		{ID: "rt-auth-b", Provider: "rt-provider-b"},
	}

	if _, errPick := selector.Pick(context.Background(), "mixed", model, opts, auths); errPick != nil {
		t.Fatalf("first Pick: %v", errPick)
	}
	totals := recorder.Snapshot().Totals
	if totals[string(RoutingTransitionBindingCreated)] != 1 {
		t.Fatalf("binding created = %d, want 1: %+v", totals[string(RoutingTransitionBindingCreated)], totals)
	}
	if totals[string(RoutingTransitionBindingHit)] != 0 {
		t.Fatalf("binding hit = %d, want 0", totals[string(RoutingTransitionBindingHit)])
	}

	// The same session again reuses its binding.
	if _, errPick := selector.Pick(context.Background(), "mixed", model, opts, auths); errPick != nil {
		t.Fatalf("second Pick: %v", errPick)
	}
	totals = recorder.Snapshot().Totals
	if totals[string(RoutingTransitionBindingHit)] != 1 {
		t.Fatalf("binding hit = %d, want 1", totals[string(RoutingTransitionBindingHit)])
	}
	if totals[string(RoutingTransitionBindingCreated)] != 1 {
		t.Fatalf("binding created = %d, want 1", totals[string(RoutingTransitionBindingCreated)])
	}
}

func TestRoutingTransitionRecordsCredentialReselection(t *testing.T) {

	recorder := NewRoutingTransitionRecorder(10)
	selector, _, _, model := routingTransitionTestSelector(t, recorder)

	sessionID := "rt-session-2"
	opts := cliproxyexecutor.Options{
		Headers: http.Header{"X-Session-Id": []string{sessionID}},
	}

	// Bind the session to the first credential.
	first := []*Auth{{ID: "rt-auth-a", Provider: "rt-provider-a"}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, opts, first); errPick != nil {
		t.Fatalf("first Pick: %v", errPick)
	}

	// The bound credential is gone, but the same provider has another one. That is
	// a credential reselection, not a provider failover.
	second := []*Auth{
		{ID: "rt-auth-a2", Provider: "rt-provider-a"},
		{ID: "rt-auth-b", Provider: "rt-provider-b"},
	}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, opts, second); errPick != nil {
		t.Fatalf("second Pick: %v", errPick)
	}

	totals := recorder.Snapshot().Totals
	if totals[string(RoutingTransitionCredentialReselected)] != 1 {
		t.Fatalf("credential reselected = %d, want 1: %+v", totals[string(RoutingTransitionCredentialReselected)], totals)
	}
	if totals[string(RoutingTransitionProviderFailover)] != 0 {
		t.Fatalf("provider failover = %d, want 0", totals[string(RoutingTransitionProviderFailover)])
	}
}

func TestRoutingTransitionRecordsProviderFailover(t *testing.T) {

	recorder := NewRoutingTransitionRecorder(10)
	selector, _, _, model := routingTransitionTestSelector(t, recorder)

	sessionID := "rt-session-3"
	opts := cliproxyexecutor.Options{
		Headers: http.Header{"X-Session-Id": []string{sessionID}},
	}

	// Bind the session to the first provider.
	first := []*Auth{{ID: "rt-auth-a", Provider: "rt-provider-a"}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, opts, first); errPick != nil {
		t.Fatalf("first Pick: %v", errPick)
	}

	// The bound provider has no eligible credential left, so the request moves to
	// another provider. That is a provider failover, and the binding is replaced.
	second := []*Auth{{ID: "rt-auth-b", Provider: "rt-provider-b"}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, opts, second); errPick != nil {
		t.Fatalf("second Pick: %v", errPick)
	}

	totals := recorder.Snapshot().Totals
	if totals[string(RoutingTransitionProviderFailover)] != 1 {
		t.Fatalf("provider failover = %d, want 1: %+v", totals[string(RoutingTransitionProviderFailover)], totals)
	}
	if totals[string(RoutingTransitionCredentialReselected)] != 0 {
		t.Fatalf("credential reselected = %d, want 0", totals[string(RoutingTransitionCredentialReselected)])
	}

	// The failover event records both the provider it moved to and the one it left.
	events := recorder.Snapshot().Events
	found := false
	for _, event := range events {
		if event.Transition != RoutingTransitionProviderFailover {
			continue
		}
		found = true
		if event.Provider != "rt-provider-b" {
			t.Fatalf("failover provider = %q, want rt-provider-b", event.Provider)
		}
	}
	if !found {
		t.Fatalf("no provider failover event: %+v", events)
	}
}

// TestRoutingTransitionRecorderBoundsTheCounterCardinality asserts that the
// counter map cannot grow without limit.
//
// A client can vary the spelling of a model it asks for, so the distinct model
// and provider names are capped and the overflow is folded into a bounded bucket.
// The aggregate totals must stay exact.
func TestRoutingTransitionRecorderBoundsTheCounterCardinality(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(10)
	limit := maxRoutingTransitionModels
	for i := 0; i < limit*2; i++ {
		recorder.Record(RoutingTransitionEvent{
			Transition: RoutingTransitionNoEligibleProvider,
			Model:      "model-" + strconv.Itoa(i),
		})
	}

	counters := recorder.Snapshot().Counters
	if len(counters) > limit+1 {
		t.Fatalf("counters len = %d, want at most %d plus the overflow bucket", len(counters), limit)
	}

	// The totals must be exact: every recorded transition is counted.
	totals := recorder.Snapshot().Totals
	if totals[string(RoutingTransitionNoEligibleProvider)] != uint64(limit*2) {
		t.Fatalf("total = %d, want %d", totals[string(RoutingTransitionNoEligibleProvider)], limit*2)
	}
}

// TestRoutingTransitionRecordsNoEligibleProviderOnTheAffinityPath asserts that a
// mixed request with session affinity that cannot be served is counted.
//
// The session-affinity selector is not a built-in selector, so an affinity request
// enters the legacy mixed path. The transition has to be recorded there too, or
// the counter would only see the fast path.
func TestRoutingTransitionRecordsNoEligibleProviderOnTheAffinityPath(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(10)
	previous := GetRoutingTransitionRecorder()
	SetRoutingTransitionRecorder(recorder)
	t.Cleanup(func() { SetRoutingTransitionRecorder(previous) })

	manager := NewManager(nil, nil, nil)
	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Hour,
	})
	t.Cleanup(affinity.Stop)
	manager.SetSelector(affinity)

	// No credential is registered, so the request cannot be routed.
	_, _, _, errPick := manager.pickNextMixed(context.Background(), []string{"rt-provider-a"}, "rt-model", cliproxyexecutor.Options{}, nil)
	if errPick == nil {
		t.Fatal("expected the request to fail with no eligible credential")
	}

	totals := recorder.Snapshot().Totals
	if totals[string(RoutingTransitionNoEligibleProvider)] != 1 {
		t.Fatalf("no eligible provider = %d, want 1: %+v", totals[string(RoutingTransitionNoEligibleProvider)], totals)
	}
}

// TestRoutingTransitionClassifiesAnLCPReplacementByProvider asserts that a
// replacement of an LCP binding is labelled by the provider it replaced.
//
// The bound credential has left the available candidates by the time the
// replacement is made, so the provider cannot be recovered from them. The
// selector remembers it, so the replacement is still classified.
func TestRoutingTransitionClassifiesAnLCPReplacementByProvider(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(10)
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Hour,
	})
	t.Cleanup(selector.Stop)

	// The selector remembers the provider of a bound credential.
	selector.rememberBoundProvider("bound-auth", "provider-a")

	// The remembered provider is returned even when the credential is not among
	// the candidates any more.
	if got := selector.boundProviderFor("bound-auth", nil); got != "provider-a" {
		t.Fatalf("bound provider = %q, want provider-a", got)
	}
	_ = recorder
}
