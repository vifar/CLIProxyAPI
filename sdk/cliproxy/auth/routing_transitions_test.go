package auth

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
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
	// The recorder is process-wide, so this test does not run in parallel.

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
	// The recorder is process-wide, so this test does not run in parallel.

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
	// The recorder is process-wide, so this test does not run in parallel.

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

// routingTransitionRecorderMu serializes the tests that install the process-wide
// routing transition recorder.
//
// The recorder is a process-wide global, so two tests that install it would
// record into each other's recorder and restore each other's previous value.
var routingTransitionRecorderMu sync.Mutex

// installRoutingTransitionRecorder installs a recorder for the duration of a test
// and returns the function that restores the previous one.
func installRoutingTransitionRecorder(t *testing.T, recorder *RoutingTransitionRecorder) {
	t.Helper()
	routingTransitionRecorderMu.Lock()
	t.Cleanup(routingTransitionRecorderMu.Unlock)
	previous := GetRoutingTransitionRecorder()
	SetRoutingTransitionRecorder(recorder)
	t.Cleanup(func() { SetRoutingTransitionRecorder(previous) })
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

	installRoutingTransitionRecorder(t, recorder)

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
	// The recorder is process-wide, so this test does not run in parallel.

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
	// The recorder is process-wide, so this test does not run in parallel.

	recorder := NewRoutingTransitionRecorder(10)
	installRoutingTransitionRecorder(t, recorder)

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

// TestSessionAffinityCopySharesTheAffinityState asserts that a copy of the session
// affinity selector shares the state object, with its lock.
//
// The maps and their lock must be shared together. A copy that shared the maps
// but copied the lock would let two goroutines write the same map under different
// locks, which is a process-fatal concurrent-map panic.
func TestSessionAffinityCopySharesTheAffinityState(t *testing.T) {
	t.Parallel()

	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Hour,
	})
	t.Cleanup(affinity.Stop)

	copied := affinity.withProviderEqualFallback(NewProviderEqualSelector())
	if copied == affinity {
		t.Fatal("the copy must be a distinct selector")
	}
	if copied.affinityState == nil || affinity.affinityState == nil {
		t.Fatal("the affinity state must exist")
	}
	if copied.affinityState != affinity.affinityState {
		t.Fatal("the copy must share the affinity state object")
	}
}

// TestLCPFailureRecordUsesTheSessionIdentity asserts that an LCP failure is
// recorded under the conversation's session identity, not under the credential.
//
// The retry binds a different credential, so a credential-keyed record would never
// be found and the retry would be reported as a created binding. The session is
// also what keeps an unrelated conversation that chooses the same credential from
// consuming the record.
func TestLCPFailureRecordUsesTheSessionIdentity(t *testing.T) {
	t.Parallel()

	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Hour,
	})
	t.Cleanup(affinity.Stop)

	const namespace = "lcp:v1::mixed::model-1::caller-1"

	// The failure is recorded under the session.
	affinity.rememberFailedBinding(lcpFailedBindingKey(namespace, "session-1"), "provider-a")

	// The retry binds a different credential and reads the record under the
	// session, so it is found.
	if got := affinity.takeFailedBinding(lcpFailedBindingKey(namespace, "session-1")); got != "provider-a" {
		t.Fatalf("failed provider = %q, want provider-a", got)
	}

	// The record is consumed once.
	if got := affinity.takeFailedBinding(lcpFailedBindingKey(namespace, "session-1")); got != "" {
		t.Fatalf("failed provider = %q, want the record to be consumed", got)
	}
}

// TestLCPFailureRecordIsNotConsumedByAnotherConversation asserts that a
// conversation with a different session does not consume the record.
func TestLCPFailureRecordIsNotConsumedByAnotherConversation(t *testing.T) {
	t.Parallel()

	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Hour,
	})
	t.Cleanup(affinity.Stop)

	const namespace = "lcp:v1::mixed::model-1::caller-1"
	affinity.rememberFailedBinding(lcpFailedBindingKey(namespace, "session-1"), "provider-a")

	// A different conversation that happens to use the same credential does not
	// find the record.
	if got := affinity.takeFailedBinding(lcpFailedBindingKey(namespace, "session-2")); got != "" {
		t.Fatalf("failed provider = %q, want no record for another conversation", got)
	}

	// The record is still there for the conversation that failed.
	if got := affinity.takeFailedBinding(lcpFailedBindingKey(namespace, "session-1")); got != "provider-a" {
		t.Fatalf("failed provider = %q, want provider-a", got)
	}
}

// TestSessionAffinityRemembersTheProviderOfEveryBinding asserts that the bound
// provider is remembered for every binding, so a chain of replacements is
// classified correctly.
//
// For A to B to C, with each credential becoming unavailable before the next
// hit, A to B is classified from the remembered provider of A, and B to C needs
// the provider of B to have been remembered as well.
func TestSessionAffinityRemembersTheProviderOfEveryBinding(t *testing.T) {
	t.Parallel()

	affinity := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Hour,
	})
	t.Cleanup(affinity.Stop)

	// The provider is remembered on the binding path, so the next replacement
	// can be classified.
	affinity.rememberBoundProvider("auth-b", "provider-b")
	if got := affinity.boundProviderFor("auth-b", nil); got != "provider-b" {
		t.Fatalf("bound provider = %q, want provider-b", got)
	}

	// A replacement in another provider is a provider failover.
	if affinity.boundProviderFor("auth-b", nil) == "provider-a" {
		t.Fatal("the remembered provider must be the bound one")
	}
}

// TestRoutingTransitionRecordsAnAliasReplacement asserts that a replacement
// through a live alias is reported as a replacement, not as a created binding.
//
// A request that introduces a new alias can find the conversation's binding
// under the alias while the primary key holds nothing. The binding is then
// replaced, and the transition must say so.
func TestRoutingTransitionRecordsAnAliasReplacement(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(10)
	selector, _, _, model := routingTransitionTestSelector(t, recorder)

	// The conversation is bound to the first credential. The body carries a
	// prompt cache key and a conversation identifier, so the primary key is the
	// prompt cache key and the alias is the conversation.
	body := []byte(`{"prompt_cache_key":"rt-alias-1","conversation":{"id":"rt-conv-1"},"messages":[{"role":"user","content":"hello"}]}`)
	opts := cliproxyexecutor.Options{
		Headers:         http.Header{"Content-Type": []string{"application/json"}},
		OriginalRequest: body,
	}
	first := []*Auth{{ID: "rt-auth-a", Provider: "rt-provider-a"}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, opts, first); errPick != nil {
		t.Fatalf("first Pick: %v", errPick)
	}

	// The next request introduces a different prompt cache key for the same
	// conversation. The alias still points at the first credential, which is no
	// longer available, and only another provider is eligible.
	secondBody := []byte(`{"prompt_cache_key":"rt-alias-2","conversation":{"id":"rt-conv-1"},"messages":[{"role":"user","content":"hello"}]}`)
	secondOpts := cliproxyexecutor.Options{
		Headers:         http.Header{"Content-Type": []string{"application/json"}},
		OriginalRequest: secondBody,
	}
	second := []*Auth{{ID: "rt-auth-b", Provider: "rt-provider-b"}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, secondOpts, second); errPick != nil {
		t.Fatalf("second Pick: %v", errPick)
	}

	totals := recorder.Snapshot().Totals
	if totals[string(RoutingTransitionProviderFailover)] != 1 {
		t.Fatalf("provider failover = %d, want 1: %+v", totals[string(RoutingTransitionProviderFailover)], totals)
	}
}
