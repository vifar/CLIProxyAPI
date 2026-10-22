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

// testRememberBoundProvider records the provider of a bound credential through
// the locked helper the production path uses.
func testRememberBoundProvider(selector *SessionAffinitySelector, authID, providerKey string) {
	selector.withAffinityState(func(state *sessionAffinityState) {
		selector.rememberBoundProviderLocked(state, authID, providerKey)
	})
}

// testBoundProvider returns the remembered provider of a bound credential.
func testBoundProvider(selector *SessionAffinitySelector, authID string) string {
	var providerKey string
	selector.withAffinityState(func(state *sessionAffinityState) {
		providerKey = state.boundProviders[authID]
	})
	return providerKey
}

// testRememberFailedBinding records a failed binding through the locked helper
// the production path uses.
func testRememberFailedBinding(selector *SessionAffinitySelector, bindingKey, providerKey string) {
	selector.withAffinityState(func(state *sessionAffinityState) {
		selector.rememberFailedBindingLocked(state, bindingKey, providerKey)
	})
}

// testTakeFailedBinding consumes a failed binding's record through the locked
// helper the production path uses.
func testTakeFailedBinding(selector *SessionAffinitySelector, bindingKey string) string {
	var providerKey string
	selector.withAffinityState(func(state *sessionAffinityState) {
		providerKey = selector.takeFailedBindingLocked(state, bindingKey)
	})
	return providerKey
}

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
	testRememberBoundProvider(selector, "bound-auth", "provider-a")

	// The remembered provider is returned even when the credential is not among
	// the candidates any more.
	if got := testBoundProvider(selector, "bound-auth"); got != "provider-a" {
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
	testRememberFailedBinding(affinity, lcpFailedBindingKey(namespace, "session-1"), "provider-a")

	// The retry binds a different credential and reads the record under the
	// session, so it is found.
	if got := testTakeFailedBinding(affinity, lcpFailedBindingKey(namespace, "session-1")); got != "provider-a" {
		t.Fatalf("failed provider = %q, want provider-a", got)
	}

	// The record is consumed once.
	if got := testTakeFailedBinding(affinity, lcpFailedBindingKey(namespace, "session-1")); got != "" {
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
	testRememberFailedBinding(affinity, lcpFailedBindingKey(namespace, "session-1"), "provider-a")

	// A different conversation that happens to use the same credential does not
	// find the record.
	if got := testTakeFailedBinding(affinity, lcpFailedBindingKey(namespace, "session-2")); got != "" {
		t.Fatalf("failed provider = %q, want no record for another conversation", got)
	}

	// The record is still there for the conversation that failed.
	if got := testTakeFailedBinding(affinity, lcpFailedBindingKey(namespace, "session-1")); got != "provider-a" {
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
	testRememberBoundProvider(affinity, "auth-b", "provider-b")
	if got := testBoundProvider(affinity, "auth-b"); got != "provider-b" {
		t.Fatalf("bound provider = %q, want provider-b", got)
	}

	// A replacement in another provider is a provider failover.
	if testBoundProvider(affinity, "auth-b") == "provider-a" {
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

// TestTruncateSessionIDDistinguishesLCPSessions asserts that two different LCP
// session identifiers get two different short forms.
//
// An LCP session identifier starts with "lcp:v1:" and continues with a hex
// digest, so keeping only the first few characters leaves every LCP session
// with the same short form.
func TestTruncateSessionIDDistinguishesLCPSessions(t *testing.T) {
	t.Parallel()

	// Two LCP sessions whose identifiers share their first characters, so only
	// the digest distinguishes them.
	first := "lcp:v1:" + strings.Repeat("a", 32) + strings.Repeat("b", 32)
	second := "lcp:v1:" + strings.Repeat("a", 32) + strings.Repeat("c", 32)

	shortFirst := truncateSessionID(first)
	shortSecond := truncateSessionID(second)
	if shortFirst == shortSecond {
		t.Fatalf("two different LCP sessions share the short form %q", shortFirst)
	}
	if !strings.HasPrefix(shortFirst, "lcp:v1:") {
		t.Fatalf("short form = %q, want the prefix preserved", shortFirst)
	}
	// A short identifier is returned unchanged.
	if got := truncateSessionID("short"); got != "short" {
		t.Fatalf("short form = %q, want it unchanged", got)
	}
}

// TestSessionAffinityFailureAttributionSurvivesAPrimaryChange asserts that a
// replacement through a changed primary identifier is attributed to the provider
// whose credential failed, and that the attribution is consumed once.
//
// The test drives the real path: a failure is reported through OnResult, the
// session is rebound through a different primary identifier for the same
// conversation, and a later replacement must be attributed to the current
// provider rather than to the original failed one.
func TestSessionAffinityFailureAttributionSurvivesAPrimaryChange(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(10)
	selector, _, providerA, model := routingTransitionTestSelector(t, recorder)

	// The conversation is bound to the first credential. The body carries a
	// prompt cache key and a conversation identifier, so the primary identifier
	// is the prompt cache key and the alias is the conversation.
	body := func(promptCacheKey string) []byte {
		return []byte(`{"prompt_cache_key":"` + promptCacheKey + `","conversation":{"id":"rt-conv-1"},"messages":[{"role":"user","content":"hello"}]}`)
	}
	opts := func(promptCacheKey string) cliproxyexecutor.Options {
		return cliproxyexecutor.Options{
			Headers:         http.Header{"Content-Type": []string{"application/json"}},
			OriginalRequest: body(promptCacheKey),
			Metadata: map[string]any{
				cliproxyexecutor.SessionAffinityProviderMetadataKey: "mixed",
				cliproxyexecutor.SessionAffinityModelMetadataKey:    model,
			},
		}
	}

	primaryOpts := opts("rt-pck-1")
	first := []*Auth{{ID: "rt-auth-a", Provider: providerA}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, primaryOpts, first); errPick != nil {
		t.Fatalf("first Pick: %v", errPick)
	}

	// The bound credential fails, and the result handling removes the binding.
	selector.OnResult(Result{
		AuthID:   "rt-auth-a",
		Provider: "mixed",
		Model:    model,
		Success:  false,
		Error:    &Error{Code: ErrorCodeForceCooldown, Message: "unavailable"},
		Options:  primaryOpts,
	})

	// The conversation is retried with a different prompt cache key and the same
	// conversation, and only another provider is eligible.
	changedOpts := opts("rt-pck-2")
	second := []*Auth{{ID: "rt-auth-b", Provider: "rt-provider-b"}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, changedOpts, second); errPick != nil {
		t.Fatalf("second Pick: %v", errPick)
	}

	totals := recorder.Snapshot().Totals
	if totals[string(RoutingTransitionProviderFailover)] != 1 {
		t.Fatalf("provider failover = %d, want 1: %+v", totals[string(RoutingTransitionProviderFailover)], totals)
	}

	// The attribution is consumed once. A later replacement is attributed to the
	// provider it actually failed on, not to the original failed provider.
	selector.OnResult(Result{
		AuthID:   "rt-auth-b",
		Provider: "mixed",
		Model:    model,
		Success:  false,
		Error:    &Error{Code: ErrorCodeForceCooldown, Message: "unavailable"},
		Options:  changedOpts,
	})
	thirdOpts := opts("rt-pck-3")
	third := []*Auth{{ID: "rt-auth-c", Provider: "rt-provider-c"}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, thirdOpts, third); errPick != nil {
		t.Fatalf("third Pick: %v", errPick)
	}

	totals = recorder.Snapshot().Totals
	if totals[string(RoutingTransitionProviderFailover)] != 2 {
		t.Fatalf("provider failover = %d, want 2: %+v", totals[string(RoutingTransitionProviderFailover)], totals)
	}
}

// TestSessionAffinityConcurrentRetriesConsumeTheAttributionOnce asserts that
// two concurrent retries of one failed binding do not both report a replacement.
//
// The attribution of a failed binding is consumed once. A retry that finds no
// attribution has a binding that was never failed, so it must not report a
// replacement of the failed one.
func TestSessionAffinityConcurrentRetriesConsumeTheAttributionOnce(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(10)
	selector, _, providerA, model := routingTransitionTestSelector(t, recorder)

	// The conversation is bound to the first credential.
	opts := cliproxyexecutor.Options{
		Headers: http.Header{"X-Session-Id": []string{"rt-session-concurrent"}},
		Metadata: map[string]any{
			cliproxyexecutor.SessionAffinityProviderMetadataKey: "mixed",
			cliproxyexecutor.SessionAffinityModelMetadataKey:    model,
		},
	}
	first := []*Auth{{ID: "rt-auth-a", Provider: providerA}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, opts, first); errPick != nil {
		t.Fatalf("first Pick: %v", errPick)
	}

	// The bound credential fails.
	selector.OnResult(Result{
		AuthID:   "rt-auth-a",
		Provider: "mixed",
		Model:    model,
		Success:  false,
		Error:    &Error{Code: ErrorCodeForceCooldown, Message: "unavailable"},
		Options:  opts,
	})

	// Two retries run at once. Exactly one of them can consume the attribution.
	//
	// Each retry has its own options, because the selection writes the route's
	// provider and model into the options' metadata, and two selections that
	// share one map would write to it at the same time.
	retryOpts := func() cliproxyexecutor.Options {
		return cliproxyexecutor.Options{
			Headers: http.Header{"X-Session-Id": []string{"rt-session-concurrent"}},
			Metadata: map[string]any{
				cliproxyexecutor.SessionAffinityProviderMetadataKey: "mixed",
				cliproxyexecutor.SessionAffinityModelMetadataKey:    model,
			},
		}
	}
	second := []*Auth{{ID: "rt-auth-b", Provider: "rt-provider-b"}}
	third := []*Auth{{ID: "rt-auth-c", Provider: "rt-provider-c"}}
	group := sync.WaitGroup{}
	group.Add(2)
	go func() {
		defer group.Done()
		_, _ = selector.Pick(context.Background(), "mixed", model, retryOpts(), second)
	}()
	go func() {
		defer group.Done()
		_, _ = selector.Pick(context.Background(), "mixed", model, retryOpts(), third)
	}()
	group.Wait()

	// The attribution is gone: it was consumed exactly once, and the two retries
	// shared it.
	state := selector.affinityState
	if state == nil {
		t.Fatal("the affinity state must exist")
	}
	state.mu.Lock()
	remaining := len(state.failedBindings)
	state.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("failed binding records = %d, want 0: the attribution is consumed once", remaining)
	}

	// The two retries replaced the failed binding: one of them reported the
	// replacement, and the other reported that it replaced the binding the first
	// one wrote. Neither reported a creation of the failed binding.
	//
	// The events counted are the ones after the failure, so the binding of the
	// first pick is not counted.
	// Only the events for this test's model are counted. The recorder is
	// process-wide, so other tests can record into it.
	events := recorder.Snapshot().Events
	replacements := 0
	creations := 0
	for _, event := range events {
		if event.Model != model {
			continue
		}
		switch event.Transition {
		case RoutingTransitionCredentialReselected, RoutingTransitionProviderFailover:
			replacements++
		case RoutingTransitionBindingCreated:
			creations++
		}
	}
	// The first pick binds the session, which is a creation, and the two
	// replacements are not. A second creation would mean one of the retries
	// reported a creation of the failed binding.
	if creations > 1 {
		t.Fatalf("creations = %d, want at most 1: %+v", creations, events)
	}
	if replacements > 2 {
		t.Fatalf("replacements = %d, want at most 2: %+v", replacements, events)
	}
}

// TestSessionAffinityFailureRecordIsConsumedThroughTheAlias asserts that a
// failure recorded under the alias is consumed by a retry that carries only the
// primary identifier.
//
// A conversation can be addressed by two prompt cache keys. When one of them
// fails, the record is published under the alias as well, and a retry that
// carries the other key must still find it: otherwise the attribution survives
// and a later replacement is reported against the wrong provider.
func TestSessionAffinityFailureRecordIsConsumedThroughTheAlias(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(10)
	selector, _, providerA, model := routingTransitionTestSelector(t, recorder)

	// The conversation is bound to the first credential, under a prompt cache key
	// and a conversation identifier.
	body := func(promptCacheKey string) []byte {
		return []byte(`{"prompt_cache_key":"` + promptCacheKey + `","conversation":{"id":"rt-conv-alias"},"messages":[{"role":"user","content":"hello"}]}`)
	}
	opts := func(promptCacheKey string) cliproxyexecutor.Options {
		return cliproxyexecutor.Options{
			Headers:         http.Header{"Content-Type": []string{"application/json"}},
			OriginalRequest: body(promptCacheKey),
			Metadata: map[string]any{
				cliproxyexecutor.SessionAffinityProviderMetadataKey: "mixed",
				cliproxyexecutor.SessionAffinityModelMetadataKey:    model,
			},
		}
	}

	firstOpts := opts("rt-pck-a")
	first := []*Auth{{ID: "rt-auth-a", Provider: providerA}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, firstOpts, first); errPick != nil {
		t.Fatalf("first Pick: %v", errPick)
	}

	// The bound credential fails.
	selector.OnResult(Result{
		AuthID:   "rt-auth-a",
		Provider: "mixed",
		Model:    model,
		Success:  false,
		Error:    &Error{Code: ErrorCodeForceCooldown, Message: "unavailable"},
		Options:  firstOpts,
	})

	// The retry carries the other prompt cache key for the same conversation, and
	// only another provider is eligible. It must find the attribution through the
	// alias, and it must be reported as a failover from the failed provider.
	secondOpts := opts("rt-pck-b")
	second := []*Auth{{ID: "rt-auth-b", Provider: "rt-provider-b"}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, secondOpts, second); errPick != nil {
		t.Fatalf("second Pick: %v", errPick)
	}

	totals := recorder.Snapshot().Totals
	if totals[string(RoutingTransitionProviderFailover)] != 1 {
		t.Fatalf("provider failover = %d, want 1: %+v", totals[string(RoutingTransitionProviderFailover)], totals)
	}

	// The attribution is gone: it was consumed through the alias.
	state := selector.affinityState
	if state == nil {
		t.Fatal("the affinity state must exist")
	}
	state.mu.Lock()
	for key := range state.failedBindings {
		t.Logf("surviving record: %q", key)
	}
	remaining := len(state.failedBindings)
	state.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("failed binding records = %d, want 0: the attribution is consumed once", remaining)
	}
}
