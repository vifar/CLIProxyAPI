package auth

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/session"
)

// The regressions in this file cover the two defects the review found in the
// routing transition classification:
//
//   - the predecessor of a binding was read outside the binding transaction, so
//     a transition could be reported against a credential that had already been
//     replaced, and two concurrent cold requests could both report a creation.
//
//   - the failure attribution was published under one set of identifiers and
//     consumed under another, so a retry could miss it, a child could never
//     find its own record, and a failure could leave the binding's other
//     identifiers pointing at the failed credential.

// routingTransitionOptions builds the request options for a conversation that is
// addressed by a prompt cache key and a conversation identifier.
func routingTransitionOptions(provider, model, promptCacheKey, conversationID string) cliproxyexecutor.Options {
	return cliproxyexecutor.Options{
		Headers: http.Header{"Content-Type": []string{"application/json"}},
		OriginalRequest: []byte(`{"prompt_cache_key":"` + promptCacheKey +
			`","conversation":{"id":"` + conversationID + `"},"messages":[{"role":"user","content":"hello"}]}`),
		Metadata: map[string]any{
			cliproxyexecutor.SessionAffinityProviderMetadataKey: provider,
			cliproxyexecutor.SessionAffinityModelMetadataKey:    model,
		},
	}
}

// routingTransitionEvents returns the recorded events for one model.
//
// The recorder is process-wide, so events of another test can be recorded into
// it while it is installed. A test only looks at the events of its own model.
func routingTransitionEvents(recorder *RoutingTransitionRecorder, model string) []RoutingTransitionEvent {
	var events []RoutingTransitionEvent
	for _, event := range recorder.Snapshot().Events {
		if event.Model == model {
			events = append(events, event)
		}
	}
	return events
}

// routingTransitionKeys returns the cache keys a request's primary identifier
// and fallback identifier produce, the same way the selector builds them.
func routingTransitionKeys(t *testing.T, provider, model string, opts cliproxyexecutor.Options) (string, string) {
	t.Helper()
	primary, fallback := extractSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
	primary = cliproxysession.BoundSessionIdentity(primary)
	fallback = cliproxysession.BoundSessionIdentity(fallback)
	modelKey := canonicalModelKey(model)
	return provider + "::" + primary + "::" + modelKey, provider + "::" + fallback + "::" + modelKey
}

// hookFallback runs a hook before it picks, so a test can interleave another
// request at a chosen point.
type hookFallback struct {
	mu      sync.Mutex
	hook    func()
	pending bool
	pick    *Auth
}

func (f *hookFallback) Pick(_ context.Context, _, _ string, _ cliproxyexecutor.Options, _ []*Auth) (*Auth, error) {
	f.mu.Lock()
	hook := f.hook
	f.hook = nil
	f.mu.Unlock()
	if hook != nil {
		hook()
	}
	return f.pick, nil
}

// barrierFallback holds every caller until the expected number of them has
// arrived, so two requests reach the binding transaction together.
type barrierFallback struct {
	mu      sync.Mutex
	arrived int
	release chan struct{}
	want    int
	pick    *Auth
}

func newBarrierFallback(want int, pick *Auth) *barrierFallback {
	return &barrierFallback{release: make(chan struct{}), want: want, pick: pick}
}

func (f *barrierFallback) Pick(ctx context.Context, _, _ string, _ cliproxyexecutor.Options, _ []*Auth) (*Auth, error) {
	f.mu.Lock()
	f.arrived++
	if f.arrived >= f.want {
		select {
		case <-f.release:
		default:
			close(f.release)
		}
	}
	f.mu.Unlock()
	select {
	case <-f.release:
		return f.pick, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(10 * time.Second):
		return nil, errors.New("the barrier was never released")
	}
}

// TestRoutingTransitionStalePredecessorIsNotReported asserts that a transition
// is reported against the credential that was really replaced.
//
// The predecessor of a binding must be read inside the binding transaction. A
// request that read it before another request rebound the conversation would
// report the replacement of a credential that had already been replaced.
func TestRoutingTransitionStalePredecessorIsNotReported(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(10)
	selector, _, providerA, model := routingTransitionTestSelector(t, recorder)

	// The conversation is bound to the first credential.
	firstOpts := routingTransitionOptions("mixed", model, "rt-stale-pck-a", "rt-stale-conv")
	first := []*Auth{{ID: "rt-auth-a", Provider: providerA}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, firstOpts, first); errPick != nil {
		t.Fatalf("first Pick: %v", errPick)
	}
	_, aliasKey := routingTransitionKeys(t, "mixed", model, firstOpts)

	// The second request finds the conversation under its identifier, but the
	// bound credential is no longer among the candidates, so the binding is
	// replaced. While it chooses, a concurrent request rebinds the
	// conversation to another credential.
	providerB := "rt-provider-b"
	fallback := &hookFallback{pick: &Auth{ID: "rt-auth-c", Provider: "rt-provider-c"}}
	fallback.hook = func() {
		selector.withAffinityState(func(state *sessionAffinityState) {
			selector.cache.SetAliases("rt-auth-b", aliasKey, "mixed::rt-stale-pck-b::rt-model")
			selector.rememberBoundProviderLocked(state, "rt-auth-b", providerB)
		})
	}
	selector.fallback = fallback

	secondOpts := routingTransitionOptions("mixed", model, "rt-stale-pck-b", "rt-stale-conv")
	second := []*Auth{{ID: "rt-auth-b", Provider: providerB}, {ID: "rt-auth-c", Provider: "rt-provider-c"}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, secondOpts, second); errPick != nil {
		t.Fatalf("second Pick: %v", errPick)
	}

	events := routingTransitionEvents(recorder, model)
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2: %+v", len(events), events)
	}
	last := events[len(events)-1]
	if last.Transition != RoutingTransitionProviderFailover {
		t.Fatalf("last transition = %q, want %q: %+v", last.Transition, RoutingTransitionProviderFailover, last)
	}
	// The credential that was really replaced is the one the concurrent request
	// bound, not the one that was bound before it.
	if last.PreviousProvider != providerB {
		t.Fatalf("previous provider = %q, want %q: %+v", last.PreviousProvider, providerB, last)
	}
}

// TestRoutingTransitionConcurrentColdRequestsReportOneCreation asserts that two
// concurrent cold requests for one conversation do not both report a creation.
//
// The second request finds the binding the first one wrote, so it is a hit and
// not the creation of a second binding.
func TestRoutingTransitionConcurrentColdRequestsReportOneCreation(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(10)
	manager := NewManager(nil, nil, nil)
	fallback := newBarrierFallback(2, &Auth{ID: "rt-auth-a", Provider: "rt-provider-a"})
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: fallback,
		TTL:      time.Hour,
	})
	t.Cleanup(selector.Stop)
	manager.SetSelector(selector)
	installRoutingTransitionRecorder(t, recorder)

	model := "rt-txn-model"
	auths := []*Auth{{ID: "rt-auth-a", Provider: "rt-provider-a"}}

	// Both requests run at the same time, so both miss the binding and reach
	// the binding transaction together.
	var wg sync.WaitGroup
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			defer wg.Done()
			// Each request has its own options, so the metadata map is not
			// shared between two requests that run at the same time.
			requestOpts := routingTransitionOptions("mixed", model, "rt-cold-pck", "rt-cold-conv")
			if _, errPick := selector.Pick(context.Background(), "mixed", model, requestOpts, auths); errPick != nil {
				t.Errorf("Pick: %v", errPick)
			}
		}()
	}
	wg.Wait()

	events := routingTransitionEvents(recorder, model)
	if len(events) != 2 {
		t.Fatalf("events = %d, want 2: %+v", len(events), events)
	}
	creations := 0
	hits := 0
	for _, event := range events {
		switch event.Transition {
		case RoutingTransitionBindingCreated:
			creations++
		case RoutingTransitionBindingHit:
			hits++
		}
	}
	if creations != 1 {
		t.Fatalf("creations = %d, want exactly 1: %+v", creations, events)
	}
	if hits != 1 {
		t.Fatalf("hits = %d, want exactly 1: %+v", hits, events)
	}
}

// TestRoutingTransitionFailureRemovesTheWholeBinding asserts that a credential
// failure invalidates the whole binding and not one of its names.
//
// The failure is reported for one of the binding's identifiers. The other one
// must not keep pointing at the failed credential, and a retry through it must
// not reuse it.
func TestRoutingTransitionFailureRemovesTheWholeBinding(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(10)
	selector, _, providerA, model := routingTransitionTestSelector(t, recorder)

	firstOpts := routingTransitionOptions("mixed", model, "rt-whole-pck-a", "rt-whole-conv")
	primaryKey, aliasKey := routingTransitionKeys(t, "mixed", model, firstOpts)
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

	// The failure invalidates the whole binding. Neither of its identifiers may
	// keep pointing at the failed credential.
	for _, key := range []string{primaryKey, aliasKey} {
		if bound, ok := selector.cache.Get(key); ok && bound == "rt-auth-a" {
			t.Fatalf("the binding %q still points at the failed credential", key)
		}
	}

	// The retry carries the other prompt cache key for the same conversation.
	// It must find the attribution and be reported as the replacement it is.
	secondOpts := routingTransitionOptions("mixed", model, "rt-whole-pck-b", "rt-whole-conv")
	second := []*Auth{{ID: "rt-auth-b", Provider: "rt-provider-b"}}
	picked, errPick := selector.Pick(context.Background(), "mixed", model, secondOpts, second)
	if errPick != nil {
		t.Fatalf("second Pick: %v", errPick)
	}
	if picked == nil || picked.ID != "rt-auth-b" {
		t.Fatalf("picked = %+v, want rt-auth-b", picked)
	}

	events := routingTransitionEvents(recorder, model)
	last := events[len(events)-1]
	if last.Transition != RoutingTransitionProviderFailover {
		t.Fatalf("last transition = %q, want %q: %+v", last.Transition, RoutingTransitionProviderFailover, last)
	}
	if last.PreviousProvider != providerA {
		t.Fatalf("previous provider = %q, want %q: %+v", last.PreviousProvider, providerA, last)
	}

	// The attribution is consumed once.
	state := selector.affinityState
	if state == nil {
		t.Fatal("the affinity state must exist")
	}
	state.mu.Lock()
	remaining := len(state.failedBindings)
	state.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("failed binding records = %d, want 0", remaining)
	}
}

// TestRoutingTransitionLateFailureRemovesTheReboundBinding asserts that a late
// failure invalidates the binding the conversation has now, not only the name
// the failing request used.
//
// The conversation is addressed by one prompt cache key, then by another, and
// the failure of the first request arrives afterwards. The binding the
// conversation has now must not keep pointing at the failed credential.
func TestRoutingTransitionLateFailureRemovesTheReboundBinding(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(10)
	selector, _, providerA, model := routingTransitionTestSelector(t, recorder)

	// The conversation is bound under the first prompt cache key.
	firstOpts := routingTransitionOptions("mixed", model, "rt-late-pck-a", "rt-late-conv")
	first := []*Auth{{ID: "rt-auth-a", Provider: providerA}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, firstOpts, first); errPick != nil {
		t.Fatalf("first Pick: %v", errPick)
	}

	// The conversation is addressed by another prompt cache key, and the binding
	// follows it.
	secondOpts := routingTransitionOptions("mixed", model, "rt-late-pck-b", "rt-late-conv")
	second := []*Auth{{ID: "rt-auth-a", Provider: providerA}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, secondOpts, second); errPick != nil {
		t.Fatalf("second Pick: %v", errPick)
	}
	secondPrimaryKey, secondAliasKey := routingTransitionKeys(t, "mixed", model, secondOpts)

	// The failure of the first request arrives afterwards.
	selector.OnResult(Result{
		AuthID:   "rt-auth-a",
		Provider: "mixed",
		Model:    model,
		Success:  false,
		Error:    &Error{Code: ErrorCodeForceCooldown, Message: "unavailable"},
		Options:  firstOpts,
	})

	// The binding the conversation has now must not keep pointing at the failed
	// credential, whichever of its identifiers the failure was reported under.
	for _, key := range []string{secondPrimaryKey, secondAliasKey} {
		if bound, ok := selector.cache.Get(key); ok && bound == "rt-auth-a" {
			t.Fatalf("the binding %q still points at the failed credential", key)
		}
	}
}

// TestRoutingTransitionChildRetryFindsItsOwnAttribution asserts that a child's
// retry finds the child's own failure record.
//
// A subagent's fallback identifier is its parent's session, and a parent's
// session is not an alias of the child's binding. The child must therefore be
// keyed by its own identifier, and its retry must be reported as the
// replacement it is.
func TestRoutingTransitionChildRetryFindsItsOwnAttribution(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(10)
	selector, _, providerA, model := routingTransitionTestSelector(t, recorder)

	// The child's session identifier carries the agent marker, so it is a
	// subagent whose fallback identifier is its parent's session.
	childOpts := routingTransitionOptions("mixed", model, "rt-child:agent:pck", "rt-child-parent-conv")
	child := []*Auth{{ID: "rt-auth-a", Provider: providerA}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, childOpts, child); errPick != nil {
		t.Fatalf("first Pick: %v", errPick)
	}

	selector.OnResult(Result{
		AuthID:   "rt-auth-a",
		Provider: "mixed",
		Model:    model,
		Success:  false,
		Error:    &Error{Code: ErrorCodeForceCooldown, Message: "unavailable"},
		Options:  childOpts,
	})

	// The retry of the child finds its own attribution.
	retryOpts := routingTransitionOptions("mixed", model, "rt-child:agent:pck", "rt-child-parent-conv")
	retry := []*Auth{{ID: "rt-auth-b", Provider: "rt-provider-b"}}
	if _, errPick := selector.Pick(context.Background(), "mixed", model, retryOpts, retry); errPick != nil {
		t.Fatalf("retry Pick: %v", errPick)
	}

	events := routingTransitionEvents(recorder, model)
	last := events[len(events)-1]
	if last.Transition != RoutingTransitionProviderFailover {
		t.Fatalf("last transition = %q, want %q: %+v", last.Transition, RoutingTransitionProviderFailover, last)
	}
	if last.PreviousProvider != providerA {
		t.Fatalf("previous provider = %q, want %q: %+v", last.PreviousProvider, providerA, last)
	}
}
