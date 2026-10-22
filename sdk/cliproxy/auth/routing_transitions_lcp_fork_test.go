package auth

import (
	"context"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// TestRoutingTransitionLCPForkFailureIsAttributedToTheFork asserts that a
// failure of a fork's credential is attributed to the fork.
//
// A fork has a binding of its own: the matched parent supplies the credential,
// but the fork's sequence is bound separately. Without that binding the result
// handling finds no sequence to remove, publishes no attribution, and the retry
// is reported as another creation instead of as the replacement it is.
func TestRoutingTransitionLCPForkFailureIsAttributedToTheFork(t *testing.T) {
	t.Parallel()

	recorder := NewRoutingTransitionRecorder(4096)
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Minute,
	})
	t.Cleanup(selector.Stop)
	installRoutingTransitionRecorder(t, recorder)

	providerA := "rt-provider-a"
	providerB := "rt-provider-b"
	model := "rt-lcp-model"

	// The parent conversation binds the first credential.
	parentOpts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		OriginalRequest: []byte(`{"messages":[{"role":"user","content":"one"},` +
			`{"role":"assistant","content":"two"},{"role":"user","content":"three"}]}`),
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
		},
	}
	parent := []*Auth{{ID: "rt-lcp-auth-a", Provider: providerA}}
	picked, errPick := selector.Pick(context.Background(), "mixed", model, parentOpts, parent)
	if errPick != nil {
		t.Fatalf("parent Pick: %v", errPick)
	}
	if picked == nil || picked.ID != "rt-lcp-auth-a" {
		t.Fatalf("picked = %+v, want rt-lcp-auth-a", picked)
	}

	// The fork diverges from the parent after the shared prefix.
	forkOpts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		OriginalRequest: []byte(`{"messages":[{"role":"user","content":"one"},` +
			`{"role":"assistant","content":"two"},{"role":"user","content":"different"}]}`),
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
		},
	}
	fork := []*Auth{{ID: "rt-lcp-auth-a", Provider: providerA}}
	picked, errPick = selector.Pick(context.Background(), "mixed", model, forkOpts, fork)
	if errPick != nil {
		t.Fatalf("fork Pick: %v", errPick)
	}
	if picked == nil || picked.ID != "rt-lcp-auth-a" {
		t.Fatalf("picked = %+v, want rt-lcp-auth-a", picked)
	}

	// The fork's credential fails.
	selector.OnResult(Result{
		AuthID:   "rt-lcp-auth-a",
		Provider: "mixed",
		Model:    model,
		Success:  false,
		Error:    &Error{Code: ErrorCodeForceCooldown, Message: "unavailable"},
		Options:  forkOpts,
	})

	// The retry finds the attribution and is reported as the replacement it is.
	retryOpts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAI,
		OriginalRequest: []byte(`{"messages":[{"role":"user","content":"one"},` +
			`{"role":"assistant","content":"two"},{"role":"user","content":"different"}]}`),
		Metadata: map[string]any{
			cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
		},
	}
	retry := []*Auth{{ID: "rt-lcp-auth-b", Provider: providerB}}
	picked, errPick = selector.Pick(context.Background(), "mixed", model, retryOpts, retry)
	if errPick != nil {
		t.Fatalf("retry Pick: %v", errPick)
	}
	if picked == nil || picked.ID != "rt-lcp-auth-b" {
		t.Fatalf("picked = %+v, want rt-lcp-auth-b", picked)
	}

	events := routingTransitionEvents(recorder, model)
	if len(events) == 0 {
		t.Fatal("no transition was recorded")
	}
	last := events[len(events)-1]
	if last.Transition != RoutingTransitionProviderFailover {
		t.Fatalf("the retry = %q, want %q: %+v", last.Transition, RoutingTransitionProviderFailover, last)
	}
	if last.PreviousProvider != providerA {
		t.Fatalf("previous provider = %q, want %q: %+v", last.PreviousProvider, providerA, last)
	}
}
