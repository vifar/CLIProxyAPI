package auth

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/session"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// TestRoutingTransitionLongSequenceFailureIsAttributedToTheContinuation
// asserts that the failure of a long conversation is attributed to the
// conversation that continues it.
//
// The matcher truncates a long sequence to its turn limit before it binds,
// matches and removes it. The identity of the failure record has to be derived
// the same way, or a record of a long conversation could never be found by the
// conversation that continues it: the retry would be reported as a creation
// instead of as the replacement it was.
func TestRoutingTransitionLongSequenceFailureIsAttributedToTheContinuation(t *testing.T) {
	t.Parallel()

	const maxTurns = 4

	recorder := NewRoutingTransitionRecorder(4096)
	matcher := cliproxysession.NewMerklePrefixMatcherWithConfig(cliproxysession.MerklePrefixMatcherConfig{
		TTL:      time.Minute,
		MaxTurns: maxTurns,
	})
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Fallback: &RoundRobinSelector{},
		TTL:      time.Minute,
	})
	selector.matcher = matcher
	t.Cleanup(selector.Stop)
	installRoutingTransitionRecorder(t, recorder)

	providerA := "rt-provider-a"
	providerB := "rt-provider-b"
	model := "rt-long-model"

	// The conversation is longer than the matcher's turn limit.
	conversation := func(turns int) string {
		var builder strings.Builder
		builder.WriteString(`{"messages":[`)
		for i := 0; i < turns; i++ {
			if i > 0 {
				builder.WriteString(",")
			}
			role := "user"
			if i%2 == 1 {
				role = "assistant"
			}
			fmt.Fprintf(&builder, `{"role":%q,"content":"turn-%d"}`, role, i)
		}
		builder.WriteString(`]}`)
		return builder.String()
	}
	opts := func(turns int) cliproxyexecutor.Options {
		return cliproxyexecutor.Options{
			SourceFormat:    sdktranslator.FormatOpenAI,
			OriginalRequest: []byte(conversation(turns)),
			Metadata: map[string]any{
				cliproxyexecutor.CallerScopeMetadataKey: "caller-a",
			},
		}
	}

	// The long conversation binds the first credential.
	longOpts := opts(maxTurns + 2)
	first := []*Auth{{ID: "rt-long-auth-a", Provider: providerA}}
	picked, errPick := selector.Pick(context.Background(), "mixed", model, longOpts, first)
	if errPick != nil {
		t.Fatalf("first Pick: %v", errPick)
	}
	if picked == nil || picked.ID != "rt-long-auth-a" {
		t.Fatalf("picked = %+v, want rt-long-auth-a", picked)
	}

	// The credential fails.
	selector.OnResult(Result{
		AuthID:   "rt-long-auth-a",
		Provider: "mixed",
		Model:    model,
		Success:  false,
		Error:    &Error{Code: ErrorCodeForceCooldown, Message: "unavailable"},
		Options:  longOpts,
	})

	// A continuation that shares the first turns finds the attribution.
	continueOpts := opts(maxTurns + 1)
	second := []*Auth{{ID: "rt-long-auth-b", Provider: providerB}}
	picked, errPick = selector.Pick(context.Background(), "mixed", model, continueOpts, second)
	if errPick != nil {
		t.Fatalf("continuation Pick: %v", errPick)
	}
	if picked == nil || picked.ID != "rt-long-auth-b" {
		t.Fatalf("picked = %+v, want rt-long-auth-b", picked)
	}

	events := routingTransitionEvents(recorder, model)
	if len(events) == 0 {
		t.Fatal("no transition was recorded")
	}
	last := events[len(events)-1]
	if last.Transition != RoutingTransitionProviderFailover {
		t.Fatalf("the continuation = %q, want %q: %+v", last.Transition, RoutingTransitionProviderFailover, last)
	}
	if last.PreviousProvider != providerA {
		t.Fatalf("previous provider = %q, want %q: %+v", last.PreviousProvider, providerA, last)
	}
}
