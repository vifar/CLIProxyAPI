package openai

import "testing"

// TestResponsesLocalInterruptOnlyReachesTheActiveResponse asserts that a local
// interrupt is only delivered to the response that is in flight.
//
// An interrupt names a response. Delivering one that names a response that
// already completed would report an incomplete response for a finished one and
// cancel the response that is running.
func TestResponsesLocalInterruptOnlyReachesTheActiveResponse(t *testing.T) {
	t.Parallel()

	local := newResponsesLocalInterrupt()

	// An interrupt before any response is known is delivered, as it was
	// before: the turn is in flight and no response has been created.
	local.begin()
	if !local.deliver([]byte(`{"type":"response.interrupt","response_id":"unknown"}`)) {
		t.Fatal("an interrupt for an unknown response was not delivered")
	}

	// A response is in flight: an interrupt for another response is refused.
	local.setResponseID("r2")
	if local.deliver([]byte(`{"type":"response.interrupt","response_id":"r1"}`)) {
		t.Fatal("an interrupt for another response was delivered")
	}
	if !local.deliver([]byte(`{"type":"response.interrupt","response_id":"r2"}`)) {
		t.Fatal("an interrupt for the response in flight was not delivered")
	}

	// The response completed and a new turn began: an interrupt for the
	// completed response is refused, even though the turn is in flight.
	local.end()
	local.begin()
	local.setResponseID("r3")
	if local.deliver([]byte(`{"type":"response.interrupt","response_id":"r2"}`)) {
		t.Fatal("an interrupt for a completed response was delivered")
	}
	if !local.deliver([]byte(`{"type":"response.interrupt","response_id":"r3"}`)) {
		t.Fatal("an interrupt for the response in flight was not delivered")
	}
}
