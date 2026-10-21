package auth

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// RoutingTransitionEventLimit bounds how many recent routing transition events the
// recorder retains.
const RoutingTransitionEventLimit = 200

// RoutingTransition names a significant routing transition.
type RoutingTransition string

const (
	// RoutingTransitionBindingCreated is emitted when a new session is bound to a
	// provider and credential.
	RoutingTransitionBindingCreated RoutingTransition = "binding_created"
	// RoutingTransitionBindingHit is emitted when an existing session reuses its
	// bound provider and credential.
	RoutingTransitionBindingHit RoutingTransition = "binding_hit"
	// RoutingTransitionCredentialReselected is emitted when the bound credential is
	// unavailable and another credential of the same provider is chosen.
	RoutingTransitionCredentialReselected RoutingTransition = "credential_reselected"
	// RoutingTransitionProviderFailover is emitted when the bound provider has no
	// eligible credential and another provider is chosen.
	RoutingTransitionProviderFailover RoutingTransition = "provider_failover"
	// RoutingTransitionNoEligibleProvider is emitted when a request cannot be
	// routed at all.
	RoutingTransitionNoEligibleProvider RoutingTransition = "no_eligible_provider"
)

// RoutingTransitionEvent describes one routing transition.
//
// It carries the requested model, the provider key, the transition outcome and an
// opaque session identifier. It never carries an API key, a token, or any part of
// the prompt.
type RoutingTransitionEvent struct {
	// Transition names the transition.
	Transition RoutingTransition `json:"transition"`
	// Model is the requested model.
	Model string `json:"model"`
	// Provider is the provider key the request was routed to, when one was chosen.
	Provider string `json:"provider,omitempty"`
	// PreviousProvider is the provider the session was bound to before the
	// transition, when the transition replaced a binding.
	PreviousProvider string `json:"previous_provider,omitempty"`
	// Session is the opaque session identifier, truncated.
	Session string `json:"session,omitempty"`
}

// routingTransitionKey identifies one counter entry. The model and provider are
// bounded by the recorder, so a hostile client cannot grow the map without limit.
type routingTransitionKey struct {
	// transition names the transition.
	transition RoutingTransition
	// model is the requested model.
	model string
	// provider is the provider key.
	provider string
}

// maxRoutingTransitionModels bounds how many distinct models are counted.
const maxRoutingTransitionModels = 256

// maxRoutingTransitionProviders bounds how many distinct providers are counted.
const maxRoutingTransitionProviders = 64

// maxRoutingTransitionKeyLength bounds the length of a counted model or provider
// name, so a hostile client cannot make the key map large.
const maxRoutingTransitionKeyLength = 128

// routingTransitionOverflowName is the bucket a model or provider name beyond the
// cardinality limit is counted under. The aggregate totals stay exact, because
// every overflowed name still increments this bucket.
const routingTransitionOverflowName = "<overflow>"

// RoutingTransitionRecorder records routing transitions and counts them.
//
// The recorder is safe for concurrent use.
//
// The counter map is bounded. A client can vary the spelling of a model it asks
// for, so the distinct model and provider names are capped and the overflow is
// folded into a bounded bucket per transition. The aggregate totals stay exact.
type RoutingTransitionRecorder struct {
	// mu protects counters.
	mu sync.Mutex
	// counters holds the count per transition key.
	counters map[routingTransitionKey]uint64
	// knownModels holds the counted model names, up to the model limit.
	knownModels map[string]struct{}
	// knownProviders holds the counted provider names, up to the provider limit.
	knownProviders map[string]struct{}
	// events holds the most recent events, bounded.
	events []RoutingTransitionEvent
	// maxEvents bounds the retained event list.
	maxEvents int
}

// NewRoutingTransitionRecorder creates a recorder that retains the given number of
// recent events.
func NewRoutingTransitionRecorder(maxEvents int) *RoutingTransitionRecorder {
	if maxEvents <= 0 {
		maxEvents = 100
	}
	return &RoutingTransitionRecorder{
		counters:  make(map[routingTransitionKey]uint64),
		events:    make([]RoutingTransitionEvent, 0, maxEvents),
		maxEvents: maxEvents,
	}
}

// Record records one routing transition and increments its counter.
func (r *RoutingTransitionRecorder) Record(event RoutingTransitionEvent) {
	if r == nil {
		return
	}
	event.Model = truncateRoutingTransitionKey(event.Model)
	event.Provider = truncateRoutingTransitionKey(event.Provider)
	event.PreviousProvider = truncateRoutingTransitionKey(event.PreviousProvider)
	event.Session = truncateSessionID(event.Session)

	r.mu.Lock()
	if r.knownModels == nil {
		r.knownModels = make(map[string]struct{})
	}
	if r.knownProviders == nil {
		r.knownProviders = make(map[string]struct{})
	}
	// The model and provider names are bounded, so a client cannot make the
	// counter map grow without limit by varying the spelling of a model. A name
	// beyond the limit is counted in a bounded overflow bucket, so the aggregate
	// totals stay exact.
	model := r.boundedName(r.knownModels, event.Model, maxRoutingTransitionModels)
	provider := r.boundedName(r.knownProviders, event.Provider, maxRoutingTransitionProviders)

	key := routingTransitionKey{
		transition: event.Transition,
		model:      model,
		provider:   provider,
	}
	r.counters[key]++
	if len(r.events) >= r.maxEvents {
		// Drop the oldest event, keeping the list bounded.
		copy(r.events, r.events[1:])
		r.events = r.events[:len(r.events)-1]
	}
	r.events = append(r.events, event)
	r.mu.Unlock()
}

// boundedName returns the name to count under, folding a name beyond the limit
// into the overflow bucket.
//
// The caller holds the recorder lock.
func (r *RoutingTransitionRecorder) boundedName(known map[string]struct{}, name string, limit int) string {
	if name == "" {
		return ""
	}
	if _, ok := known[name]; ok {
		return name
	}
	if len(known) < limit {
		known[name] = struct{}{}
		return name
	}
	// The name is beyond the limit, so it is counted in the overflow bucket.
	return routingTransitionOverflowName
}

// RoutingTransitionSnapshot is one consistent view of the recorded transitions.
//
// The counters, the totals and the events are read under one lock, so a binding
// that arrives between two reads cannot make the totals disagree with the sum of
// the counters, and the events cannot describe a later state.
type RoutingTransitionSnapshot struct {
	// Counters are the per-transition, model and provider counts.
	Counters []RoutingTransitionCounter
	// Totals are the total count per transition.
	Totals map[string]uint64
	// Events are the most recent events, newest last.
	Events []RoutingTransitionEvent
}

// Snapshot returns one consistent view of the recorded transitions.
func (r *RoutingTransitionRecorder) Snapshot() RoutingTransitionSnapshot {
	if r == nil {
		return RoutingTransitionSnapshot{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	counters := make([]RoutingTransitionCounter, 0, len(r.counters))
	totals := make(map[string]uint64, len(RoutingTransitionValues()))
	for key, count := range r.counters {
		counters = append(counters, RoutingTransitionCounter{
			Transition: string(key.transition),
			Model:      key.model,
			Provider:   key.provider,
			Count:      count,
		})
		totals[string(key.transition)] += count
	}
	sort.Slice(counters, func(i, j int) bool {
		if counters[i].Transition != counters[j].Transition {
			return counters[i].Transition < counters[j].Transition
		}
		if counters[i].Model != counters[j].Model {
			return counters[i].Model < counters[j].Model
		}
		return counters[i].Provider < counters[j].Provider
	})
	events := make([]RoutingTransitionEvent, len(r.events))
	copy(events, r.events)
	return RoutingTransitionSnapshot{Counters: counters, Totals: totals, Events: events}
}

// RoutingTransitionCounters returns the counters as a flat list, sorted for a
// stable presentation.
func (r *RoutingTransitionRecorder) RoutingTransitionCounters() []RoutingTransitionCounter {
	if r == nil {
		return nil
	}
	return r.Snapshot().Counters
}

// RoutingTransitionCounter is one counted routing transition.
type RoutingTransitionCounter struct {
	// Transition names the transition.
	Transition string `json:"transition"`
	// Model is the requested model.
	Model string `json:"model"`
	// Provider is the provider key.
	Provider string `json:"provider"`
	// Count is how many times the transition happened.
	Count uint64 `json:"count"`
}

// RoutingTransitionEvents returns the most recent events, newest last.
func (r *RoutingTransitionRecorder) RoutingTransitionEvents() []RoutingTransitionEvent {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RoutingTransitionEvent, len(r.events))
	copy(out, r.events)
	return out
}

// RoutingTransitionTotals returns the total count per transition.
func (r *RoutingTransitionRecorder) RoutingTransitionTotals() map[string]uint64 {
	if r == nil {
		return nil
	}
	return r.Snapshot().Totals
}

// RoutingTransitionValues returns every known transition.
func RoutingTransitionValues() []RoutingTransition {
	return []RoutingTransition{
		RoutingTransitionBindingCreated,
		RoutingTransitionBindingHit,
		RoutingTransitionCredentialReselected,
		RoutingTransitionProviderFailover,
		RoutingTransitionNoEligibleProvider,
	}
}

// truncateRoutingTransitionKey bounds a counted model or provider name.
func truncateRoutingTransitionKey(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if len(trimmed) > maxRoutingTransitionKeyLength {
		return trimmed[:maxRoutingTransitionKeyLength]
	}
	return trimmed
}

// routingTransitionRecorder is the process-wide recorder. It is set by the
// service so the management API can read it.
var routingTransitionRecorder atomic.Pointer[RoutingTransitionRecorder]

// SetRoutingTransitionRecorder installs the process-wide recorder.
func SetRoutingTransitionRecorder(recorder *RoutingTransitionRecorder) {
	if recorder == nil {
		routingTransitionRecorder.Store(nil)
		return
	}
	routingTransitionRecorder.Store(recorder)
}

// GetRoutingTransitionRecorder returns the process-wide recorder, or nil when none
// is installed.
func GetRoutingTransitionRecorder() *RoutingTransitionRecorder {
	return routingTransitionRecorder.Load()
}

// recordRoutingTransition records one transition on the process-wide recorder.
func recordRoutingTransition(ctx context.Context, event RoutingTransitionEvent) {
	recorder := GetRoutingTransitionRecorder()
	if recorder == nil {
		return
	}
	recorder.Record(event)
}
