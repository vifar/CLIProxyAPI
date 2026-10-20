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

// RoutingTransitionRecorder records routing transitions and counts them.
//
// The recorder is safe for concurrent use.
type RoutingTransitionRecorder struct {
	// mu protects counters.
	mu sync.Mutex
	// counters holds the count per transition key.
	counters map[routingTransitionKey]uint64
	// events holds the most recent events, bounded.
	events []RoutingTransitionEvent
	// maxEvents bounds the retained event list.
	maxEvents int
	// listeners receive each event as it is recorded.
	listeners []func(RoutingTransitionEvent)
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

// AddListener registers a listener that receives every recorded event.
//
// A listener must not block: it runs on the routing path.
func (r *RoutingTransitionRecorder) AddListener(listener func(RoutingTransitionEvent)) {
	if r == nil || listener == nil {
		return
	}
	r.mu.Lock()
	r.listeners = append(r.listeners, listener)
	r.mu.Unlock()
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
	key := routingTransitionKey{
		transition: event.Transition,
		model:      event.Model,
		provider:   event.Provider,
	}
	r.counters[key]++
	if len(r.events) >= r.maxEvents {
		// Drop the oldest event, keeping the list bounded.
		copy(r.events, r.events[1:])
		r.events = r.events[:len(r.events)-1]
	}
	r.events = append(r.events, event)
	listeners := make([]func(RoutingTransitionEvent), len(r.listeners))
	copy(listeners, r.listeners)
	r.mu.Unlock()

	for _, listener := range listeners {
		listener(event)
	}
}

// RoutingTransitionCounters returns the counters as a flat list, sorted for a
// stable presentation.
func (r *RoutingTransitionRecorder) RoutingTransitionCounters() []RoutingTransitionCounter {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RoutingTransitionCounter, 0, len(r.counters))
	for key, count := range r.counters {
		out = append(out, RoutingTransitionCounter{
			Transition: string(key.transition),
			Model:      key.model,
			Provider:   key.provider,
			Count:      count,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Transition != out[j].Transition {
			return out[i].Transition < out[j].Transition
		}
		if out[i].Model != out[j].Model {
			return out[i].Model < out[j].Model
		}
		return out[i].Provider < out[j].Provider
	})
	return out
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
	r.mu.Lock()
	defer r.mu.Unlock()
	totals := make(map[string]uint64, len(RoutingTransitionValues()))
	for key, count := range r.counters {
		totals[string(key.transition)] += count
	}
	return totals
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
