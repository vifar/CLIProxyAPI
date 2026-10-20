package auth

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// ProviderEqualSelector selects a credential on a mixed-provider route so that the
// eligible providers share the traffic equally.
//
// The plain round-robin selector flattens every eligible credential into one ring
// ordered by credential ID, so a provider's share of the traffic scales with the
// number of credentials it owns. This selector instead picks the provider first
// and then a credential inside that provider, so two providers with different
// credential counts receive the same share.
//
// The provider ring is scoped by the canonical model and the canonical eligible
// provider set, so provider rotation for one model never advances another model's
// cursor, and two provider sets that differ only in order share one scope.
type ProviderEqualSelector struct {
	mu sync.Mutex
	// providerCursors holds the next provider slot per cursor scope.
	providerCursors map[string]int
	// credentialCursors holds the last credential picked per provider and model.
	credentialCursors map[string]string
}

// NewProviderEqualSelector creates a provider-equal selector.
func NewProviderEqualSelector() *ProviderEqualSelector {
	return &ProviderEqualSelector{
		providerCursors:   make(map[string]int),
		credentialCursors: make(map[string]string),
	}
}

// Pick selects the next credential for a mixed-provider route.
//
// The provider argument is the route's namespace, for example the literal "mixed".
// The eligible providers are derived from the candidates themselves, so the
// selection follows the same provider set the caller resolved.
func (s *ProviderEqualSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	if len(available) == 0 {
		return nil, nil
	}

	// Group the candidates by provider, keeping each group's credentials in a
	// stable order.
	byProvider := make(map[string][]*Auth)
	for _, auth := range available {
		if auth == nil {
			continue
		}
		providerKey := executorKeyFromAuth(auth)
		if providerKey == "" {
			continue
		}
		byProvider[providerKey] = append(byProvider[providerKey], auth)
	}
	if len(byProvider) == 0 {
		// Preserve availability when candidates have no resolvable provider identity.
		return pickRoundRobinByID(available), nil
	}

	providerKeys := make([]string, 0, len(byProvider))
	for providerKey := range byProvider {
		providerKeys = append(providerKeys, providerKey)
	}
	sort.Strings(providerKeys)

	modelKey := canonicalModelKey(model)
	cursorKey := provider + "|" + strings.Join(providerKeys, ",") + "|" + modelKey

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.providerCursors == nil {
		s.providerCursors = make(map[string]int)
	}
	if s.credentialCursors == nil {
		s.credentialCursors = make(map[string]string)
	}

	start := s.providerCursors[cursorKey] % len(providerKeys)
	if start < 0 {
		start = 0
	}
	for offset := 0; offset < len(providerKeys); offset++ {
		providerKey := providerKeys[(start+offset)%len(providerKeys)]
		group := byProvider[providerKey]
		sort.Slice(group, func(i, j int) bool { return group[i].ID < group[j].ID })
		credentialKey := providerKey + "|" + modelKey
		last := s.credentialCursors[credentialKey]
		picked := group[successorIndex(group, last)]
		if picked == nil {
			continue
		}
		s.credentialCursors[credentialKey] = picked.ID
		s.providerCursors[cursorKey] = start + offset + 1
		return picked, nil
	}
	return nil, nil
}

func pickRoundRobinByID(available []*Auth) *Auth {
	if len(available) == 0 {
		return nil
	}
	return available[0]
}

// newMixedSelectorFor builds the selector a mixed-provider route uses.
//
// A mixed route must balance the eligible providers equally, so the built-in
// round-robin selector is replaced by the provider-equal one.
//
// Only the round-robin family is replaced. fill-first and weighted round robin
// keep their own semantics: replacing a weighted fallback would also bypass the
// session-affinity selector's positive-weight filtering, and replacing a
// fill-first fallback would switch it from credential ordering to provider
// ordering.
//
// The result is built once and kept for the lifetime of the configured selector.
// Building it per request would reset the provider cursor every time, and the
// providers would never alternate.
func newMixedSelectorFor(selector Selector) Selector {
	switch typed := selector.(type) {
	case *SessionAffinitySelector:
		return typed.withProviderEqualFallback()
	case *RoundRobinSelector:
		return NewProviderEqualSelector()
	default:
		return selector
	}
}
