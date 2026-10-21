package cliproxy

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// CompatCatalogRefreshInterval is the cadence at which the live model lists of
// OpenAI-compatible providers are re-read. It matches the model catalog refresh
// cadence, so both lists stay in step.
const CompatCatalogRefreshInterval = 3 * time.Hour

// compatCatalogFetcher is the live model list reader. It is replaceable in tests.
type compatCatalogFetcher = config.CompatCatalogFetcher

// compatCatalogState tracks the live model list of one configured provider entry.
//
// The entry is identified by its full target identity, not by its name: two
// entries can share a name, and a reload can change an entry's base URL, so the
// name alone does not identify what a discovered list belongs to.
type compatCatalogState struct {
	// target is the configured entry this list belongs to.
	target compatCatalogTarget
	// models is the last known good live model list.
	models []config.CompatCatalogModel
}

// compatCatalogTarget identifies one configured provider entry.
//
// The identity covers the entry's position, its name, its base URL and its key, so
// a list is only ever applied to the entry it was read for.
type compatCatalogTarget struct {
	// entryIndex is the entry's position in the configuration.
	entryIndex int
	// name is the configured provider name.
	name string
	// baseURL is the configured provider base URL.
	baseURL string
	// apiKey is the provider key used for the live read.
	apiKey string
	// proxyURL is the proxy the credential's own requests use, if any. The live
	// read uses it too, so a provider reachable only through its configured proxy
	// can be discovered.
	proxyURL string
}

// key returns the identity of the target.
func (t compatCatalogTarget) key() string {
	return strings.Join([]string{
		itoa(t.entryIndex),
		t.name,
		t.baseURL,
		t.apiKey,
		t.proxyURL,
	}, "\x00")
}

// itoa renders an int without pulling in strconv for one call.
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	negative := value < 0
	if negative {
		value = -value
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	if negative {
		index--
		digits[index] = '-'
	}
	return string(digits[index:])
}

// compatCatalogManager keeps the live model lists of the configured
// OpenAI-compatible providers.
type compatCatalogManager struct {
	// service owns the running proxy.
	service *Service
	// fetcher reads a provider's live model list.
	fetcher compatCatalogFetcher

	mu sync.Mutex
	// state holds the last known good list per configured entry.
	state map[string]*compatCatalogState
	// inFlight holds the entries whose live read is in progress, so a provider
	// that never answers does not accumulate a request per interval.
	inFlight map[string]struct{}
	// publishMu serializes the publications, so a publication that started before a
	// newer one cannot register a stale list after it.
	publishMu sync.Mutex
}

// newCompatCatalogManager creates a manager for a service.
func newCompatCatalogManager(service *Service) *compatCatalogManager {
	return &compatCatalogManager{
		service: service,
		fetcher: nil,
		state:   make(map[string]*compatCatalogState),
	}
}

// Start begins the background refresh loop. The loop is bounded: a provider that
// cannot be read keeps its last known good list, and the configured list is always
// the floor.
func (m *compatCatalogManager) Start(ctx context.Context) {
	if m == nil || m.service == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(CompatCatalogRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.Refresh(ctx)
			}
		}
	}()
}

// Refresh reads the live model list of every supported provider and publishes the
// merged list.
//
// Every provider is read on its own goroutine, so a provider that never completes
// its response cannot block the others, and a provider that has answered
// publishes its result without waiting for the rest.
//
// At most one read per provider is in flight. A provider whose response never
// completes would otherwise accumulate another request every interval, and an
// older response could land after a newer one and resurrect removed models.
func (m *compatCatalogManager) Refresh(ctx context.Context) {
	if m == nil || m.service == nil {
		return
	}
	m.service.cfgMu.RLock()
	cfg := m.service.cfg
	m.service.cfgMu.RUnlock()
	if cfg == nil {
		return
	}
	targets := compatCatalogTargets(cfg)
	if len(targets) == 0 {
		return
	}

	for _, target := range targets {
		if ctx.Err() != nil {
			return
		}
		if !m.beginRead(target) {
			// A read for this provider is already in flight. The provider keeps
			// its last known good list until that read answers.
			continue
		}
		go func(current compatCatalogTarget) {
			defer m.endRead(current)
			// No deadline is imposed on the upstream request. A provider that
			// establishes its connection promptly but takes a long time to return
			// its catalog must not be cancelled while the response is read: the
			// repository rule is that a timeout may only bound credential
			// acquisition, never the network behavior after a connection is
			// established. The caller's context still cancels the pass.
			m.refreshProvider(ctx, current)
			// Each provider publishes as soon as it has answered, so a provider
			// that never completes its response cannot hold back the results the
			// others returned, and it cannot stop the next pass either.
			if ctx.Err() == nil {
				m.publishLiveModels(ctx)
			}
		}(target)
	}

	// The publication runs on every refresh, not only when the upstream list
	// changed. A file reload replaces the configuration with the provider's
	// static models, so the discovered models have to be reconciled back even
	// when the provider still reports the same list.
	m.publishLiveModels(ctx)
}

// beginRead marks a read for one provider as in flight. It reports whether the
// caller may proceed.
func (m *compatCatalogManager) beginRead(target compatCatalogTarget) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.inFlight == nil {
		m.inFlight = make(map[string]struct{})
	}
	key := target.key()
	if _, ok := m.inFlight[key]; ok {
		return false
	}
	m.inFlight[key] = struct{}{}
	return true
}

// endRead clears the in-flight mark for one provider.
func (m *compatCatalogManager) endRead(target compatCatalogTarget) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.inFlight, target.key())
}

// compatCatalogTargets returns the configured entries whose live model list is
// supported.
func compatCatalogTargets(cfg *config.Config) []compatCatalogTarget {
	if cfg == nil {
		return nil
	}
	targets := make([]compatCatalogTarget, 0, len(cfg.OpenAICompatibility))
	for index := range cfg.OpenAICompatibility {
		provider := &cfg.OpenAICompatibility[index]
		if provider.Disabled {
			continue
		}
		baseURL := strings.TrimSpace(provider.BaseURL)
		if config.CompatCatalogProviderFor(baseURL) == nil {
			continue
		}
		apiKey := ""
		proxyURL := strings.TrimSpace(cfg.ProxyURL)
		for _, entry := range provider.APIKeyEntries {
			if key := strings.TrimSpace(entry.APIKey); key != "" {
				apiKey = key
				if keyProxy := strings.TrimSpace(entry.ProxyURL); keyProxy != "" {
					proxyURL = keyProxy
				}
				break
			}
		}
		targets = append(targets, compatCatalogTarget{
			entryIndex: index,
			name:       strings.TrimSpace(provider.Name),
			baseURL:    baseURL,
			apiKey:     apiKey,
			proxyURL:   proxyURL,
		})
	}
	return targets
}

// refreshProvider reads one provider's live model list and stores it. It reports
// whether the list changed.
func (m *compatCatalogManager) refreshProvider(ctx context.Context, target compatCatalogTarget) bool {
	if target.name == "" {
		return false
	}
	models, errList := config.CompatCatalogModelList(ctx, target.baseURL, target.apiKey, target.proxyURL, m.fetcher)
	if errList != nil {
		// A failed refresh keeps the last known good list.
		log.WithError(errList).Warnf("compat catalog: live model list unavailable for provider %s", target.name)
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous, existed := m.state[target.key()]
	changed := !existed || !compatCatalogModelIDsEqual(previous.models, models)
	m.state[target.key()] = &compatCatalogState{
		target: target,
		models: models,
	}
	return changed
}

// compatCatalogModelIDsEqual reports whether two live model lists carry the same
// model identifiers.
func compatCatalogModelIDsEqual(left, right []config.CompatCatalogModel) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].ID != right[index].ID {
			return false
		}
	}
	return true
}

// liveModelsFor returns the last known good live model list of one configured
// entry.
//
// The entry's full identity is matched, so a list discovered for one entry is
// never applied to another entry that happens to share its name.
func (m *compatCatalogManager) liveModelsFor(target compatCatalogTarget) []config.CompatCatalogModel {
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.state[target.key()]
	if !ok || state == nil {
		return nil
	}
	return state.models
}

// liveModelsForEntry returns the live model list of the entry with the given name,
// base URL and key.
//
// The key is part of the match, so a rotated key does not find the catalog the
// previous key discovered.
// liveModelsForEntry returns the live model list of the configured entry.
//
// The entry's full identity is matched: its position in the configuration, its
// name, its base URL, its key and its proxy. Matching on the name alone would
// let two entries that share a name receive each other's models, and a rotated
// key or a changed proxy would leave the obsolete list in place.
//
// The position is the strongest identifier, so it is matched first. A caller
// that does not know the position falls back to the name, the base URL, the key
// and the proxy, and a negative position never matches a stored one.
func (m *compatCatalogManager) liveModelsForEntry(target compatCatalogTarget) []config.CompatCatalogModel {
	m.mu.Lock()
	defer m.mu.Unlock()
	if target.entryIndex >= 0 {
		state, ok := m.state[target.key()]
		if !ok || state == nil {
			return nil
		}
		return state.models
	}
	for _, state := range m.state {
		if state == nil {
			continue
		}
		if !strings.EqualFold(state.target.name, strings.TrimSpace(target.name)) {
			continue
		}
		if !strings.EqualFold(state.target.baseURL, strings.TrimSpace(target.baseURL)) {
			continue
		}
		if target.apiKey != "" && state.target.apiKey != target.apiKey {
			// The key was rotated, so this catalog belongs to the old key.
			continue
		}
		if target.proxyURL != "" && state.target.proxyURL != target.proxyURL {
			// The proxy was changed, so this catalog was read through the old
			// proxy.
			continue
		}
		return state.models
	}
	return nil
}

// publishLiveModels publishes the live model lists to the model registry.
//
// The configuration is not changed. The discovered models are merged into a copy of
// the provider entry at the model registration boundary, which is where routing
// reads them from, so nothing discovered can be written back to the configuration
// file.
//
// Only the credentials that are currently registered are re-registered. A
// credential that a configuration change removed is not recreated from a
// configuration snapshot.
func (m *compatCatalogManager) publishLiveModels(ctx context.Context) {
	if m == nil || m.service == nil {
		return
	}
	// The publications are serialized, so a publication that started before a
	// newer one cannot register a stale list after it.
	m.publishMu.Lock()
	defer m.publishMu.Unlock()
	m.service.refreshCompatModelRegistration(coreauth.WithSkipPersist(ctx))
}

// modelsFor returns a copy of a provider entry whose model list also carries the
// models its live model list contributed.
//
// The entry is a copy, so the configuration the operator wrote is never changed:
// a discovered row belongs to the runtime, and writing it back would turn it into
// a permanent pin the live list could never take back.
// modelsFor returns a copy of a provider entry whose model list also carries the
// models its live model list contributed.
//
// The entry is a copy, so the configuration the operator wrote is never changed:
// a discovered row belongs to the runtime, and writing it back would turn it into
// a permanent pin the live list could never take back.
//
// The entry's position in the configuration identifies it. The position is
// negative when the caller does not know it, and the lookup then falls back to
// the name, the base URL, the key and the proxy.
func (m *compatCatalogManager) modelsFor(entryIndex int, compat *config.OpenAICompatibility, proxyURL string) *config.OpenAICompatibility {
	if m == nil || compat == nil {
		return compat
	}
	target := compatCatalogTarget{
		entryIndex: entryIndex,
		name:       strings.TrimSpace(compat.Name),
		baseURL:    strings.TrimSpace(compat.BaseURL),
		apiKey:     compatKeyOf(compat),
		proxyURL:   strings.TrimSpace(proxyURL),
	}
	live := m.liveModelsForEntry(target)
	if len(live) == 0 {
		return compat
	}
	copied := *compat
	copied.Models = config.ReconcileCompatCatalogModels(compat.Models, live, compat.ExcludedModels)
	return &copied
}

// compatKeyOf returns the first key of a provider entry, which is the key the live
// model list was read with.
func compatKeyOf(compat *config.OpenAICompatibility) string {
	if compat == nil {
		return ""
	}
	for _, entry := range compat.APIKeyEntries {
		if key := strings.TrimSpace(entry.APIKey); key != "" {
			return key
		}
	}
	return ""
}
