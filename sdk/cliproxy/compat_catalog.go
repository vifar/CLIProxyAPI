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

// compatCatalogRefreshTimeout bounds one refresh pass, so a slow provider cannot
// hold the refresh loop. It is a budget for the whole pass, not a deadline
// imposed on the upstream request.
const compatCatalogRefreshTimeout = 60 * time.Second

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
	// fetchedAt is when the list was last read.
	fetchedAt time.Time
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
	// operatorModels holds the models the operator configured for each entry, so the
	// live list is always merged onto the operator's own rows.
	//
	// The augmented configuration is a runtime artifact: a file reload replaces it
	// with the operator's static rows, and a supported configuration write could
	// save it back to the file. Keeping the operator's rows here means a discovered
	// model can never become a permanent pin.
	operatorModels map[int][]config.OpenAICompatibilityModel
}

// newCompatCatalogManager creates a manager for a service.
func newCompatCatalogManager(service *Service) *compatCatalogManager {
	return &compatCatalogManager{
		service:        service,
		fetcher:        nil,
		state:          make(map[string]*compatCatalogState),
		operatorModels: make(map[int][]config.OpenAICompatibilityModel),
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
// The publication goes through the service's own configuration commit boundary, so
// a file reload that commits meanwhile is never overwritten by a stale snapshot.
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
	for _, target := range compatCatalogTargets(cfg) {
		if ctx.Err() != nil {
			return
		}
		// No deadline is imposed on the upstream request. A provider that
		// establishes its connection promptly but takes a long time to return its
		// catalog must not be cancelled while the response is read: the repository
		// rule is that a timeout may only bound credential acquisition, never the
		// network behavior after a connection is established. The caller's context
		// still cancels the pass.
		m.refreshProvider(ctx, target)
	}
	// The publication runs on every refresh, not only when the upstream list
	// changed. A file reload replaces the augmented configuration with the
	// provider's static models, so the discovered models have to be reconciled
	// back even when the provider still reports the same list.
	m.publishLiveModels(ctx)
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
		target:    target,
		models:    models,
		fetchedAt: time.Now(),
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

// publishLiveModels applies the live model lists to the running configuration and
// re-registers the affected credentials, so the added models are published to the
// model registry and become routable.
//
// The configured list is always the floor: a live list only adds models the
// configuration does not mention, and it never removes a configured model.
//
// The publication is guarded by the configuration sequence the merge was computed
// against. A file reload that committed meanwhile is therefore never overwritten by
// a stale snapshot, and the reload's own models stand.
func (m *compatCatalogManager) publishLiveModels(ctx context.Context) {
	if m == nil || m.service == nil {
		return
	}
	// The configuration and its sequence are read together, under the same lock
	// the commits use, so the snapshot and the sequence always describe the same
	// configuration.
	current, sequence := m.service.configSnapshot()
	if current == nil {
		return
	}

	targets := compatCatalogTargets(current)
	merged := current.CloneForRuntime()
	if merged == nil {
		return
	}
	changed := false
	for index := range merged.OpenAICompatibility {
		provider := &merged.OpenAICompatibility[index]
		target := compatCatalogTarget{
			entryIndex: index,
			name:       strings.TrimSpace(provider.Name),
			baseURL:    strings.TrimSpace(provider.BaseURL),
		}
		for _, candidate := range targets {
			if candidate.entryIndex == index {
				target = candidate
				break
			}
		}
		live := m.liveModelsFor(target)
		if len(live) == 0 {
			continue
		}
		// The operator's own rows are the ones the configuration held when this
		// entry was first seen. The live list is merged onto them, so a model the
		// provider stopped listing is dropped, and a discovered row can never
		// become a permanent pin.
		operatorRows := m.operatorRowsFor(index, provider.Models)
		updated := config.ReconcileCompatCatalogModels(operatorRows, live, provider.ExcludedModels)
		if compatCatalogModelsEqual(provider.Models, updated) {
			continue
		}
		provider.Models = updated
		changed = true
	}
	if !changed {
		return
	}

	// The merge is committed only while the configuration it was computed against
	// is still the current one. The check and the write happen under the same
	// lock, so a reload that committed in the meantime is never overwritten by a
	// stale snapshot, and the reload's own models stand.
	commit := m.service.commitConfigUpdateIfCurrent(merged, sequence)
	if commit.cfg == nil {
		return
	}

	// The runtime application re-registers the affected credentials, so the added
	// models are published to the model registry and become routable.
	m.service.applyConfigRuntime(coreauth.WithSkipPersist(ctx), commit, true)
}

// mergeInto merges the cached live model lists into a configuration.
//
// The operator's own rows are the ones the catalog manager recorded, so the merge
// never treats a discovered model as a configured one. A configuration that
// already carries the discovered rows is unchanged, so the merge is idempotent.
func (m *compatCatalogManager) mergeInto(cfg *config.Config) *config.Config {
	if m == nil || cfg == nil {
		return cfg
	}
	targets := compatCatalogTargets(cfg)
	merged := cfg.CloneForRuntime()
	if merged == nil {
		return cfg
	}
	for index := range merged.OpenAICompatibility {
		provider := &merged.OpenAICompatibility[index]
		target := compatCatalogTarget{
			entryIndex: index,
			name:       strings.TrimSpace(provider.Name),
			baseURL:    strings.TrimSpace(provider.BaseURL),
		}
		for _, candidate := range targets {
			if candidate.entryIndex == index {
				target = candidate
				break
			}
		}
		live := m.liveModelsFor(target)
		if len(live) == 0 {
			continue
		}
		operatorRows := m.operatorRowsFor(index, provider.Models)
		provider.Models = config.ReconcileCompatCatalogModels(operatorRows, live, provider.ExcludedModels)
	}
	return merged
}

// compatCatalogModelsEqual reports whether two configured model lists are the same.
func compatCatalogModelsEqual(left, right []config.OpenAICompatibilityModel) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Name != right[index].Name || left[index].Alias != right[index].Alias {
			return false
		}
	}
	return true
}

// operatorRowsFor returns the models the operator configured for one entry.
//
// The rows are recorded the first time the entry is seen. A later configuration
// that already carries discovered models does not replace them, so the operator's
// own rows stay distinguishable from the live list's contribution.
func (m *compatCatalogManager) operatorRowsFor(entryIndex int, current []config.OpenAICompatibilityModel) []config.OpenAICompatibilityModel {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.operatorModels == nil {
		m.operatorModels = make(map[int][]config.OpenAICompatibilityModel)
	}
	recorded, ok := m.operatorModels[entryIndex]
	if !ok {
		recorded = append([]config.OpenAICompatibilityModel(nil), current...)
		m.operatorModels[entryIndex] = recorded
	}
	return recorded
}
