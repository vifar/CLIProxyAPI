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
// hold the refresh loop.
const compatCatalogRefreshTimeout = 60 * time.Second

// compatCatalogFetcher is the live model list reader. It is replaceable in tests.
type compatCatalogFetcher = config.CompatCatalogFetcher

// compatCatalogState tracks the live model list of one provider.
type compatCatalogState struct {
	// providerName is the configured provider name.
	providerName string
	// baseURL is the configured provider base URL.
	baseURL string
	// apiKey is the provider key used for the live read.
	apiKey string
	// models is the last known good live model list.
	models []config.CompatCatalogModel
	// fetchedAt is when the list was last read.
	fetchedAt time.Time
}

// compatCatalogManager keeps the live model lists of the configured
// OpenAI-compatible providers.
type compatCatalogManager struct {
	// service owns the running proxy.
	service *Service
	// fetcher reads a provider's live model list.
	fetcher compatCatalogFetcher

	mu    sync.Mutex
	state map[string]*compatCatalogState
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
// used as the floor.
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

// Refresh reads the live model list of every supported provider and applies the
// merged list. It never blocks the caller for longer than one provider's timeout
// per provider, and a failure leaves the previous list in place.
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
	changed := false
	for _, provider := range compatCatalogProviders(cfg) {
		if ctx.Err() != nil {
			return
		}
		refreshCtx, cancel := context.WithTimeout(ctx, compatCatalogRefreshTimeout)
		if m.refreshProvider(refreshCtx, provider) {
			changed = true
		}
		cancel()
	}
	if changed {
		m.applyLiveModels(ctx)
	}
}

// applyLiveModels merges the live model lists into the running configuration and
// re-registers the affected credentials, so the new models become routable without
// a restart.
//
// The configured list is always the floor: a live list only adds models the
// configuration does not mention, and it never removes a configured model.
func (m *compatCatalogManager) applyLiveModels(ctx context.Context) {
	if m == nil || m.service == nil {
		return
	}
	m.service.cfgMu.RLock()
	current := m.service.cfg
	m.service.cfgMu.RUnlock()
	if current == nil {
		return
	}

	merged := current.CloneForRuntime()
	if merged == nil {
		return
	}
	changed := false
	for index := range merged.OpenAICompatibility {
		provider := &merged.OpenAICompatibility[index]
		live := m.LiveModels(strings.TrimSpace(provider.Name))
		if len(live) == 0 {
			continue
		}
		updated := config.MergeCompatCatalogModels(provider.Models, live, provider.ExcludedModels)
		if len(updated) == len(provider.Models) {
			continue
		}
		provider.Models = updated
		changed = true
	}
	if !changed {
		return
	}

	m.service.cfgMu.Lock()
	m.service.cfg = merged
	m.service.cfgMu.Unlock()

	// Re-register the credentials so the added models are published to the model
	// registry and become routable.
	registrationCtx := coreauth.WithSkipPersist(ctx)
	m.service.registerConfigAPIKeyAuths(registrationCtx, merged)
}

// compatCatalogProviderTarget is one provider the refresh reads.
type compatCatalogProviderTarget struct {
	// name is the configured provider name.
	name string
	// baseURL is the configured provider base URL.
	baseURL string
	// apiKey is the provider key used for the live read.
	apiKey string
}

// compatCatalogProviders returns the providers whose live model list is supported.
func compatCatalogProviders(cfg *config.Config) []compatCatalogProviderTarget {
	if cfg == nil {
		return nil
	}
	targets := make([]compatCatalogProviderTarget, 0, len(cfg.OpenAICompatibility))
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
		for _, entry := range provider.APIKeyEntries {
			if key := strings.TrimSpace(entry.APIKey); key != "" {
				apiKey = key
				break
			}
		}
		targets = append(targets, compatCatalogProviderTarget{
			name:    strings.TrimSpace(provider.Name),
			baseURL: baseURL,
			apiKey:  apiKey,
		})
	}
	return targets
}

// refreshProvider reads one provider's live model list and stores it. It reports
// whether the list changed.
func (m *compatCatalogManager) refreshProvider(ctx context.Context, target compatCatalogProviderTarget) bool {
	if target.name == "" {
		return false
	}
	models, errList := config.CompatCatalogModelList(ctx, target.baseURL, target.apiKey, m.fetcher)
	if errList != nil {
		// A failed refresh keeps the last known good list.
		log.WithError(errList).Warnf("compat catalog: live model list unavailable for provider %s", target.name)
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	previous, existed := m.state[target.name]
	changed := !existed || !compatCatalogModelIDsEqual(previous.models, models)
	m.state[target.name] = &compatCatalogState{
		providerName: target.name,
		baseURL:      target.baseURL,
		apiKey:       target.apiKey,
		models:       models,
		fetchedAt:    time.Now(),
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

// LiveModels returns the last known good live model list of one provider.
func (m *compatCatalogManager) LiveModels(providerName string) []config.CompatCatalogModel {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	state, ok := m.state[providerName]
	if !ok || state == nil {
		return nil
	}
	return state.models
}
