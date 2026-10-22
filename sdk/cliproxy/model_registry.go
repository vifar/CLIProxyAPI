package cliproxy

import (
	"maps"
	"strconv"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/diff"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

// ModelInfo re-exports the registry model info structure.
type ModelInfo = registry.ModelInfo

// ClientModelProjection re-exports the registry model projection structure.
type ClientModelProjection = registry.ClientModelProjection

// ModelRegistryHook re-exports the registry hook interface for external integrations.
type ModelRegistryHook = registry.ModelRegistryHook

// ModelRegistry describes registry operations consumed by external callers.
type ModelRegistry interface {
	RegisterClient(clientID, clientProvider string, models []*ModelInfo)
	RegisterClientIfEpochCurrent(clientID, clientProvider string, expectedEpoch uint64, models []*ModelInfo, publish func() bool) bool
	UnregisterClient(clientID string)
	UnregisterClientIfEpochCurrent(clientID string, expectedEpoch uint64, publish func() bool) bool
	SetModelQuotaExceeded(clientID, modelID string)
	ClearModelQuotaExceeded(clientID, modelID string)
	ApplyClientModelProjections(clientID string, epoch uint64, generation uint64, projections []ClientModelProjection) bool
	ClientSupportsModel(clientID, modelID string) bool
	GetAvailableModels(handlerType string) []map[string]any
	GetAvailableModelsByProvider(provider string) []*ModelInfo
	GetModelsForClient(clientID string) []*ModelInfo
	GetModelsAndEpochForClient(clientID string) ([]*ModelInfo, uint64)
	ClientRegistrationEpoch(clientID string) uint64
	ApplyClientModelCapabilities(clientID string, expectedEpoch uint64, mutate func(modelID string, info *ModelInfo)) bool
}

// GlobalModelRegistry returns the shared registry instance.
func GlobalModelRegistry() ModelRegistry {
	return registry.GetGlobalRegistry()
}

// SetGlobalModelRegistryHook registers an optional hook on the shared global registry instance.
func SetGlobalModelRegistryHook(hook ModelRegistryHook) {
	registry.GetGlobalRegistry().SetHook(hook)
}

// modelRegistrationFence captures the model-registration inputs and the
// global exclusion summaries and registry epoch observed when registration began.
// Publication takes the auth mutation lock, then the config read lock, then the
// registry lock. Obsolete inherited exclusions must not advance the registry epoch
// and invalidate newer work, even if the credential attributes are unchanged.
type modelRegistrationFence struct {
	globalExclusions          map[string]diff.ExcludedModelsSummary
	exclusionProvider         string
	fallbackExclusionProvider string
	// compatExclusions is the compatible provider's own excluded-models list, in
	// the order the configuration holds it.
	//
	// The global OAuth exclusions are not the only exclusion that applies to a
	// compatible provider: it carries its own list. A registration that captured
	// one configuration must not publish under a later one, or an excluded
	// model would be republished.
	compatExclusions string
	// compatAuth is the credential the fence was built for, so the compatible
	// provider's own excluded-models list can be compared against the current
	// configuration.
	compatAuth        *coreauth.Auth
	registryEpoch     uint64
	registrationEpoch uint64
	prefix            string
	provider          string
	disabled          bool
	authKind          string
	attributes        map[string]string
}

func newModelRegistrationFence(a *coreauth.Auth, cfg *config.Config) modelRegistrationFence {
	var exclusions map[string]diff.ExcludedModelsSummary
	if cfg != nil && len(cfg.OAuthExcludedModels) > 0 {
		exclusions = make(map[string]diff.ExcludedModelsSummary, len(cfg.OAuthExcludedModels))
		for provider, rules := range cfg.OAuthExcludedModels {
			exclusions[provider] = diff.SummarizeExcludedModels(rules)
		}
	}
	if a == nil {
		return modelRegistrationFence{globalExclusions: exclusions}
	}
	provider := strings.ToLower(strings.TrimSpace(a.Provider))
	compatExclusions := ""
	if _, _, compat := openAICompatInfoFromAuth(a); compat {
		provider = "openai-compatibility"
		compatExclusions = compatExcludedModelsSummaryForConfig(cfg, a)
	}
	return modelRegistrationFence{
		globalExclusions:  exclusions,
		exclusionProvider: provider,
		compatExclusions:  compatExclusions,
		compatAuth:        a,
		registryEpoch:     GlobalModelRegistry().ClientRegistrationEpoch(a.ID),
		registrationEpoch: a.RegistrationEpoch,
		prefix:            a.Prefix,
		provider:          a.Provider,
		disabled:          a.Disabled || a.Status == coreauth.StatusDisabled,
		authKind:          a.AuthKind(),
		attributes:        maps.Clone(a.Attributes),
	}
}

// withAuth returns a copy of f with the auth-input fields replaced by a's
// current values. Exclusion summaries and the registry epoch intentionally remain
// unchanged so stale work cannot adopt newer global rules or publications.
func (f modelRegistrationFence) withAuth(a *coreauth.Auth) modelRegistrationFence {
	if a == nil {
		return f
	}
	next := newModelRegistrationFence(a, nil)
	next.globalExclusions = f.globalExclusions
	// The compatible provider's own excluded-models list is carried over with the
	// credential. The fence is rebuilt without a configuration here, so the list
	// would be lost, and the publication would then compare an empty list against
	// the current one and never publish.
	next.compatAuth = f.compatAuth
	next.compatExclusions = f.compatExclusions
	next.fallbackExclusionProvider = f.fallbackExclusionProvider
	next.registryEpoch = f.registryEpoch
	return next
}

func (f modelRegistrationFence) publishModels(s *Service, authID, providerKey string, models []*ModelInfo) bool {
	return f.publishIfCurrent(s, authID, func() bool {
		return GlobalModelRegistry().RegisterClientIfEpochCurrent(authID, providerKey, f.registryEpoch, models, func() bool { return true })
	})
}

func (f modelRegistrationFence) publishUnregister(s *Service, authID string) bool {
	return f.publishIfCurrent(s, authID, func() bool {
		return GlobalModelRegistry().UnregisterClientIfEpochCurrent(authID, f.registryEpoch, func() bool { return true })
	})
}

// compatExcludedModelsSummaryForConfig returns the compatible provider's own
// excluded-models list for a configuration.
//
// The list is identified by the provider entry the credential was synthesized
// from, so a reload that moves the credential to another entry is detected.
func compatExcludedModelsSummaryForConfig(cfg *config.Config, a *coreauth.Auth) string {
	if cfg == nil || a == nil {
		return ""
	}
	entry := resolveCompatConfigEntry(cfg, a)
	if entry == nil {
		return ""
	}
	parts := make([]string, 0, len(entry.ExcludedModels))
	for _, item := range entry.ExcludedModels {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			parts = append(parts, strings.ToLower(trimmed))
		}
	}
	return strings.Join(parts, ",")
}

// resolveCompatConfigEntry returns the compatible provider entry a credential
// was synthesized from.
//
// The entry is found by the credential's position in the configuration, and by
// its name when the position is not known. It matches how the registration path
// resolves the entry, so both name the same entry.
func resolveCompatConfigEntry(cfg *config.Config, a *coreauth.Auth) *config.OpenAICompatibility {
	if cfg == nil || a == nil || len(cfg.OpenAICompatibility) == 0 {
		return nil
	}
	// Only a compatible credential names a compatible provider entry. A native
	// credential can carry a configuration index too, and resolving it against
	// the compatible entries would apply one provider's exclusions to it.
	if _, _, ok := openAICompatInfoFromAuth(a); !ok {
		return nil
	}
	if a.AuthSourceKind() == coreauth.AuthSourceConfig && a.Attributes != nil {
		index, errIndex := strconv.Atoi(strings.TrimSpace(a.Attributes[coreauth.AttributeConfigIndex]))
		if errIndex == nil && index >= 0 && index < len(cfg.OpenAICompatibility) {
			entry := &cfg.OpenAICompatibility[index]
			if !entry.Disabled {
				return entry
			}
			return nil
		}
	}
	compatName := strings.TrimSpace(a.Attributes["compat_name"])
	if compatName == "" {
		return nil
	}
	for index := range cfg.OpenAICompatibility {
		entry := &cfg.OpenAICompatibility[index]
		if entry.Disabled {
			continue
		}
		if strings.EqualFold(entry.Name, compatName) {
			return entry
		}
	}
	return nil
}

func (f modelRegistrationFence) publishIfCurrent(s *Service, authID string, publish func() bool) bool {
	publishWithConfig := func() bool {
		if s != nil && !f.disabled {
			s.cfgMu.RLock()
			defer s.cfgMu.RUnlock()
			// The compatible provider carries its own excluded-models list, and it
			// applies to an API-key credential, so this check is not restricted to
			// the credentials the global OAuth exclusions apply to.
			//
			// A registration that captured one configuration must not publish
			// under a later one, or an excluded model would be republished.
			if f.compatAuth != nil && f.compatExclusions != compatExcludedModelsSummaryForConfig(s.cfg, f.compatAuth) {
				return false
			}
			if f.authKind != coreauth.AuthKindAPIKey && strings.TrimSpace(f.attributes["excluded_models"]) == "" {
				// Match the watcher's normalization so no-op and unrelated reloads do not
				// discard work. A real change always schedules a replacement: the watcher
				// redispatches affected auths, and applyConfigRuntime re-registers every
				// auth (which also covers Home mode, where no watcher runs).
				for _, provider := range [2]string{f.exclusionProvider, f.fallbackExclusionProvider} {
					if provider == "" {
						continue
					}
					current := oauthExcludedModelsForConfig(s.cfg, provider, f.authKind)
					if f.globalExclusions[provider] != diff.SummarizeExcludedModels(current) {
						return false
					}
				}
			}
			// Hold cfgMu through registry publication, not just the comparison.
		}
		return publish()
	}
	if s == nil || s.coreManager == nil {
		return publishWithConfig()
	}
	return s.coreManager.PublishIfRegistrationCurrent(authID, f.registrationEpoch, f.prefix, f.provider, f.disabled, f.authKind, f.attributes, publishWithConfig)
}
