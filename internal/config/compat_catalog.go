package config

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
)

// CompatCatalogProvider describes a provider whose live model list the proxy can
// read.
type CompatCatalogProvider struct {
	// ID identifies the provider family.
	ID string
	// Host is the hostname the provider serves its model list on.
	Host string
	// Path is the path of the OpenAI-compatible model list endpoint.
	Path string
	// RequiresKey reports whether the endpoint needs the provider's API key.
	RequiresKey bool
}

// CompatCatalogProviders lists the providers whose live model list is supported.
var CompatCatalogProviders = []CompatCatalogProvider{
	{ID: "ollama-cloud", Host: "ollama.com", Path: "/v1/models", RequiresKey: true},
	{ID: "openrouter", Host: "openrouter.ai", Path: "/api/v1/models", RequiresKey: false},
	{ID: "vercel", Host: "ai-gateway.vercel.sh", Path: "/v1/models", RequiresKey: false},
}

// CompatCatalogProviderFor returns the live catalog provider for a configured base
// URL, or nil when the provider is not supported.
//
// The base URL must be an https URL without userinfo, an explicit port, a query or
// a fragment, so the configured origin cannot be widened.
func CompatCatalogProviderFor(baseURL string) *CompatCatalogProvider {
	trimmed := strings.TrimSpace(baseURL)
	if trimmed == "" {
		return nil
	}
	parsed, errParse := url.Parse(trimmed)
	if errParse != nil {
		return nil
	}
	if parsed.Scheme != "https" || parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil
	}
	host := strings.ToLower(parsed.Hostname())
	for index := range CompatCatalogProviders {
		if CompatCatalogProviders[index].Host == host {
			return &CompatCatalogProviders[index]
		}
	}
	return nil
}

// CompatCatalogModel is one model read from a provider's live model list.
type CompatCatalogModel struct {
	// ID is the upstream model identifier.
	//
	// The live model list is used to publish the identifiers a provider serves.
	// The other fields a provider may report are not decoded: nothing consumes
	// them, and decoding them would imply a contract the discovery does not have.
	ID string
}

// compatCatalogModelsResponse is the OpenAI-compatible model list payload.
type compatCatalogModelsResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
}

// CompatCatalogTransport builds the transport for a live model list request,
// honouring the credential's proxy. A nil transport means the default transport is
// used.
func CompatCatalogTransport(proxyURL string) (*http.Transport, error) {
	trimmed := strings.TrimSpace(proxyURL)
	if trimmed == "" {
		return nil, nil
	}
	transport, _, errBuild := proxyutil.BuildHTTPTransport(trimmed)
	if errBuild != nil {
		return nil, errBuild
	}
	return transport, nil
}

// CompatCatalogFetcher reads a provider's live model list. The proxy URL is the
// one the credential's own requests use, so a provider reachable only through its
// configured proxy can be discovered too.
type CompatCatalogFetcher func(ctx context.Context, endpoint, apiKey, proxyURL string) ([]byte, int, error)

// compatCatalogHTTPFetcher performs the live model list request. Redirects are not
// followed, so a redirect cannot move the key to another origin.
//
// The request carries no whole-request timeout: the repository's rule is that a
// timeout may only bound credential acquisition, never the network behavior after
// a connection is established. The request context still cancels the read.
func compatCatalogHTTPFetcher(ctx context.Context, endpoint, apiKey, proxyURL string) ([]byte, int, error) {
	request, errNew := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if errNew != nil {
		return nil, 0, errNew
	}
	if apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+apiKey)
	}
	request.Header.Set("Accept", "application/json")

	transport, errTransport := CompatCatalogTransport(proxyURL)
	if errTransport != nil {
		return nil, 0, errTransport
	}
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if transport != nil {
		client.Transport = transport
		// The transport belongs to this request, so its idle connections are closed
		// when the request is done.
		defer transport.CloseIdleConnections()
	}
	response, errDo := client.Do(request)
	if errDo != nil {
		return nil, 0, errDo
	}
	defer func() {
		_ = response.Body.Close()
	}()
	body, errRead := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if errRead != nil {
		return nil, response.StatusCode, errRead
	}
	return body, response.StatusCode, nil
}

// CompatCatalogModelList reads the live model list of one provider.
//
// The endpoint is derived from the provider's own configured base URL, so the key
// is only ever sent to the origin it was configured for.
func CompatCatalogModelList(
	ctx context.Context,
	baseURL string,
	apiKey string,
	proxyURL string,
	fetcher CompatCatalogFetcher,
) ([]CompatCatalogModel, error) {
	provider := CompatCatalogProviderFor(baseURL)
	if provider == nil {
		return nil, fmt.Errorf("provider has no supported live model list")
	}
	if fetcher == nil {
		fetcher = compatCatalogHTTPFetcher
	}
	key := strings.TrimSpace(apiKey)
	if provider.RequiresKey && key == "" {
		return nil, fmt.Errorf("provider requires an API key for the live model list")
	}
	endpoint := "https://" + provider.Host + provider.Path
	body, status, errFetch := fetcher(ctx, endpoint, key, proxyURL)
	if errFetch != nil {
		return nil, errFetch
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("live model list request returned status %d", status)
	}
	payload := compatCatalogModelsResponse{}
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		return nil, fmt.Errorf("decode live model list: %w", errDecode)
	}
	models := make([]CompatCatalogModel, 0, len(payload.Data))
	seen := make(map[string]struct{}, len(payload.Data))
	for _, entry := range payload.Data {
		id := strings.TrimSpace(entry.ID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		models = append(models, CompatCatalogModel{ID: id})
	}
	if len(models) == 0 {
		return nil, fmt.Errorf("live model list is empty")
	}
	return models, nil
}

// MergeCompatCatalogModels merges a provider's live model list into its configured
// model list.
//
// A configured model always wins: an explicit pin is never removed. The live list
// only adds models the configuration does not mention, and never a model the
// operator excluded, so a model removed through `excluded-models` does not come back
// from the provider.
//
// The configured rows are kept exactly as written, including several rows that share
// an upstream name under different aliases: those are separate published models and
// deduplicating them would drop a pinned alias. The known names and the operator's
// public aliases are reserved, so a discovered model never takes over a name the
// operator already publishes.
//
// The merge is deterministic: the configured models keep their order, and the added
// live models follow in the order the provider reported them.
func MergeCompatCatalogModels(configured []OpenAICompatibilityModel, live []CompatCatalogModel, excluded []string) []OpenAICompatibilityModel {
	if len(live) == 0 {
		return configured
	}
	merged := make([]OpenAICompatibilityModel, 0, len(configured)+len(live))
	known := make(map[string]struct{}, len(configured))
	// The operator's public aliases are reserved too: a discovered model whose
	// name matches an operator's alias would make requests for that alias
	// round-robin between two different upstreams. The reservation is
	// case-insensitive, because the alias pool resolves aliases that way.
	aliases := make(map[string]struct{}, len(configured))
	for _, model := range configured {
		merged = append(merged, model)
		key := compatCatalogModelKey(model)
		// The alias and its base name are both reserved. The routing lookup
		// tries the base name when the requested model carries a suffix, so an
		// alias of "model-b(high)" also answers a request for "model-b". A
		// discovered model that took that name would make the request round
		// robin between two different upstreams.
		if alias := strings.TrimSpace(model.Alias); alias != "" {
			aliases[strings.ToLower(alias)] = struct{}{}
			if base := compatCatalogStripThinkingSuffix(alias); base != alias {
				aliases[strings.ToLower(base)] = struct{}{}
			}
		}
		if key == "" {
			continue
		}
		if _, ok := known[strings.ToLower(key)]; ok {
			continue
		}
		known[strings.ToLower(key)] = struct{}{}
	}
	for _, candidate := range live {
		id := strings.TrimSpace(candidate.ID)
		if id == "" {
			continue
		}
		if _, ok := known[strings.ToLower(id)]; ok {
			continue
		}
		if _, ok := aliases[strings.ToLower(id)]; ok {
			// The operator already publishes this name as an alias.
			continue
		}
		if CompatCatalogModelExcluded(id, excluded) {
			continue
		}
		known[strings.ToLower(id)] = struct{}{}
		merged = append(merged, OpenAICompatibilityModel{
			Name:  id,
			Alias: id,
		})
	}
	return merged
}

// CompatCatalogModelExcluded reports whether a model ID matches one of the
// provider's exclusion patterns.
//
// A pattern is an exact model ID, a prefix wildcard such as "gemini-2.5-*", a
// suffix wildcard such as "*-preview", or a substring wildcard such as "*flash*".
//
// The model name is matched both as written and with a thinking suffix removed.
// A client may ask for a model with a suffix such as "(high)", and the executor
// strips the suffix before sending the request upstream, so the identity that
// reaches the provider is the name without it. An exclusion written for that
// identity must still match.
func CompatCatalogModelExcluded(modelID string, excluded []string) bool {
	if len(excluded) == 0 {
		return false
	}
	value := strings.ToLower(strings.TrimSpace(modelID))
	if value == "" {
		return false
	}
	// The identity the upstream sees, with a thinking suffix removed.
	upstream := strings.ToLower(strings.TrimSpace(compatCatalogStripThinkingSuffix(value)))
	for _, item := range excluded {
		pattern := strings.ToLower(strings.TrimSpace(item))
		if pattern == "" {
			continue
		}
		if compatCatalogMatchWildcard(pattern, value) {
			return true
		}
		if upstream != value && compatCatalogMatchWildcard(pattern, upstream) {
			return true
		}
	}
	return false
}

// compatCatalogStripThinkingSuffix removes a trailing thinking suffix from a
// model name.
//
// A model name may carry a suffix in parentheses, such as "(high)" or a numeric
// budget, which selects a reasoning effort rather than a different model. The
// suffix is stripped before the request reaches the provider, so the identity
// that reaches the provider is the name without it.
//
// The parsing is the executor's own, so the two cannot disagree about which
// names carry a suffix.
func compatCatalogStripThinkingSuffix(model string) string {
	trimmed := strings.TrimSpace(model)
	if trimmed == "" {
		return ""
	}
	parsed := thinking.ParseSuffix(trimmed)
	if !parsed.HasSuffix {
		return trimmed
	}
	base := strings.TrimSpace(parsed.ModelName)
	if base == "" {
		return trimmed
	}
	return base
}

// compatCatalogMatchWildcard matches a value against a wildcard pattern.
func compatCatalogMatchWildcard(pattern, value string) bool {
	if pattern == "" {
		return false
	}
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}
	parts := strings.Split(pattern, "*")
	if prefix := parts[0]; prefix != "" {
		if !strings.HasPrefix(value, prefix) {
			return false
		}
		value = value[len(prefix):]
	}
	if suffix := parts[len(parts)-1]; suffix != "" {
		if len(value) < len(suffix) {
			return false
		}
		if !strings.HasSuffix(value, suffix) {
			return false
		}
		value = value[:len(value)-len(suffix)]
	}
	for _, middle := range parts[1 : len(parts)-1] {
		if middle == "" {
			continue
		}
		index := strings.Index(value, middle)
		if index < 0 {
			return false
		}
		value = value[index+len(middle):]
	}
	return true
}

// compatCatalogModelKey returns the identity of a configured model.
func compatCatalogModelKey(model OpenAICompatibilityModel) string {
	if name := strings.TrimSpace(model.Name); name != "" {
		return name
	}
	return strings.TrimSpace(model.Alias)
}
