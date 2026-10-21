package management

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
)

// compatUsageMeter is a provider-reported usage window for one credential.
type compatUsageMeter struct {
	// ID identifies the window, for example "session", "weekly", "monthly" or
	// "key_budget".
	ID string `json:"id"`
	// UsedPercent is the share of the window already consumed, from 0 to 100.
	UsedPercent float64 `json:"used_percent"`
	// RemainingPercent is the share of the window still available, from 0 to 100.
	RemainingPercent float64 `json:"remaining_percent"`
	// ResetAt is the upstream reported reset time in RFC 3339, when the provider
	// reports one.
	ResetAt string `json:"reset_at,omitempty"`
}

// compatUsageBalance is a provider-reported monetary balance for one credential.
type compatUsageBalance struct {
	// ID identifies the balance, for example "key_remaining" or "key_spent".
	ID string `json:"id"`
	// Amount is the balance value.
	Amount float64 `json:"amount"`
	// Currency is the currency code for the normalized amount.
	Currency string `json:"currency"`
}

// compatUsageCredential identifies one OpenAI-compatible credential without
// exposing its key.
type compatUsageCredential struct {
	// ID is an opaque identifier derived from the credential. It does not encode
	// the API key.
	ID string `json:"id"`
	// ProviderName is the configured provider name.
	ProviderName string `json:"provider_name"`
	// KeyNumber is the 1-based position of the key inside its provider entry.
	KeyNumber int `json:"key_number"`
	// Enabled reports whether the credential is active.
	Enabled bool `json:"enabled"`
	// Supported reports whether a balance API exists for this provider.
	Supported bool `json:"supported"`
	// Scope is the granularity the provider reports, "account" or "key".
	Scope string `json:"scope"`
}

// compatUsageResponse is the meter report for one credential.
type compatUsageResponse struct {
	Credential compatUsageCredential `json:"credential"`
	// Status is one of "success", "unavailable", "disabled" or
	// "error".
	Status string `json:"status"`
	// HTTPStatus is the upstream status code when the upstream answered with an
	// error.
	HTTPStatus int `json:"http_status,omitempty"`
	// Windows are the provider-reported usage windows.
	Windows []compatUsageMeter `json:"windows"`
	// Balances are the provider-reported monetary balances.
	Balances []compatUsageBalance `json:"balances"`
	// FetchedAt is the RFC 3339 time the meter was read.
	FetchedAt string `json:"fetched_at,omitempty"`
}

// compatUsageAdapter describes how to read the balance of one provider.
type compatUsageAdapter struct {
	// ID identifies the provider family.
	ID string
	// Endpoint is the fixed balance endpoint.
	Endpoint string
	// Scope is the granularity the provider reports.
	Scope string
}

// compatUsageAdapters lists the supported balance APIs. The endpoint is chosen
// from the *host* of the configured base URL, so a key can never be sent to a
// different origin than the one it was configured for.
//
// Ollama Cloud's balance endpoint is /api/balance: /api/usage reports usage
// totals and buckets, not the remaining allowance. See
// https://docs.ollama.com/api/balance.
var compatUsageAdapters = []compatUsageAdapter{
	{ID: "ollama", Endpoint: "https://ollama.com/api/balance", Scope: "account"},
	{ID: "openrouter", Endpoint: "https://openrouter.ai/api/v1/key", Scope: "key"},
}

// compatUsageAdapterFor returns the balance adapter for a configured base URL, or
// nil when the provider exposes no supported balance API.
//
// The base URL must be an https URL without userinfo, an explicit port, a query or
// a fragment, so that the configured origin cannot be widened.
func compatUsageAdapterFor(baseURL string) *compatUsageAdapter {
	trimmed := strings.TrimSpace(baseURL)
	if trimmed == "" {
		return nil
	}
	parsed, errParse := url.Parse(trimmed)
	if errParse != nil {
		return nil
	}
	// Port() and RawQuery alone miss an explicit empty port (host:) and an
	// empty query (path?). Reject those delimiters as well.
	if parsed.Scheme != "https" || parsed.User != nil || strings.Contains(parsed.Host, ":") || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return nil
	}
	host := strings.ToLower(parsed.Hostname())
	path := strings.TrimRight(parsed.Path, "/")
	switch host {
	case "ollama.com":
		if path == "" || path == "/v1" {
			return &compatUsageAdapters[0]
		}
	case "openrouter.ai":
		if path == "" || path == "/api" || path == "/api/v1" {
			return &compatUsageAdapters[1]
		}
	}
	return nil
}

// compatUsageIdentitySecret separates the opaque credential identifier from the key
// material. It is generated per process and never leaves it.
var compatUsageIdentitySecret = func() []byte {
	secret := make([]byte, 32)
	if _, errRead := rand.Read(secret); errRead != nil {
		// A fixed fallback still keeps the identifier opaque, because it cannot be
		// reversed to the key without the key itself.
		return []byte("cliproxyapi-compat-usage-identity-v1")
	}
	return secret
}()

// compatUsageCredentialKey carries the key of one credential together with the
// provider it belongs to.
type compatUsageCredentialKey struct {
	// ID is the opaque credential identifier.
	ID string
	// ProviderName is the configured provider name.
	ProviderName string
	// BaseURL is the configured provider base URL.
	BaseURL string
	// KeyNumber is the 1-based position of the key inside its provider entry.
	KeyNumber int
	// Key is sent only to the selected provider endpoint, never in management responses.
	Key string
	// ProxyURL is the proxy the credential's own requests use, if any. The meter
	// request uses it too, so a provider reachable only through its proxy reports
	// a meter.
	ProxyURL string
	// Enabled reports whether the credential is active.
	Enabled bool
	// Adapter is the balance adapter for the provider, nil when unsupported.
	Adapter *compatUsageAdapter
}

// compatUsageListCredentials lists the OpenAI-compatible credentials in the running
// configuration, with an opaque identifier per credential.
func compatUsageListCredentials(cfg *config.Config) []compatUsageCredential {
	out := make([]compatUsageCredential, 0)
	for _, credential := range compatUsageResolveCredentials(cfg) {
		out = append(out, compatUsageCredential{
			ID:           credential.ID,
			ProviderName: credential.ProviderName,
			KeyNumber:    credential.KeyNumber,
			Enabled:      credential.Enabled,
			Supported:    credential.Adapter != nil,
			Scope:        compatUsageScope(credential.Adapter),
		})
	}
	return out
}

// compatUsageScope reports the granularity a provider reports, defaulting to
// "account" for a provider without a balance API.
func compatUsageScope(adapter *compatUsageAdapter) string {
	if adapter == nil {
		return "account"
	}
	return adapter.Scope
}

// compatUsageResolveCredentials resolves the OpenAI-compatible credentials from the
// configuration, in configuration order.
func compatUsageResolveCredentials(cfg *config.Config) []compatUsageCredentialKey {
	if cfg == nil {
		return nil
	}
	out := make([]compatUsageCredentialKey, 0)
	for index := range cfg.OpenAICompatibility {
		provider := &cfg.OpenAICompatibility[index]
		providerName := strings.TrimSpace(provider.Name)
		baseURL := strings.TrimSpace(provider.BaseURL)
		adapter := compatUsageAdapterFor(baseURL)
		providerProxy := strings.TrimSpace(cfg.ProxyURL)
		for keyIndex, entry := range provider.APIKeyEntries {
			key := strings.TrimSpace(entry.APIKey)
			if key == "" {
				continue
			}
			// A per-key proxy overrides the global one, the same way the
			// credential's own requests resolve it.
			proxyURL := strings.TrimSpace(entry.ProxyURL)
			if proxyURL == "" {
				proxyURL = providerProxy
			}
			out = append(out, compatUsageCredentialKey{
				ID:           compatUsageOpaqueID(providerName, baseURL, index, keyIndex, key),
				ProviderName: providerName,
				BaseURL:      baseURL,
				KeyNumber:    keyIndex + 1,
				Key:          key,
				ProxyURL:     proxyURL,
				Enabled:      !provider.Disabled,
				Adapter:      adapter,
			})
		}
	}
	return out
}

// compatUsageOpaqueID mixes the key into a process-secret HMAC so identifiers do
// not expose key material. Key rotation changes the identifier and prevents reuse
// of a cached report for the old key.
//
// The provider entry's position in the configuration is part of the identity, so
// two entries that share a name, a base URL and a key still get distinct
// identifiers. Without it, a lookup could resolve to the wrong entry.
func compatUsageOpaqueID(providerName, baseURL string, entryIndex, keyIndex int, key string) string {
	mac := hmac.New(sha256.New, compatUsageIdentitySecret)
	_, _ = mac.Write([]byte(providerName))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(baseURL))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(strconv.Itoa(entryIndex)))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(strconv.Itoa(keyIndex)))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(key))
	return hex.EncodeToString(mac.Sum(nil))
}

// compatUsageNumber reads a non-negative number from a JSON value.
func compatUsageNumber(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		if typed < 0 || math.IsNaN(typed) || math.IsInf(typed, 0) {
			return 0, false
		}
		return typed, true
	case json.Number:
		parsed, errParse := typed.Float64()
		if errParse != nil || parsed < 0 || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return 0, false
		}
		return parsed, true
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return 0, false
		}
		parsed, errParse := strconv.ParseFloat(trimmed, 64)
		if errParse != nil || parsed < 0 || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

// compatUsageParseWindows extracts the usage windows a provider reports.
func compatUsageParseWindows(adapterID string, payload map[string]any) []compatUsageMeter {
	windows := make([]compatUsageMeter, 0)
	switch adapterID {
	case "ollama":
		// Ollama Cloud's balance response has two shapes. A modern plan reports
		// the included balance and allowance for the period; a legacy plan reports
		// the session and weekly limits with the percentage remaining.
		included, ok := payload["included"].(map[string]any)
		if !ok {
			return windows
		}
		for _, period := range []string{"session", "weekly", "monthly"} {
			entry, okEntry := included[period].(map[string]any)
			if !okEntry {
				continue
			}
			remaining, okRemaining := compatUsageNumber(entry["remaining_percent"])
			if !okRemaining {
				continue
			}
			resetAt := ""
			if raw, okRaw := entry["resets_at"].(string); okRaw {
				if parsed, errParse := time.Parse(time.RFC3339, strings.TrimSpace(raw)); errParse == nil {
					resetAt = parsed.UTC().Format(time.RFC3339)
				}
			}
			remainingPercent := math.Min(100, math.Max(0, remaining))
			windows = append(windows, compatUsageMeter{
				ID:               period,
				UsedPercent:      100 - remainingPercent,
				RemainingPercent: remainingPercent,
				ResetAt:          resetAt,
			})
		}
		if len(windows) == 0 {
			// A modern plan reports the included balance against the allowance for
			// the period, which is a remaining percentage too.
			balance, hasBalance := compatUsageNumber(included["balance_usd"])
			allowance, hasAllowance := compatUsageNumber(included["allowance_usd"])
			if hasBalance && hasAllowance && allowance > 0 {
				remainingPercent := math.Min(100, math.Max(0, (balance/allowance)*100))
				resetAt := ""
				if period, okPeriod := included["period"].(map[string]any); okPeriod {
					if raw, okRaw := period["until"].(string); okRaw {
						if parsed, errParse := time.Parse(time.RFC3339, strings.TrimSpace(raw)); errParse == nil {
							resetAt = parsed.UTC().Format(time.RFC3339)
						}
					}
				}
				windows = append(windows, compatUsageMeter{
					ID:               "included",
					UsedPercent:      100 - remainingPercent,
					RemainingPercent: remainingPercent,
					ResetAt:          resetAt,
				})
			}
		}
	case "openrouter":
		data, ok := payload["data"].(map[string]any)
		if !ok {
			return windows
		}
		limit, hasLimit := compatUsageNumber(data["limit"])
		remaining, hasRemaining := compatUsageNumber(data["limit_remaining"])
		if hasLimit && limit > 0 && hasRemaining {
			remainingPercent := math.Min(100, (remaining/limit)*100)
			windows = append(windows, compatUsageMeter{
				ID:               "key_budget",
				UsedPercent:      100 - remainingPercent,
				RemainingPercent: remainingPercent,
			})
		}
	}
	return windows
}

// compatUsageParseBalances extracts the monetary balances a provider reports.
func compatUsageParseBalances(adapterID string, payload map[string]any) []compatUsageBalance {
	balances := make([]compatUsageBalance, 0)
	switch adapterID {
	case "ollama":
		// The purchased balance is the unexpired purchased credits. The included
		// balance can also yield a window when the period's allowance is known.
		if purchased, ok := payload["purchased"].(map[string]any); ok {
			if amount, okAmount := compatUsageNumber(purchased["balance_usd"]); okAmount {
				balances = append(balances, compatUsageBalance{ID: "purchased_remaining", Amount: amount, Currency: "USD"})
			}
		}
		if included, ok := payload["included"].(map[string]any); ok {
			if amount, okAmount := compatUsageNumber(included["balance_usd"]); okAmount {
				balances = append(balances, compatUsageBalance{ID: "included_remaining", Amount: amount, Currency: "USD"})
			}
		}
	case "openrouter":
		data, ok := payload["data"].(map[string]any)
		if !ok {
			return balances
		}
		if remaining, okRemaining := compatUsageNumber(data["limit_remaining"]); okRemaining {
			balances = append(balances, compatUsageBalance{ID: "key_remaining", Amount: remaining, Currency: "USD"})
		}
		if spent, okSpent := compatUsageNumber(data["usage"]); okSpent {
			balances = append(balances, compatUsageBalance{ID: "key_spent", Amount: spent, Currency: "USD"})
		}
	}
	return balances
}

// compatUsageReader reads provider usage meters with a short per-credential cache.
type compatUsageReader struct {
	// fetcher performs the upstream request. It is replaceable in tests.
	fetcher func(ctx context.Context, endpoint, key, proxyURL string) ([]byte, int, error)
	// now returns the current time.
	now func() time.Time
	// ttl is the cache lifetime of one credential's meter.
	ttl time.Duration

	mu      sync.Mutex
	cache   map[string]compatUsageCacheEntry
	pending map[string]*compatUsagePending
	// onPending is called when a read parks on an in-flight read. It exists so a
	// test can establish that ordering deterministically instead of sleeping.
	onPending func(credentialID string)
}

// compatUsageCacheEntry is one cached meter result.
type compatUsageCacheEntry struct {
	at     time.Time
	result compatUsageResponse
}

// compatUsagePending is an in-flight meter read. The result is published to every
// waiter, so a waiter never observes a zero-value report.
type compatUsagePending struct {
	// done is closed once the result is published.
	done chan struct{}
	// result is the published result. It is written before done is closed.
	result compatUsageResponse
}

// newCompatUsageReader creates a reader with the default cache settings.
func newCompatUsageReader() *compatUsageReader {
	return &compatUsageReader{
		fetcher: compatUsageDefaultFetcher,
		now:     time.Now,
		ttl:     30 * time.Second,
		cache:   make(map[string]compatUsageCacheEntry),
		pending: make(map[string]*compatUsagePending),
	}
}

// compatUsageDefaultFetcher performs the upstream request for a meter. Redirects are
// never followed, so a redirect cannot move the key to another origin.
//
// The request carries no whole-request timeout: the repository's rule is that a
// timeout may only bound credential acquisition, never the network behavior after
// a connection is established. The request context still cancels the read.
func compatUsageDefaultFetcher(ctx context.Context, endpoint, key, proxyURL string) ([]byte, int, error) {
	request, errNew := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if errNew != nil {
		return nil, 0, errNew
	}
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("Accept", "application/json")

	transport, errTransport := compatUsageTransport(proxyURL)
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
		// The transport belongs to this request. Its idle connections are closed
		// when the request is done, so repeated refreshes do not accumulate idle
		// connections and transport goroutines until the idle timeout.
		defer transport.CloseIdleConnections()
	}
	response, errDo := client.Do(request)
	if errDo != nil {
		return nil, 0, errDo
	}
	defer func() {
		_ = response.Body.Close()
	}()
	body, errRead := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if errRead != nil {
		return nil, response.StatusCode, errRead
	}
	return body, response.StatusCode, nil
}

// compatUsageTransport builds the transport for a meter request, honouring the
// credential's proxy. A nil transport means the default transport is used.
func compatUsageTransport(proxyURL string) (*http.Transport, error) {
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

// errCompatUsageCredentialNotFound marks an unknown credential identifier.
var errCompatUsageCredentialNotFound = errors.New("credential not found")

// Read returns the meter for one credential.
func (r *compatUsageReader) Read(ctx context.Context, cfg *config.Config, credentialID string, force bool) (compatUsageResponse, error) {
	if r == nil {
		return compatUsageResponse{Status: "unavailable"}, errors.New("usage reader unavailable")
	}
	var target *compatUsageCredentialKey
	for _, credential := range compatUsageResolveCredentials(cfg) {
		if credential.ID == credentialID {
			copied := credential
			target = &copied
			break
		}
	}
	if target == nil {
		return compatUsageResponse{Status: "unavailable"}, errCompatUsageCredentialNotFound
	}

	empty := compatUsageResponse{
		Credential: compatUsageCredential{
			ID:           target.ID,
			ProviderName: target.ProviderName,
			KeyNumber:    target.KeyNumber,
			Enabled:      target.Enabled,
			Supported:    target.Adapter != nil,
			Scope:        compatUsageScope(target.Adapter),
		},
		Windows:  []compatUsageMeter{},
		Balances: []compatUsageBalance{},
	}
	if !target.Enabled {
		empty.Status = "disabled"
		return empty, nil
	}
	if target.Adapter == nil {
		empty.Status = "unavailable"
		return empty, nil
	}

	r.mu.Lock()
	previous, hasPrevious := r.cache[target.ID]
	if !force && hasPrevious && r.now().Sub(previous.at) < r.ttl {
		r.mu.Unlock()
		return previous.result, nil
	}
	if wait, okPending := r.pending[target.ID]; okPending {
		onPending := r.onPending
		r.mu.Unlock()
		if onPending != nil {
			onPending(target.ID)
		}
		select {
		case <-wait.done:
			// The result is published before done is closed, so every waiter reads
			// the same report.
			return wait.result, nil
		case <-ctx.Done():
			return compatUsageResponse{Status: "error"}, ctx.Err()
		}
	}
	pending := &compatUsagePending{done: make(chan struct{})}
	r.pending[target.ID] = pending
	r.mu.Unlock()

	result := r.fetch(ctx, *target, empty)
	r.mu.Lock()
	// Only a successful read is cached. Caching a failure would make the next
	// healthy caller receive the error without ever contacting the provider: for
	// example when the initiating request is cancelled, its upstream fetch is
	// cancelled too, and the resulting error would be served for the whole cache
	// lifetime.
	if result.Status == "success" {
		r.cache[target.ID] = compatUsageCacheEntry{at: r.now(), result: result}
	} else {
		delete(r.cache, target.ID)
	}
	pending.result = result
	delete(r.pending, target.ID)
	r.mu.Unlock()
	// The result is written before the channel is closed, so a waiter never
	// observes a zero-value report.
	close(pending.done)
	return result, nil
}

// fetch reads the meter for one credential from its provider.
func (r *compatUsageReader) fetch(ctx context.Context, credential compatUsageCredentialKey, empty compatUsageResponse) compatUsageResponse {
	body, status, errFetch := r.fetcher(ctx, credential.Adapter.Endpoint, credential.Key, credential.ProxyURL)
	if errFetch != nil {
		empty.Status = "error"
		return empty
	}
	if status < 200 || status >= 300 {
		empty.Status = "error"
		empty.HTTPStatus = status
		return empty
	}

	payload := map[string]any{}
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		empty.Status = "error"
		return empty
	}

	windows := compatUsageParseWindows(credential.Adapter.ID, payload)
	balances := compatUsageParseBalances(credential.Adapter.ID, payload)
	empty.Windows = windows
	empty.Balances = balances
	empty.FetchedAt = r.now().UTC().Format(time.RFC3339)
	if len(windows) == 0 && len(balances) == 0 {
		empty.Status = "unavailable"
		return empty
	}
	empty.Status = "success"
	return empty
}

// GetCompatProviderUsage lists OpenAI-compatible credentials, including entries
// without a supported usage meter.
func (h *Handler) GetCompatProviderUsage(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	h.mu.Lock()
	// The configuration is snapshotted while the lock is held, because a
	// concurrent provider edit mutates the same structure under that lock.
	cfg := h.cfg.CloneForRuntime()
	h.mu.Unlock()
	if cfg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "configuration unavailable"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"credentials": compatUsageListCredentials(cfg)})
}

// GetCompatProviderUsageDetail returns the usage meter for one OpenAI-compatible
// credential.
func (h *Handler) GetCompatProviderUsageDetail(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	credentialID := strings.TrimSpace(c.Param("id"))
	if credentialID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "credential id required"})
		return
	}
	h.mu.Lock()
	// The configuration is snapshotted while the lock is held, because a
	// concurrent provider edit mutates the same structure under that lock.
	cfg := h.cfg.CloneForRuntime()
	h.mu.Unlock()
	if cfg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "configuration unavailable"})
		return
	}

	force := c.Query("refresh") == "true"
	result, errRead := h.compatUsage().Read(c.Request.Context(), cfg, credentialID, force)
	if errRead != nil {
		if errors.Is(errRead, errCompatUsageCredentialNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "credential not found"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "unable to read the usage meter"})
		return
	}
	c.JSON(http.StatusOK, result)
}

// compatUsage returns the shared usage reader for the handler.
func (h *Handler) compatUsage() *compatUsageReader {
	if h == nil {
		return nil
	}
	h.compatUsageOnce.Do(func() {
		h.compatUsageReader = newCompatUsageReader()
	})
	return h.compatUsageReader
}
