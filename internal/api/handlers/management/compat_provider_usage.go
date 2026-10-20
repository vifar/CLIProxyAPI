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
	// Currency is the currency code reported by the provider.
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
	// Status is one of "success", "unavailable", "unsupported", "disabled" or
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
var compatUsageAdapters = []compatUsageAdapter{
	{ID: "ollama", Endpoint: "https://ollama.com/api/usage", Scope: "account"},
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
	if parsed.Scheme != "https" || parsed.User != nil || parsed.Port() != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
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
	// Key is the API key. It never leaves the process.
	Key string
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
		for keyIndex, entry := range provider.APIKeyEntries {
			key := strings.TrimSpace(entry.APIKey)
			if key == "" {
				continue
			}
			out = append(out, compatUsageCredentialKey{
				ID:           compatUsageOpaqueID(providerName, baseURL, keyIndex, key),
				ProviderName: providerName,
				BaseURL:      baseURL,
				KeyNumber:    keyIndex + 1,
				Key:          key,
				Enabled:      !provider.Disabled,
				Adapter:      adapter,
			})
		}
	}
	return out
}

// compatUsageOpaqueID derives a stable, opaque identifier for a credential. The key
// is mixed into an HMAC, so the identifier cannot be reversed to the key and does
// not change when the key rotates in place.
func compatUsageOpaqueID(providerName, baseURL string, index int, key string) string {
	mac := hmac.New(sha256.New, compatUsageIdentitySecret)
	_, _ = mac.Write([]byte(providerName))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(baseURL))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(strconv.Itoa(index)))
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
		limits, ok := payload["limits"].(map[string]any)
		if !ok {
			return windows
		}
		for _, period := range []string{"session", "weekly", "monthly"} {
			entry, okEntry := limits[period].(map[string]any)
			if !okEntry {
				continue
			}
			usage, okUsage := compatUsageNumber(entry["usage"])
			if !okUsage {
				continue
			}
			usedPercent := usage * 100
			if math.IsNaN(usedPercent) || math.IsInf(usedPercent, 0) {
				continue
			}
			resetAt := ""
			if raw, okRaw := entry["reset_at"].(string); okRaw {
				if parsed, errParse := time.Parse(time.RFC3339, strings.TrimSpace(raw)); errParse == nil {
					resetAt = parsed.UTC().Format(time.RFC3339)
				}
			}
			windows = append(windows, compatUsageMeter{
				ID:               period,
				UsedPercent:      usedPercent,
				RemainingPercent: math.Max(0, 100-usedPercent),
				ResetAt:          resetAt,
			})
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
	if adapterID != "openrouter" {
		return balances
	}
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
	return balances
}

// compatUsageReader reads provider usage meters with a short per-credential cache.
type compatUsageReader struct {
	// fetcher performs the upstream request. It is replaceable in tests.
	fetcher func(ctx context.Context, endpoint, key string) ([]byte, int, error)
	// now returns the current time.
	now func() time.Time
	// ttl is the cache lifetime of one credential's meter.
	ttl time.Duration

	mu      sync.Mutex
	cache   map[string]compatUsageCacheEntry
	pending map[string]chan compatUsageResponse
}

// compatUsageCacheEntry is one cached meter result.
type compatUsageCacheEntry struct {
	at     time.Time
	result compatUsageResponse
}

// newCompatUsageReader creates a reader with the default cache settings.
func newCompatUsageReader() *compatUsageReader {
	return &compatUsageReader{
		fetcher: compatUsageDefaultFetcher,
		now:     time.Now,
		ttl:     30 * time.Second,
		cache:   make(map[string]compatUsageCacheEntry),
		pending: make(map[string]chan compatUsageResponse),
	}
}

// compatUsageDefaultFetcher performs the upstream request for a meter. Redirects are
// never followed, so a redirect cannot move the key to another origin.
func compatUsageDefaultFetcher(ctx context.Context, endpoint, key string) ([]byte, int, error) {
	request, errNew := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if errNew != nil {
		return nil, 0, errNew
	}
	request.Header.Set("Authorization", "Bearer "+key)
	request.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
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
		empty.Status = "unsupported"
		return empty, nil
	}

	r.mu.Lock()
	previous, hasPrevious := r.cache[target.ID]
	if !force && hasPrevious && r.now().Sub(previous.at) < r.ttl {
		r.mu.Unlock()
		return previous.result, nil
	}
	if wait, okPending := r.pending[target.ID]; okPending {
		r.mu.Unlock()
		select {
		case result := <-wait:
			return result, nil
		case <-ctx.Done():
			return compatUsageResponse{Status: "error"}, ctx.Err()
		}
	}
	done := make(chan compatUsageResponse, 1)
	r.pending[target.ID] = done
	r.mu.Unlock()

	result := r.fetch(ctx, *target, empty)
	r.mu.Lock()
	r.cache[target.ID] = compatUsageCacheEntry{at: r.now(), result: result}
	delete(r.pending, target.ID)
	r.mu.Unlock()
	close(done)
	return result, nil
}

// fetch reads the meter for one credential from its provider.
func (r *compatUsageReader) fetch(ctx context.Context, credential compatUsageCredentialKey, empty compatUsageResponse) compatUsageResponse {
	body, status, errFetch := r.fetcher(ctx, credential.Adapter.Endpoint, credential.Key)
	if errFetch != nil {
		r.dropCache(credential.ID)
		empty.Status = "error"
		return empty
	}
	if status < 200 || status >= 300 {
		r.dropCache(credential.ID)
		empty.Status = "error"
		empty.HTTPStatus = status
		return empty
	}

	payload := map[string]any{}
	if errDecode := json.Unmarshal(body, &payload); errDecode != nil {
		r.dropCache(credential.ID)
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

// dropCache removes one cached meter result.
func (r *compatUsageReader) dropCache(credentialID string) {
	r.mu.Lock()
	delete(r.cache, credentialID)
	r.mu.Unlock()
}

// GetCompatProviderUsage lists the OpenAI-compatible credentials that have a usage
// meter.
func (h *Handler) GetCompatProviderUsage(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	h.mu.Lock()
	cfg := h.cfg
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
	cfg := h.cfg
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
