package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// compatUsageTestConfig builds a configuration with one Ollama Cloud provider and
// one OpenRouter provider.
func compatUsageTestConfig() *config.Config {
	return &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{
				Name:    "ollama-cloud",
				BaseURL: "https://ollama.com/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{
					{APIKey: "ollama-secret-key-1"},
					{APIKey: "ollama-secret-key-2"},
				},
			},
			{
				Name:    "openrouter",
				BaseURL: "https://openrouter.ai/api/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{
					{APIKey: "openrouter-secret-key"},
				},
			},
		},
	}
}

func TestCompatUsageAdapterForRecognizesSupportedProviders(t *testing.T) {
	t.Parallel()

	ollama := compatUsageAdapterFor("https://ollama.com/v1")
	if ollama == nil {
		t.Fatal("expected an adapter for https://ollama.com/v1")
	}
	if ollama.Endpoint != "https://ollama.com/api/balance" {
		t.Fatalf("ollama endpoint = %q", ollama.Endpoint)
	}
	if ollama.Scope != "account" {
		t.Fatalf("ollama scope = %q, want account", ollama.Scope)
	}

	openRouter := compatUsageAdapterFor("https://openrouter.ai/api/v1")
	if openRouter == nil {
		t.Fatal("expected an adapter for https://openrouter.ai/api/v1")
	}
	if openRouter.Endpoint != "https://openrouter.ai/api/v1/key" {
		t.Fatalf("openrouter endpoint = %q", openRouter.Endpoint)
	}
	if openRouter.Scope != "key" {
		t.Fatalf("openrouter scope = %q, want key", openRouter.Scope)
	}
}

func TestCompatUsageAdapterForRejectsUnsafeOrUnknownOrigins(t *testing.T) {
	t.Parallel()

	// A base URL that is not https must never be queried, so a key can never be
	// sent in clear text.
	if got := compatUsageAdapterFor("http://ollama.com/v1"); got != nil {
		t.Fatalf("plain http accepted: %+v", got)
	}
	// Userinfo would leak the key to an unexpected host.
	if got := compatUsageAdapterFor("https://user@ollama.com/v1"); got != nil {
		t.Fatalf("userinfo accepted: %+v", got)
	}
	// An explicit port changes the origin.
	if got := compatUsageAdapterFor("https://ollama.com:8443/v1"); got != nil {
		t.Fatalf("explicit port accepted: %+v", got)
	}
	// A query string is not part of any supported provider URL.
	if got := compatUsageAdapterFor("https://ollama.com/v1?x=1"); got != nil {
		t.Fatalf("query accepted: %+v", got)
	}
	// A lookalike host must not match.
	if got := compatUsageAdapterFor("https://ollama.com.evil.example/v1"); got != nil {
		t.Fatalf("lookalike host accepted: %+v", got)
	}
	// A path the provider does not serve is not the provider.
	if got := compatUsageAdapterFor("https://ollama.com/some/other/path"); got != nil {
		t.Fatalf("unknown path accepted: %+v", got)
	}
	// An unknown provider has no balance API.
	if got := compatUsageAdapterFor("https://api.example.com/v1"); got != nil {
		t.Fatalf("unknown provider accepted: %+v", got)
	}
}

func TestCompatUsageOpaqueIDDoesNotLeakTheKey(t *testing.T) {
	t.Parallel()

	id := compatUsageOpaqueID("ollama-cloud", "https://ollama.com/v1", 0, 0, "super-secret-key-value")
	if strings.Contains(id, "super-secret-key-value") {
		t.Fatal("opaque id contains the API key")
	}
	if len(id) != 64 {
		t.Fatalf("opaque id length = %d, want 64", len(id))
	}
	// The identifier is stable for the same credential.
	if again := compatUsageOpaqueID("ollama-cloud", "https://ollama.com/v1", 0, 0, "super-secret-key-value"); again != id {
		t.Fatal("opaque id is not stable")
	}
	// A different key produces a different identifier.
	if other := compatUsageOpaqueID("ollama-cloud", "https://ollama.com/v1", 0, 0, "another-key"); other == id {
		t.Fatal("opaque id did not change with the key")
	}
}

func TestCompatUsageParseWindowsReadsOllamaUsage(t *testing.T) {
	t.Parallel()

	// A legacy plan reports the session and weekly limits with the percentage
	// remaining.
	payload := map[string]any{
		"included": map[string]any{
			"session": map[string]any{"remaining_percent": 75.0, "resets_at": "2026-10-21T00:00:00Z"},
			"weekly":  map[string]any{"remaining_percent": 40.0},
		},
		"purchased": map[string]any{"balance_usd": 25.0},
	}

	windows := compatUsageParseWindows("ollama", payload)
	if len(windows) != 2 {
		t.Fatalf("windows len = %d, want 2", len(windows))
	}
	if windows[0].ID != "session" || windows[0].UsedPercent != 25 || windows[0].RemainingPercent != 75 {
		t.Fatalf("session window = %+v", windows[0])
	}
	if windows[0].ResetAt != "2026-10-21T00:00:00Z" {
		t.Fatalf("session reset_at = %q", windows[0].ResetAt)
	}
	if windows[1].ID != "weekly" || windows[1].RemainingPercent != 40 {
		t.Fatalf("weekly window = %+v", windows[1])
	}

	balances := compatUsageParseBalances("ollama", payload)
	if len(balances) != 1 {
		t.Fatalf("balances len = %d, want 1", len(balances))
	}
	if balances[0].ID != "purchased_remaining" || balances[0].Amount != 25 {
		t.Fatalf("purchased balance = %+v", balances[0])
	}
}

// TestCompatUsageParseWindowsReadsOllamaModernPlan asserts that a modern Ollama
// plan, which reports the included balance against the period's allowance, is
// read as a remaining percentage.
func TestCompatUsageParseWindowsReadsOllamaModernPlan(t *testing.T) {
	t.Parallel()

	payload := map[string]any{
		"included": map[string]any{
			"balance_usd":   72.5,
			"allowance_usd": 100.0,
			"period": map[string]any{
				"from":  "2026-09-15T09:30:00Z",
				"until": "2026-10-15T09:30:00Z",
			},
		},
		"purchased": map[string]any{"balance_usd": 25.0},
	}

	windows := compatUsageParseWindows("ollama", payload)
	if len(windows) != 1 {
		t.Fatalf("windows len = %d, want 1", len(windows))
	}
	if windows[0].ID != "included" {
		t.Fatalf("window id = %q, want included", windows[0].ID)
	}
	if windows[0].RemainingPercent != 72.5 {
		t.Fatalf("remaining percent = %v, want 72.5", windows[0].RemainingPercent)
	}
	if windows[0].ResetAt != "2026-10-15T09:30:00Z" {
		t.Fatalf("reset at = %q, want the period end", windows[0].ResetAt)
	}

	balances := compatUsageParseBalances("ollama", payload)
	if len(balances) != 2 {
		t.Fatalf("balances len = %d, want 2", len(balances))
	}
}

func TestCompatUsageParseWindowsReadsOpenRouterBudget(t *testing.T) {
	t.Parallel()

	payload := map[string]any{
		"data": map[string]any{
			"limit":           100.0,
			"limit_remaining": 25.0,
			"usage":           75.0,
		},
	}

	windows := compatUsageParseWindows("openrouter", payload)
	if len(windows) != 1 {
		t.Fatalf("windows len = %d, want 1", len(windows))
	}
	if windows[0].ID != "key_budget" {
		t.Fatalf("window id = %q, want key_budget", windows[0].ID)
	}
	if windows[0].RemainingPercent != 25 {
		t.Fatalf("remaining percent = %v, want 25", windows[0].RemainingPercent)
	}

	balances := compatUsageParseBalances("openrouter", payload)
	if len(balances) != 2 {
		t.Fatalf("balances len = %d, want 2", len(balances))
	}
	if balances[0].ID != "key_remaining" || balances[0].Amount != 25 {
		t.Fatalf("remaining balance = %+v", balances[0])
	}
	if balances[1].ID != "key_spent" || balances[1].Amount != 75 {
		t.Fatalf("spent balance = %+v", balances[1])
	}
}

func TestCompatUsageParseIgnoresUnsupportedAndMalformedValues(t *testing.T) {
	t.Parallel()

	// A payload without the expected shape yields no windows rather than a panic.
	if got := compatUsageParseWindows("ollama", map[string]any{"unexpected": "shape"}); len(got) != 0 {
		t.Fatalf("windows = %+v, want none", got)
	}
	if got := compatUsageParseWindows("openrouter", map[string]any{"data": "not-an-object"}); len(got) != 0 {
		t.Fatalf("windows = %+v, want none", got)
	}
	// A negative or unparsable percentage is ignored.
	if got := compatUsageParseWindows("ollama", map[string]any{
		"included": map[string]any{"session": map[string]any{"remaining_percent": -1.0}},
	}); len(got) != 0 {
		t.Fatalf("windows = %+v, want none", got)
	}
	// A provider without a balance API reports no balances.
	if got := compatUsageParseBalances("ollama", map[string]any{"data": map[string]any{"usage": 1.0}}); len(got) != 0 {
		t.Fatalf("balances = %+v, want none", got)
	}
}

func TestCompatUsageReaderReportsProviderMeters(t *testing.T) {
	t.Parallel()

	cfg := compatUsageTestConfig()
	reader := newCompatUsageReader()

	var requestedEndpoint string
	var requestedKey string
	reader.fetcher = func(_ context.Context, endpoint, key, _ string) ([]byte, int, error) {
		requestedEndpoint = endpoint
		requestedKey = key
		body := `{"included":{"session":{"remaining_percent":60,"resets_at":"2026-10-21T00:00:00Z"}}}`
		return []byte(body), http.StatusOK, nil
	}

	credentials := compatUsageListCredentials(cfg)
	if len(credentials) != 3 {
		t.Fatalf("credentials len = %d, want 3", len(credentials))
	}
	if !credentials[0].Supported || credentials[0].Scope != "account" {
		t.Fatalf("ollama credential = %+v", credentials[0])
	}
	if !credentials[2].Supported || credentials[2].Scope != "key" {
		t.Fatalf("openrouter credential = %+v", credentials[2])
	}

	result, errRead := reader.Read(context.Background(), cfg, credentials[0].ID, false)
	if errRead != nil {
		t.Fatalf("Read: %v", errRead)
	}
	if result.Status != "success" {
		t.Fatalf("status = %q, want success", result.Status)
	}
	if len(result.Windows) != 1 || result.Windows[0].RemainingPercent != 60 {
		t.Fatalf("windows = %+v", result.Windows)
	}
	if requestedEndpoint != "https://ollama.com/api/balance" {
		t.Fatalf("endpoint = %q", requestedEndpoint)
	}
	if requestedKey != "ollama-secret-key-1" {
		t.Fatalf("wrong key was sent: %q", requestedKey)
	}
	// The response never carries the key.
	encoded, errMarshal := json.Marshal(result)
	if errMarshal != nil {
		t.Fatalf("marshal: %v", errMarshal)
	}
	if strings.Contains(string(encoded), "ollama-secret-key-1") {
		t.Fatal("the response contains the API key")
	}
}

func TestCompatUsageReaderReportsUnsupportedAndDisabled(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{
				Name:    "unknown",
				BaseURL: "https://api.example.com/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{
					{APIKey: "unknown-key"},
				},
			},
			{
				Name:     "ollama-cloud",
				BaseURL:  "https://ollama.com/v1",
				Disabled: true,
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{
					{APIKey: "disabled-key"},
				},
			},
		},
	}
	reader := newCompatUsageReader()
	reader.fetcher = func(_ context.Context, _ string, _ string, _ string) ([]byte, int, error) {
		t.Fatal("the reader must not query an unsupported or disabled credential")
		return nil, 0, nil
	}

	credentials := compatUsageListCredentials(cfg)
	if len(credentials) != 2 {
		t.Fatalf("credentials len = %d, want 2", len(credentials))
	}
	if credentials[0].Supported {
		t.Fatal("an unknown provider must not be reported as supported")
	}

	unsupported, errRead := reader.Read(context.Background(), cfg, credentials[0].ID, false)
	if errRead != nil {
		t.Fatalf("Read unsupported: %v", errRead)
	}
	if unsupported.Status != "unavailable" {
		t.Fatalf("status = %q, want unavailable", unsupported.Status)
	}

	disabled, errRead := reader.Read(context.Background(), cfg, credentials[1].ID, false)
	if errRead != nil {
		t.Fatalf("Read disabled: %v", errRead)
	}
	if disabled.Status != "disabled" {
		t.Fatalf("status = %q, want disabled", disabled.Status)
	}
}

func TestCompatUsageReaderReportsUnknownCredential(t *testing.T) {
	t.Parallel()

	reader := newCompatUsageReader()
	if _, errRead := reader.Read(context.Background(), compatUsageTestConfig(), "does-not-exist", false); errRead == nil {
		t.Fatal("expected an error for an unknown credential")
	}
}

func TestCompatUsageReaderCachesWithinTheTTL(t *testing.T) {
	t.Parallel()

	cfg := compatUsageTestConfig()
	reader := newCompatUsageReader()
	now := time.Now()
	reader.now = func() time.Time { return now }

	calls := 0
	reader.fetcher = func(_ context.Context, _ string, _ string, _ string) ([]byte, int, error) {
		calls++
		return []byte(`{"data":{"limit":100,"limit_remaining":50,"usage":50}}`), http.StatusOK, nil
	}

	credential := compatUsageListCredentials(cfg)[2]
	if _, errRead := reader.Read(context.Background(), cfg, credential.ID, false); errRead != nil {
		t.Fatalf("first Read: %v", errRead)
	}
	if _, errRead := reader.Read(context.Background(), cfg, credential.ID, false); errRead != nil {
		t.Fatalf("second Read: %v", errRead)
	}
	if calls != 1 {
		t.Fatalf("upstream calls = %d, want 1 (the meter is cached)", calls)
	}

	// A forced refresh bypasses the cache.
	if _, errRead := reader.Read(context.Background(), cfg, credential.ID, true); errRead != nil {
		t.Fatalf("forced Read: %v", errRead)
	}
	if calls != 2 {
		t.Fatalf("upstream calls = %d, want 2 after a forced refresh", calls)
	}
}

func TestCompatUsageReaderReportsUpstreamErrorWithoutTheBody(t *testing.T) {
	t.Parallel()

	cfg := compatUsageTestConfig()
	reader := newCompatUsageReader()
	reader.fetcher = func(_ context.Context, _ string, _ string, _ string) ([]byte, int, error) {
		// The upstream error body can contain account metadata. It must not be
		// returned to the caller.
		return []byte(`{"error":"account email@example.com is over limit"}`), http.StatusForbidden, nil
	}

	credential := compatUsageListCredentials(cfg)[0]
	result, errRead := reader.Read(context.Background(), cfg, credential.ID, false)
	if errRead != nil {
		t.Fatalf("Read: %v", errRead)
	}
	if result.Status != "error" {
		t.Fatalf("status = %q, want error", result.Status)
	}
	if result.HTTPStatus != http.StatusForbidden {
		t.Fatalf("http status = %d, want 403", result.HTTPStatus)
	}
	encoded, errMarshal := json.Marshal(result)
	if errMarshal != nil {
		t.Fatalf("marshal: %v", errMarshal)
	}
	if strings.Contains(string(encoded), "email@example.com") {
		t.Fatal("the response contains the upstream error body")
	}
}

func TestGetCompatProviderUsageEndpoints(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	cfg := compatUsageTestConfig()
	cfg.AuthDir = t.TempDir()
	h := NewHandlerWithoutConfigFilePath(cfg, nil)

	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/openai-compatibility/usage", nil)
	h.GetCompatProviderUsage(ginCtx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var listPayload struct {
		Credentials []compatUsageCredential `json:"credentials"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listPayload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if len(listPayload.Credentials) != 3 {
		t.Fatalf("credentials len = %d, want 3", len(listPayload.Credentials))
	}
	if strings.Contains(rec.Body.String(), "ollama-secret-key-1") {
		t.Fatal("the credential list contains the API key")
	}

	// An unknown credential identifier answers 404.
	rec = httptest.NewRecorder()
	ginCtx, _ = gin.CreateTestContext(rec)
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/openai-compatibility/usage/unknown", nil)
	ginCtx.Params = gin.Params{{Key: "id", Value: "unknown"}}
	h.GetCompatProviderUsageDetail(ginCtx)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestCompatUsageReaderConcurrentWaitersGetTheResult(t *testing.T) {
	t.Parallel()

	cfg := compatUsageTestConfig()
	reader := newCompatUsageReader()

	release := make(chan struct{})
	started := make(chan struct{})
	// The second read must be known to have entered the pending branch before the
	// fetcher is released, so the test cannot pass by reading a populated cache
	// instead of waiting on the in-flight read.
	secondParked := make(chan struct{})
	var parkOnce sync.Once
	reader.onPending = func(string) { parkOnce.Do(func() { close(secondParked) }) }
	var fetchCount atomic.Int32
	reader.fetcher = func(_ context.Context, _ string, _ string, _ string) ([]byte, int, error) {
		if fetchCount.Add(1) == 1 {
			close(started)
		}
		<-release
		return []byte(`{"data":{"limit":100,"limit_remaining":25,"usage":75}}`), http.StatusOK, nil
	}

	credential := compatUsageListCredentials(cfg)[2]

	// The first read takes the in-flight slot; the second must wait for it.
	type outcome struct {
		result compatUsageResponse
		err    error
	}
	results := make(chan outcome, 2)

	go func() {
		result, err := reader.Read(context.Background(), cfg, credential.ID, false)
		results <- outcome{result, err}
	}()
	<-started

	go func() {
		result, err := reader.Read(context.Background(), cfg, credential.ID, false)
		results <- outcome{result, err}
	}()

	// The second read reaches the pending branch and waits there. The reader
	// signals when it parks on the in-flight read, so the ordering is
	// deterministic and no sleep is involved.
	select {
	case <-secondParked:
	case <-time.After(10 * time.Second):
		t.Fatal("the second read did not park on the in-flight read")
	}
	close(release)

	for i := 0; i < 2; i++ {
		select {
		case got := <-results:
			if got.err != nil {
				t.Fatalf("read %d: %v", i, got.err)
			}
			if got.result.Status != "success" {
				t.Fatalf("read %d status = %q, want success (a waiter must not observe a zero-value report)", i, got.result.Status)
			}
			if len(got.result.Balances) == 0 {
				t.Fatalf("read %d has no balances (a waiter must observe the published result)", i)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("a read did not return")
		}
	}
}

func TestCompatUsageReaderCarriesTheCredentialProxy(t *testing.T) {
	t.Parallel()

	cfg := compatUsageTestConfig()
	cfg.ProxyURL = "http://proxy.example.com:8080"
	cfg.OpenAICompatibility[0].APIKeyEntries[0].ProxyURL = "http://key-proxy.example.com:8080"

	reader := newCompatUsageReader()
	var seenProxy string
	reader.fetcher = func(_ context.Context, _ string, _ string, proxyURL string) ([]byte, int, error) {
		seenProxy = proxyURL
		return []byte(`{"data":{"limit":100,"limit_remaining":25,"usage":75}}`), http.StatusOK, nil
	}

	credential := compatUsageListCredentials(cfg)[0]
	if _, errRead := reader.Read(context.Background(), cfg, credential.ID, false); errRead != nil {
		t.Fatalf("Read: %v", errRead)
	}
	if seenProxy != "http://key-proxy.example.com:8080" {
		t.Fatalf("proxy = %q, want the credential's own proxy", seenProxy)
	}

	// Without a per-key proxy the global one is used.
	cfg.OpenAICompatibility[0].APIKeyEntries[0].ProxyURL = ""
	second := compatUsageListCredentials(cfg)[1]
	if _, errRead := reader.Read(context.Background(), cfg, second.ID, false); errRead != nil {
		t.Fatalf("Read: %v", errRead)
	}
	if seenProxy != "http://proxy.example.com:8080" {
		t.Fatalf("proxy = %q, want the global proxy", seenProxy)
	}
}

func TestGetCompatProviderUsageDetailAnswersFromTheScopedNamespace(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	cfg := compatUsageTestConfig()
	cfg.AuthDir = t.TempDir()
	h := NewHandlerWithoutConfigFilePath(cfg, nil)

	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/observability/usage/compatible-providers/unknown", nil)
	ginCtx.Params = gin.Params{{Key: "id", Value: "unknown"}}
	h.GetCompatProviderUsageDetail(ginCtx)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestCompatUsageDuplicateProviderEntriesGetDistinctIdentifiers(t *testing.T) {
	t.Parallel()

	// Two entries share a name, a base URL and a key. They are different
	// credentials, so they must get different identifiers.
	cfg := &config.Config{
		OpenAICompatibility: []config.OpenAICompatibility{
			{
				Name:     "ollama-cloud",
				BaseURL:  "https://ollama.com/v1",
				Disabled: true,
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{
					{APIKey: "shared-key"},
				},
			},
			{
				Name:    "ollama-cloud",
				BaseURL: "https://ollama.com/v1",
				APIKeyEntries: []config.OpenAICompatibilityAPIKey{
					{APIKey: "shared-key"},
				},
			},
		},
	}

	credentials := compatUsageListCredentials(cfg)
	if len(credentials) != 2 {
		t.Fatalf("credentials len = %d, want 2", len(credentials))
	}
	if credentials[0].ID == credentials[1].ID {
		t.Fatalf("two provider entries share the identifier %q", credentials[0].ID)
	}
	if credentials[0].Enabled {
		t.Fatal("the first entry is disabled")
	}
	if !credentials[1].Enabled {
		t.Fatal("the second entry is enabled")
	}

	// Reading the enabled entry must not resolve to the disabled one.
	reader := newCompatUsageReader()
	reader.fetcher = func(_ context.Context, _ string, _ string, _ string) ([]byte, int, error) {
		return []byte(`{"included":{"session":{"remaining_percent":50}}}`), http.StatusOK, nil
	}
	result, errRead := reader.Read(context.Background(), cfg, credentials[1].ID, false)
	if errRead != nil {
		t.Fatalf("Read: %v", errRead)
	}
	if !result.Credential.Enabled {
		t.Fatal("the read resolved to the disabled entry")
	}
}

func TestCompatUsageReaderDoesNotCacheAFailure(t *testing.T) {
	t.Parallel()

	cfg := compatUsageTestConfig()
	reader := newCompatUsageReader()

	calls := 0
	reader.fetcher = func(_ context.Context, _ string, _ string, _ string) ([]byte, int, error) {
		calls++
		if calls == 1 {
			// The first read fails.
			return nil, http.StatusInternalServerError, nil
		}
		return []byte(`{"data":{"limit":100,"limit_remaining":25,"usage":75}}`), http.StatusOK, nil
	}

	credential := compatUsageListCredentials(cfg)[2]
	first, errRead := reader.Read(context.Background(), cfg, credential.ID, false)
	if errRead != nil {
		t.Fatalf("Read: %v", errRead)
	}
	if first.Status != "error" {
		t.Fatalf("first status = %q, want error", first.Status)
	}

	// The failure must not be served from the cache: the next read contacts the
	// provider again.
	second, errRead := reader.Read(context.Background(), cfg, credential.ID, false)
	if errRead != nil {
		t.Fatalf("second Read: %v", errRead)
	}
	if second.Status != "success" {
		t.Fatalf("second status = %q, want success (a failure must not be cached)", second.Status)
	}
	if calls != 2 {
		t.Fatalf("upstream calls = %d, want 2", calls)
	}
}
