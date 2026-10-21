package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Exercise the handler's JSON contract, rather than only its parsing helpers.
func compatUsageDetailForTest(t *testing.T, h *Handler, id string) (compatUsageResponse, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/v8/management/observability/usage/compatible-providers/"+id, nil)
	c.Params = gin.Params{{Key: "id", Value: id}}
	h.GetCompatProviderUsageDetail(c)
	if rec.Code != http.StatusOK {
		t.Fatalf("detail HTTP status = %d, want 200", rec.Code)
	}
	var report compatUsageResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	return report, rec.Body.String()
}

func TestCompatUsageDetailOllamaAllReportedWindows(t *testing.T) {
	cfg := compatUsageTestConfig()
	h := &Handler{cfg: cfg}
	h.compatUsage().fetcher = func(_ context.Context, endpoint, key, _ string) ([]byte, int, error) {
		if endpoint != "https://ollama.com/api/balance" || key != cfg.OpenAICompatibility[0].APIKeyEntries[0].APIKey {
			t.Fatal("meter request did not use the configured credential's fixed endpoint")
		}
		// The balance contract expresses remaining_percent in percent, not a ratio.
		return []byte(`{"included":{"session":{"remaining_percent":75,"resets_at":"2026-10-21T01:00:00-05:00"},"weekly":{"remaining_percent":40},"monthly":{"remaining_percent":12.5,"resets_at":"2026-11-01T00:00:00Z"}}}`), http.StatusOK, nil
	}
	report, _ := compatUsageDetailForTest(t, h, compatUsageListCredentials(cfg)[0].ID)
	want := []compatUsageMeter{
		{ID: "session", UsedPercent: 25, RemainingPercent: 75, ResetAt: "2026-10-21T06:00:00Z"},
		{ID: "weekly", UsedPercent: 60, RemainingPercent: 40},
		{ID: "monthly", UsedPercent: 87.5, RemainingPercent: 12.5, ResetAt: "2026-11-01T00:00:00Z"},
	}
	if report.Status != "success" || !reflect.DeepEqual(report.Windows, want) {
		t.Fatalf("status/windows = %s %+v, want success %+v", report.Status, report.Windows, want)
	}
}

func TestCompatUsageDetailOpenRouterWithAndWithoutLimit(t *testing.T) {
	for _, tc := range []struct {
		name     string
		body     string
		windows  []compatUsageMeter
		balances []compatUsageBalance
	}{
		{"limited", `{"data":{"limit":100,"limit_remaining":25,"usage":75}}`, []compatUsageMeter{{ID: "key_budget", UsedPercent: 75, RemainingPercent: 25}}, []compatUsageBalance{{ID: "key_remaining", Amount: 25, Currency: "USD"}, {ID: "key_spent", Amount: 75, Currency: "USD"}}},
		{"unlimited", `{"data":{"limit":null,"limit_remaining":null,"usage":75}}`, []compatUsageMeter{}, []compatUsageBalance{{ID: "key_spent", Amount: 75, Currency: "USD"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compatUsageTestConfig()
			// A user-editable name must never select a different provider's endpoint.
			cfg.OpenAICompatibility[1].Name = "ollama-cloud"
			h := &Handler{cfg: cfg}
			calls := 0
			h.compatUsage().fetcher = func(_ context.Context, endpoint, key, _ string) ([]byte, int, error) {
				calls++
				if endpoint != "https://openrouter.ai/api/v1/key" || key != cfg.OpenAICompatibility[1].APIKeyEntries[0].APIKey {
					t.Fatal("provider name changed the endpoint or selected another credential")
				}
				return []byte(tc.body), http.StatusOK, nil
			}
			report, _ := compatUsageDetailForTest(t, h, compatUsageListCredentials(cfg)[2].ID)
			if calls != 1 || report.Status != "success" || !reflect.DeepEqual(report.Windows, tc.windows) || !reflect.DeepEqual(report.Balances, tc.balances) {
				t.Fatalf("calls/status/windows/balances = %d %s %+v %+v", calls, report.Status, report.Windows, report.Balances)
			}
		})
	}
}

func TestCompatUsageDetailUnsupportedIsUnavailable(t *testing.T) {
	cfg := compatUsageTestConfig()
	cfg.OpenAICompatibility[0].BaseURL = "https://unknown.example/v1"
	h := &Handler{cfg: cfg}
	calls := 0
	h.compatUsage().fetcher = func(context.Context, string, string, string) ([]byte, int, error) {
		calls++
		return nil, 0, errors.New("unexpected request")
	}
	credentials := compatUsageListCredentials(cfg)
	if len(credentials) != 3 {
		t.Fatal("unsupported credentials were omitted from inventory")
	}
	report, _ := compatUsageDetailForTest(t, h, credentials[0].ID)
	if calls != 0 || report.Status != "unavailable" || report.Credential.Supported {
		t.Fatalf("calls/status/supported = %d %s %t, want 0 unavailable false", calls, report.Status, report.Credential.Supported)
	}
}

func TestCompatUsageDetailDisabledDoesNotUseCachedSuccessOrQuery(t *testing.T) {
	cfg := compatUsageTestConfig()
	h := &Handler{cfg: cfg}
	calls := 0
	h.compatUsage().fetcher = func(context.Context, string, string, string) ([]byte, int, error) {
		calls++
		return []byte(`{"included":{"session":{"remaining_percent":75}}}`), http.StatusOK, nil
	}
	id := compatUsageListCredentials(cfg)[0].ID
	first, _ := compatUsageDetailForTest(t, h, id)
	if first.Status != "success" || calls != 1 {
		t.Fatal("expected initial successful fetch")
	}
	cfg.OpenAICompatibility[0].Disabled = true
	report, _ := compatUsageDetailForTest(t, h, id)
	if calls != 1 || report.Status != "disabled" || report.Credential.Enabled || len(report.Windows) != 0 {
		t.Fatalf("calls/status/enabled = %d %s %t, want 1 disabled false", calls, report.Status, report.Credential.Enabled)
	}
}

func TestCompatUsageDetailRejectsUnsafeBaseURLsWithoutSendingKey(t *testing.T) {
	for _, tc := range []struct{ name, baseURL string }{
		{"http", "http://ollama.com/v1"},
		{"userinfo", "https://user@ollama.com/v1"},
		{"port", "https://ollama.com:443/v1"},
		{"empty-port", "https://ollama.com:/v1"},
		{"query", "https://ollama.com/v1?account=other"},
		{"empty-query", "https://ollama.com/v1?"},
		{"fragment", "https://ollama.com/v1#other"},
		{"lookalike", "https://ollama.com.example/v1"},
		{"openrouter-empty-port", "https://openrouter.ai:/api/v1"},
		{"openrouter-empty-query", "https://openrouter.ai/api/v1?"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compatUsageTestConfig()
			cfg.OpenAICompatibility[0].BaseURL = tc.baseURL
			h := &Handler{cfg: cfg}
			calls := 0
			h.compatUsage().fetcher = func(context.Context, string, string, string) ([]byte, int, error) {
				calls++
				return nil, 0, errors.New("unexpected request")
			}
			report, _ := compatUsageDetailForTest(t, h, compatUsageListCredentials(cfg)[0].ID)
			if calls != 0 || report.Credential.Supported {
				t.Fatalf("unsafe base URL sent a credential: calls=%d supported=%t", calls, report.Credential.Supported)
			}
		})
	}
}

func TestCompatUsageDetailRedirectNeverReachesAnotherOrigin(t *testing.T) {
	var targetCalls, originCalls, wrongRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	cfg := compatUsageTestConfig()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originCalls.Add(1)
		if r.Host != "ollama.com" || r.URL.Path != "/api/balance" || r.Header.Get("Authorization") != "Bearer "+cfg.OpenAICompatibility[0].APIKeyEntries[0].APIKey {
			wrongRequests.Add(1)
		}
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer origin.Close()
	// Route only the fixed provider host to the TLS fixture, trusting its test CA.
	transport := origin.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig.ServerName = "example.com"
	dialer := &net.Dialer{}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "ollama.com:443" {
			wrongRequests.Add(1)
			return nil, errors.New("unexpected origin")
		}
		return dialer.DialContext(ctx, network, origin.Listener.Addr().String())
	}
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() { http.DefaultTransport = previous; transport.CloseIdleConnections() })
	h := &Handler{cfg: cfg}
	report, _ := compatUsageDetailForTest(t, h, compatUsageListCredentials(cfg)[0].ID)
	if report.Status != "error" || report.HTTPStatus != http.StatusFound || originCalls.Load() != 1 || targetCalls.Load() != 0 || wrongRequests.Load() != 0 {
		t.Fatalf("redirect status=%s HTTP=%d origin=%d target=%d wrong=%d", report.Status, report.HTTPStatus, originCalls.Load(), targetCalls.Load(), wrongRequests.Load())
	}
}

func TestCompatUsageDetailNeverReturnsOrLogsUpstreamBodies(t *testing.T) {
	var captured bytes.Buffer
	logger := log.StandardLogger()
	previousOutput, previousLevel := logger.Out, logger.GetLevel()
	logger.SetOutput(&captured)
	logger.SetLevel(log.TraceLevel)
	t.Cleanup(func() { logger.SetOutput(previousOutput); logger.SetLevel(previousLevel) })
	for _, tc := range []struct {
		name, body, status string
		httpStatus         int
		err                error
	}{
		{"success", `{"data":{"limit":100,"limit_remaining":25,"usage":75,"email":"private-account-marker","key":"private-key-marker"}}`, "success", http.StatusOK, nil},
		{"error-body", `{"error":"private-account-marker private-key-marker"}`, "error", http.StatusUnauthorized, nil},
		{"malformed", `private-account-marker private-key-marker`, "error", http.StatusOK, nil},
		{"transport-error", "private-account-marker private-key-marker", "error", 0, errors.New("private-account-marker private-key-marker")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compatUsageTestConfig()
			h := &Handler{cfg: cfg}
			h.compatUsage().fetcher = func(context.Context, string, string, string) ([]byte, int, error) {
				return []byte(tc.body), tc.httpStatus, tc.err
			}
			report, body := compatUsageDetailForTest(t, h, compatUsageListCredentials(cfg)[2].ID)
			if report.Status != tc.status {
				t.Fatalf("status = %s, want %s", report.Status, tc.status)
			}
			for _, private := range []string{tc.body, "private-account-marker", "private-key-marker", cfg.OpenAICompatibility[1].APIKeyEntries[0].APIKey} {
				if strings.Contains(body, private) || strings.Contains(captured.String(), private) {
					t.Fatal("upstream private data escaped through the response or logs")
				}
			}
		})
	}
}
