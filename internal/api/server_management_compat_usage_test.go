package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// TestManagementV8CompatibleProviderUsageRoutes registers the maintained management
// routes and exercises the provider usage meter endpoints through the router.
//
// The test goes through the server's own engine, so it fails if the route
// registrations are missing or land on the deprecated /v0 prefix.
func TestManagementV8CompatibleProviderUsageRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := "port: 8317\nrequest-retry: 3\ndebug: false\napi-keys: [client]\nremote-management: {secret-key: test-password}\n" +
		"openai-compatibility:\n" +
		"  - name: ollama-cloud\n" +
		"    base-url: https://ollama.com/v1\n" +
		"    api-key-entries:\n" +
		"      - api-key: \"test-ollama-key\"\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	h := management.NewHandler(cfg, path, nil)
	h.SetLocalPassword("test-password")
	s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
	s.managementRoutesEnabled.Store(true)
	s.registerManagementRoutes()

	// The list endpoint.
	req := httptest.NewRequest(http.MethodGet, "/v8/management/observability/usage/compatible-providers", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	recorder := httptest.NewRecorder()
	s.engine.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d want=%d body=%s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var listPayload struct {
		Credentials []struct {
			ID           string `json:"id"`
			ProviderName string `json:"provider_name"`
			Supported    bool   `json:"supported"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &listPayload); err != nil {
		t.Fatalf("decode list payload: %v body=%s", err, recorder.Body.String())
	}
	if len(listPayload.Credentials) != 1 {
		t.Fatalf("credentials len=%d want=1 body=%s", len(listPayload.Credentials), recorder.Body.String())
	}
	if listPayload.Credentials[0].ProviderName != "ollama-cloud" {
		t.Fatalf("provider name=%q want=ollama-cloud", listPayload.Credentials[0].ProviderName)
	}
	if !listPayload.Credentials[0].Supported {
		t.Fatal("the ollama-cloud credential should be reported as supported")
	}
	// The list must never carry the API key.
	if body := recorder.Body.String(); strings.Contains(body, "test-ollama-key") {
		t.Fatalf("the credential list contains the API key: %s", body)
	}

	// The detail endpoint, with an unknown credential.
	req = httptest.NewRequest(http.MethodGet, "/v8/management/observability/usage/compatible-providers/unknown-id", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("Authorization", "Bearer test-password")
	recorder = httptest.NewRecorder()
	s.engine.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("detail status=%d want=%d body=%s", recorder.Code, http.StatusNotFound, recorder.Body.String())
	}
}

// TestManagementV8CompatibleProviderUsageRoutesRequireTheKey asserts that the new
// endpoints are behind the management access control.
func TestManagementV8CompatibleProviderUsageRoutesRequireTheKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := "port: 8317\nremote-management: {secret-key: test-password}\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	h := management.NewHandler(cfg, path, nil)
	h.SetLocalPassword("test-password")
	s := &Server{cfg: cfg, engine: gin.New(), mgmt: h}
	s.managementRoutesEnabled.Store(true)
	s.registerManagementRoutes()

	for _, route := range []string{
		"/v8/management/observability/usage/compatible-providers",
		"/v8/management/observability/usage/compatible-providers/some-id",
	} {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		req.RemoteAddr = "127.0.0.1:1234"
		recorder := httptest.NewRecorder()
		s.engine.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status=%d want=%d body=%s", route, recorder.Code, http.StatusUnauthorized, recorder.Body.String())
		}
	}
}
