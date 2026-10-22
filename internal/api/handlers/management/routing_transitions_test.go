package management

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestGetRoutingTransitionsReturnsCountersAndEvents(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	recorder := coreauth.NewRoutingTransitionRecorder(10)
	recorder.Record(coreauth.RoutingTransitionEvent{
		Transition: coreauth.RoutingTransitionBindingCreated,
		Model:      "model-a",
		Provider:   "provider-a",
		Session:    "session-1",
	})
	recorder.Record(coreauth.RoutingTransitionEvent{
		Transition: coreauth.RoutingTransitionProviderFailover,
		Model:      "model-a",
		Provider:   "provider-b",
	})
	previous := coreauth.GetRoutingTransitionRecorder()
	coreauth.SetRoutingTransitionRecorder(recorder)
	t.Cleanup(func() { coreauth.SetRoutingTransitionRecorder(previous) })

	h := NewHandlerWithoutConfigFilePath(nil, nil)
	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/observability/routing/transitions", nil)
	h.GetRoutingTransitions(ginCtx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{"binding_created", "provider_failover", "provider-a", "provider-b", "model-a"} {
		if !strings.Contains(body, want) {
			t.Fatalf("response does not carry %q: %s", want, body)
		}
	}
}

func TestGetRoutingTransitionsWithoutARecorder(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	previous := coreauth.GetRoutingTransitionRecorder()
	coreauth.SetRoutingTransitionRecorder(nil)
	t.Cleanup(func() { coreauth.SetRoutingTransitionRecorder(previous) })

	h := NewHandlerWithoutConfigFilePath(nil, nil)
	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	ginCtx.Request = httptest.NewRequest(http.MethodGet, "/v0/management/observability/routing/transitions", nil)
	h.GetRoutingTransitions(ginCtx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "counters") {
		t.Fatalf("response does not carry the counters field: %s", rec.Body.String())
	}
}
