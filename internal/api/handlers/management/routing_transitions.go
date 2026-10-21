package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// GetRoutingTransitions returns the routing transition counters and the most
// recent routing transition events.
//
// The counters are grouped by transition, model and provider, so a provider that
// keeps failing over is visible. The events carry the requested model, the provider
// key, the transition outcome and an opaque session identifier; they never carry an
// API key, a token, or any part of the prompt.
func (h *Handler) GetRoutingTransitions(c *gin.Context) {
	if h == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "handler not initialized"})
		return
	}
	recorder := coreauth.GetRoutingTransitionRecorder()
	if recorder == nil {
		c.JSON(http.StatusOK, gin.H{
			"counters": []coreauth.RoutingTransitionCounter{},
			"totals":   map[string]uint64{},
			"events":   []coreauth.RoutingTransitionEvent{},
		})
		return
	}
	// One snapshot, so the totals always agree with the sum of the counters.
	snapshot := recorder.Snapshot()
	c.JSON(http.StatusOK, gin.H{
		"counters": snapshot.Counters,
		"totals":   snapshot.Totals,
		"events":   snapshot.Events,
	})
}
