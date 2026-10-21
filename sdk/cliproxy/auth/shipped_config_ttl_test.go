package auth

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestShippedConfigAffinityTTL(t *testing.T) {
	cfg, err := internalconfig.LoadConfig(filepath.Join("..", "..", "..", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ttl, err := time.ParseDuration(cfg.Routing.SessionAffinityTTL)
	if err != nil || ttl != time.Hour {
		t.Fatal("shipped TTL must parse to one hour")
	}
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &RoundRobinSelector{}, TTL: ttl})
	t.Cleanup(selector.Stop)
	auths := []*Auth{{ID: "shipped-ttl-a", Provider: "shipped-ttl"}, {ID: "shipped-ttl-b", Provider: "shipped-ttl"}}
	options := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Id": {"shipped-ttl-session"}}}
	before := time.Now()
	first, err := selector.Pick(context.Background(), "shipped-ttl", "shipped-model", options, auths)
	after := time.Now()
	if err != nil || first == nil {
		t.Fatalf("initial selection: %v", err)
	}
	if selector.cache.ttl != time.Hour {
		t.Fatal("selector cache did not receive the shipped TTL")
	}
	// Inspect and expire the actual binding under its lock. No sleeps, new
	// production clock seam or dependence on the provider-set key format.
	selector.cache.mu.Lock()
	if len(selector.cache.entries) == 0 {
		selector.cache.mu.Unlock()
		t.Fatal("session selection did not create a binding")
	}
	for key, entry := range selector.cache.entries {
		if entry.expiresAt.Before(before.Add(time.Hour)) || entry.expiresAt.After(after.Add(time.Hour)) {
			selector.cache.mu.Unlock()
			t.Fatal("binding expiration does not use the configured one-hour TTL")
		}
		entry.expiresAt = before.Add(-time.Hour)
		selector.cache.entries[key] = entry
	}
	selector.cache.mu.Unlock()
	again, err := selector.Pick(context.Background(), "shipped-ttl", "shipped-model", options, auths)
	if err != nil || again == nil || again.ID == first.ID {
		t.Fatal("an expired session binding must allow round-robin to choose the next credential")
	}
}
