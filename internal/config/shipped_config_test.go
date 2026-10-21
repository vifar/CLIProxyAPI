package config

import (
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func loadShippedConfig(t *testing.T) *Config {
	t.Helper()
	// LoadConfig is the non-optional startup loader, not the byte-only parser.
	cfg, err := LoadConfig(filepath.Join("..", "..", "config.yaml"))
	if err != nil {
		t.Fatalf("load shipped config: %v", err)
	}
	return cfg
}

func TestShippedConfigLoads(t *testing.T) {
	cfg := loadShippedConfig(t)
	if cfg.Host != "127.0.0.1" || cfg.Port != 8318 {
		t.Fatal("shipped config must start on 127.0.0.1:8318")
	}
}

func TestShippedConfigRoutingDefaults(t *testing.T) {
	assertShippedRoutingDefaults(t, loadShippedConfig(t).Routing)
}

func assertShippedRoutingDefaults(t *testing.T, routing RoutingConfig) {
	t.Helper()
	if routing.Strategy != "round-robin" || !routing.SessionAffinity {
		t.Fatal("issue #10 requires round-robin with session affinity enabled")
	}
	// The loader stores a string; the service consumes it with time.ParseDuration.
	ttl, err := time.ParseDuration(routing.SessionAffinityTTL)
	if err != nil || ttl != time.Hour {
		t.Fatalf("affinity TTL = %v (parse error %v), want one hour", ttl, err)
	}
}

func TestShippedConfigHasNoCredentials(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var raw Config
	if err = yaml.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	// Check both representations: startup sanitizers can drop invalid key entries.
	for _, cfg := range []*Config{&raw, loadShippedConfig(t)} {
		if len(cfg.APIKeys) != 0 || cfg.GitHubToken != "" || cfg.ProxyURL != "" ||
			cfg.RemoteManagement.SecretKey != "" || cfg.TLS.Key != "" {
			t.Fatal("shipped config contains client, management, proxy, GitHub or TLS credentials")
		}
		if len(cfg.GeminiKey)+len(cfg.InteractionsKey)+len(cfg.CodexKey)+len(cfg.XAIKey)+
			len(cfg.MetaKey)+len(cfg.ClaudeKey)+len(cfg.VertexCompatAPIKey) != 0 {
			t.Fatal("shipped config must not contain native API-key entries")
		}
		if len(cfg.Plugins.StoreAuth)+len(cfg.Plugins.Configs)+len(cfg.Codex.LiveMediaRelay.ICEServers) != 0 {
			t.Fatal("shipped config must not contain plugin or media-relay credentials")
		}
		for _, provider := range cfg.OpenAICompatibility {
			if !provider.Disabled {
				t.Error("a provider without operator credentials must start disabled")
			}
			if len(provider.Headers) != 0 {
				t.Error("shipped providers must not contain custom authentication headers")
			}
			endpoint, errParse := url.Parse(provider.BaseURL)
			if errParse != nil || endpoint.Scheme != "https" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
				t.Error("provider URL must be HTTPS without userinfo, query or fragment")
			}
			for _, key := range provider.APIKeyEntries {
				if key.APIKey != "" || key.ProxyURL != "" {
					t.Error("shipped provider contains API-key or proxy credentials")
				}
			}
		}
	}
}

func TestShippedConfigNativeExclusionKey(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]yaml.Node
	if err = yaml.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	if _, exists := document["oauth-excluded-models"]; !exists {
		t.Error("native oauth-excluded-models key is missing")
	}
	if _, exists := document["oauth-included-models"]; exists {
		t.Error("app-side inclusion key must not be shipped")
	}
	cfg := loadShippedConfig(t)
	for _, provider := range []string{"claude", "codex"} {
		if len(cfg.OAuthExcludedModels[provider]) == 0 {
			t.Errorf("native exclusions missing for %s", provider)
		}
	}
}

func TestShippedConfigProviders(t *testing.T) {
	cfg := loadShippedConfig(t)
	want := map[string]string{
		"ollama-cloud": "https://ollama.com/v1",
		"openrouter":   "https://openrouter.ai/api/v1",
		"vercel":       "https://ai-gateway.vercel.sh/v1",
	}
	for _, provider := range cfg.OpenAICompatibility {
		if endpoint, ok := want[provider.Name]; !ok || endpoint != provider.BaseURL || len(provider.Models) == 0 {
			t.Fatal("shipped provider does not match the compatible-provider configuration from PR #11")
		}
		if provider.Name == "ollama-cloud" {
			models := make(map[string]bool)
			for _, model := range provider.Models {
				models[model.Alias] = true
			}
			if !models["deepseek-v4.1-flash"] || !models["kimi-k3"] {
				t.Error("documented DeepSeek default and Kimi K3 aliases must be retained")
			}
		}
		delete(want, provider.Name)
	}
	if len(want) != 0 {
		t.Fatal("a documented compatible provider is missing")
	}
}

func TestShippedConfigIsTracked(t *testing.T) {
	cmd := exec.Command("git", "ls-files", "--error-unmatch", "--", "config.yaml")
	cmd.Dir = filepath.Join("..", "..")
	output, err := cmd.CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "config.yaml" {
		t.Fatal("config.yaml must be force-added to git, despite its ignore rule")
	}
}

func TestShippedConfigDocumentation(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	_, section, found := strings.Cut(string(data), "## Fork configuration\n")
	if !found {
		t.Fatal("README must explain the fork configuration")
	}
	section, _, _ = strings.Cut(section, "\n## ")
	_, example, found := strings.Cut(section, "```yaml\n")
	if !found {
		t.Fatal("README must show executable YAML for the routing defaults and native exclusions")
	}
	example, _, _ = strings.Cut(example, "```")
	var documented Config
	if err = yaml.Unmarshal([]byte(example), &documented); err != nil {
		t.Fatal(err)
	}
	assertShippedRoutingDefaults(t, documented.Routing)
	if len(documented.OAuthExcludedModels["claude"]) == 0 || len(documented.OAuthExcludedModels["codex"]) == 0 {
		t.Fatal("README must demonstrate the native exclusion key")
	}
}
