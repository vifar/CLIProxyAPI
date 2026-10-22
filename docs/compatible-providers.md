# Compatible providers in this fork

This fork runs OpenAI-compatible providers as first-class entries in
`openai-compatibility`. The proxy reads the provider's own model list in the
background, so a provider that adds or removes a model does not need a hand edit
of the configuration.

## The providers

| Provider | Base URL | Live model list | Key needed to read the list | Key needed to route |
|---|---|---|---|---|
| Ollama Cloud | `https://ollama.com/v1` | `https://ollama.com/v1/models` | yes | yes |
| OpenRouter | `https://openrouter.ai/api/v1` | `https://openrouter.ai/api/v1/models` | no | yes |
| Vercel AI Gateway | `https://ai-gateway.vercel.sh/v1` | `https://ai-gateway.vercel.sh/v1/models` | no | yes |

Discovery selects enabled entries by the hostname in `base-url`, regardless of
the entry's `name` or URL path, and uses the fixed model-list endpoint above.
The URL must use HTTPS, without userinfo, an explicit port, a query or a fragment.
Other hosts are never queried for discovery; their configured models still obey
the provider's exclusions. Redirects are not followed.

### Ollama Cloud

Ollama Cloud serves DeepSeek, Kimi and GLM models over an OpenAI-compatible API.

```yaml
openai-compatibility:
  - name: ollama-cloud
    base-url: https://ollama.com/v1
    api-key-entries:
      - api-key: "your-ollama-cloud-key"
    models:
      - name: deepseek-v4.1-flash
        alias: deepseek-v4.1-flash
```

See the [root configuration](../config.yaml) for the shipped model pins. A pin is
published when the provider is enabled unless excluded, whether or not discovery
has completed; it does not verify upstream availability. The alias is what a
client asks for; the name is what the upstream serves. Keeping them separate lets
an operator change the upstream name without breaking a client's alias.

### OpenRouter

OpenRouter aggregates many upstreams behind one OpenAI-compatible endpoint. Its
model list is public, so the proxy can read it without a key, but a key is needed
to route requests.

```yaml
openai-compatibility:
  - name: openrouter
    base-url: https://openrouter.ai/api/v1
    api-key-entries:
      - api-key: "your-openrouter-key"
    models:
      - name: anthropic/claude-sonnet-4.5
        alias: claude-sonnet-4.5
```

### Vercel AI Gateway

The Vercel AI Gateway fronts several model providers behind one endpoint. Its
model list is public.

```yaml
openai-compatibility:
  - name: vercel
    base-url: https://ai-gateway.vercel.sh/v1
    api-key-entries:
      - api-key: "your-vercel-key"
    models:
      - name: anthropic/claude-sonnet-4.5
        alias: claude-sonnet-4.5
```

## The model list rules

The configured list, after exclusions, is the fallback.

1. Discovery preserves configured rows, aliases and metadata even when the
   provider stops listing them. Provider exclusions take precedence over pins.
2. The latest successful live list contributes model IDs the configuration does
   not already name or reserve as public aliases. Live metadata is not imported;
   added models use their ID as both name and alias.
3. A model contributed only by discovery disappears when a later successful list
   omits it. Discovery never writes models back to the configuration file.
4. The merge is deterministic: configured models keep their order, and added live
   models follow in the order the provider reported them.

The first read runs in the background at startup, with refreshes every three
hours. Startup uses the configured fallback and never waits for a provider.
Each provider entry refreshes independently, with at most one read in flight.
A failed refresh, including an empty or invalid response, keeps the last known
good list for that entry. Live lists are held in memory, so a restart starts from
the configured fallback again. `--local-model` controls the separate model
metadata catalogs and does not disable these provider reads.

## Excluding a model

Set `excluded-models` on the `openai-compatibility` provider entry. It takes an
exact upstream model ID or a wildcard, matched without regard to case:

```yaml
excluded-models:
  - "some-model-to-hide"
  - "gemini-2.5-*"      # prefix
  - "*-preview"         # suffix
  - "*flash*"           # substring
```

The exclusion applies to configured and live models alike. For configured rows,
it matches the upstream `name` (or `alias` when no name is set), so excluding an
upstream also removes its configured aliases and its rows from shared alias
pools. Matching also checks the name with a thinking suffix such as `(high)`
removed. `"*"` excludes all models for that entry.

## Multiple keys

A provider can carry several keys. The proxy treats each key as its own credential
and rotates between them:

```yaml
openai-compatibility:
  - name: ollama-cloud
    base-url: https://ollama.com/v1
    api-key-entries:
      - api-key: "your-first-key"
      - api-key: "your-second-key"
```

Each key can carry its own `weight` and `proxy-url`.

Discovery uses the first nonempty API key and that key's `proxy-url`, falling back
to the global proxy. Its live list is shared by the entry's credentials. Changing
the entry's position, name, base URL, discovery key or effective proxy prevents
reuse of the old list; the configured fallback applies until the next successful
refresh for the new identity.

## Session-sticky round robin

When several providers expose the same model name, the fork routes **between the
providers equally** and then **within the provider's credentials**. A provider's
share of traffic does not scale with how many keys it owns.

```yaml
routing:
  strategy: round-robin
  session-affinity: true
  session-affinity-ttl: "1h"
```

`session-affinity` binds a session to the provider and credential it was first
served by, so a multi-turn conversation keeps its prompt cache warm. The binding is
scoped by the model and by the set of providers that were eligible, so turning a
provider on or off gives new sessions their own scope instead of reusing a binding
that points at a provider which is no longer eligible.

`session-affinity-ttl` is how long that binding is kept. The default is `1h`.

## The native exclusion key

This fork uses upstream's own `oauth-excluded-models` key directly. It lists the
models a provider must **not** serve:

```yaml
oauth-excluded-models:
  claude:
    - "claude-haiku-4-5"
  codex:
    - "gpt-4o-mini"
```

A `"*"` entry excludes every model for that provider.

## Where the configuration lives

- `config.example.yaml` — the full configuration reference.
- `examples/compatible-providers/config.yaml` — a working configuration for these
  providers, with placeholder keys and the routing defaults above.
- `config.yaml` in the repository root — the fork's own configuration, without
  credentials.
