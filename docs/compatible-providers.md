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

A provider whose base URL is not one of these is never queried. It keeps exactly
the model list written in the configuration.

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

**DeepSeek V4 Flash is the stable default.** `deepseek-v4.1-flash` is the alias the
fork's own configuration serves first, and the live list adds the newer
`deepseek-v4-flash` and `deepseek-v4-pro` beside it. The alias is what a client
asks for; the name is what the upstream serves. Keeping them separate is what lets
a model be renamed upstream without breaking a client's alias.

**Kimi K3** is one of the provider's models and is listed in the fork's
configuration, so it is served whether or not the live list has been read yet.

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

The configured list is always the floor.

1. A model written in the configuration is **never removed**. An explicit pin
   keeps its alias and its metadata.
2. A model listed in `excluded-models` is **never added**, so a model removed on
   purpose does not come back from the provider.
3. The live list only **adds** models the configuration does not mention.
4. The merge is deterministic: configured models keep their order, and added live
   models follow in the order the provider reported them.

The live read runs in the background. The proxy starts with the configured list and
never waits for a provider, so an unreachable provider cannot stop it becoming
ready. A failed refresh keeps the last known good list.

## Excluding a model

`excluded-models` takes an exact model ID or a wildcard:

```yaml
excluded-models:
  - "some-model-to-hide"
  - "gemini-2.5-*"      # prefix
  - "*-preview"         # suffix
  - "*flash*"           # substring
```

The exclusion applies to the configured list and to the live list alike.

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

- `config.example.yaml` — the upstream reference, with every key documented.
- `examples/compatible-providers/config.yaml` — a working configuration for these
  providers, with placeholder keys and the routing defaults above.
- `config.yaml` in the repository root — the fork's own configuration, without
  credentials.
