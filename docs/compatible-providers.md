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

Discovery recognizes these HTTPS hostnames, regardless of the configured base
URL path, and reads the fixed model-list endpoint shown above. URLs with userinfo,
an explicit port, a query or a fragment are not eligible. Other hosts and disabled
entries are never queried; their configured models are not supplemented by live
discovery.

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

The shipped configuration pins `deepseek-v4.1-flash`, `deepseek-v4-flash` and
`deepseek-v4-pro`. The alias is what a client asks for; the name is what the
upstream serves. Keeping them separate is what lets
a model be renamed upstream without breaking a client's alias.

**Kimi K3** is one of the provider's models and is listed in the fork's
configuration, so it is available after enabling the provider and adding a key,
unless excluded, whether or not the live list has been read yet.

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

The configured list is the fallback, subject to the provider's exclusions.

1. Live discovery never removes a configured pin or changes its alias or metadata.
   Provider exclusions still override pins when publishing and routing models.
2. An excluded upstream model is filtered from configured and discovered rows.
3. The current live list adds models the configuration does not mention. Models
   contributed only by discovery disappear after a successful refresh omits them.
   Configured names and public aliases are reserved, so discovery cannot replace
   an alias with a different upstream model. Live rows contribute IDs only; set
   capability metadata explicitly in configuration when needed.
4. The merge is deterministic: configured models keep their order, and added live
   models follow in the order the provider reported them.

The live read runs in the background. The proxy starts with the configured list and
never waits for a provider, so an unreachable provider cannot stop it becoming
ready. Refreshes run at startup and every three hours, independently for each
eligible entry, with at most one read in progress per entry. A failed refresh,
including an empty list, keeps the last known good list in memory. Restarting
starts again from the configured pins; discovered rows are never written to the
configuration. Changing an entry's position, name, base URL, discovery key or
proxy invalidates reuse of its previous list.

This discovery runs independently of `models.catalog` and `--local-model`; those
settings control the separate model metadata catalogs.

## Excluding a model

Set `excluded-models` on the compatible-provider entry; see
[config.example.yaml](../config.example.yaml) for the pattern syntax. Matching is
case-insensitive and checks the upstream `name` (falling back to `alias` when
the name is empty), both as written and without a thinking suffix such as
`(high)`. For configured rows, excluding an upstream also removes its aliases
from publication and routing; an alias whose text matches an exclusion does not
block an otherwise allowed upstream. In a shared alias pool, allowed upstreams
remain eligible. These rules also apply to providers without live discovery.

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

Discovery uses the first non-empty API key in the entry, with that key's
`proxy-url` overriding the global proxy. The resulting list is shared by the
entry's credentials. Public lists can be read without a key; routing still needs
one. Redirects are not followed, so discovery does not forward a key to another
origin.

## Session-sticky round robin

See the [routing guide](routing/provider-equal-mixed-round-robin.md) for provider
selection, session binding scope and failover, and
[Fork configuration](../README.md#fork-configuration) for the shipped defaults.

## The native exclusion key

Native OAuth/file-backed exclusions use a separate setting; see
[Fork configuration](../README.md#fork-configuration) and the OAuth exclusion
rules in [config.example.yaml](../config.example.yaml).

## Where the configuration lives

- [config.example.yaml](../config.example.yaml) — the full configuration reference.
- `examples/compatible-providers/config.yaml` — a working configuration for these
  providers, with placeholder keys; see its [README](../examples/compatible-providers/README.md)
  for setup.
- `config.yaml` in the repository root — the fork's starting configuration, with
  providers disabled and no credentials; follow
  [Fork configuration](../README.md#fork-configuration) to enable them.
