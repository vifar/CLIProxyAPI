# Compatible providers: live model lists and a static fallback

This directory holds the static fallback configuration for the OpenAI-compatible
providers the proxy can read a live model list from, plus a test that keeps the
file valid.

## What the live model list does

For a provider with a supported live model list, the proxy reads the provider's own
model list in the background and adds the models the configuration does not mention.

- The models written in the configuration are **never removed**. An explicit pin
  stays exactly as written.
- A model listed in `excluded-models` is **never added**, so it does not come back
  from the provider.
- The live read runs in the background, so the proxy starts with the configured
  list and never waits for the provider. A failed refresh keeps the last known good
  list.
- A provider whose base URL is not one of the supported ones is never queried.

| Provider | Base URL | Live model list | Needs a key to read the list |
|---|---|---|---|
| Ollama Cloud | `https://ollama.com/v1` | `https://ollama.com/v1/models` | yes |
| OpenRouter | `https://openrouter.ai/api/v1` | `https://openrouter.ai/api/v1/models` | no |
| Vercel AI Gateway | `https://ai-gateway.vercel.sh/v1` | `https://ai-gateway.vercel.sh/v1/models` | no |

## Using it

`config.yaml` in this directory is the **offline floor**: with no network, or when
a provider cannot be read, the proxy serves exactly the models listed in it.

```sh
cp config.yaml ~/.cli-proxy-api/config.yaml
```

Then edit it: replace the placeholder API keys with your own, and remove the
providers you do not use. The file carries no credentials of its own.

The routing block in the file enables the session-sticky round robin defaults:
a session stays on the provider and credential it was bound to, and mixed routes
balance providers equally rather than in proportion to credential count.

## Excluding a model

`excluded-models` accepts an exact model ID or a wildcard:

```yaml
excluded-models:
  - "some-model-to-hide"
  - "gemini-2.5-*"      # prefix
  - "*-preview"         # suffix
  - "*flash*"           # substring
```

An excluded model is kept out of both the configured list and the live list.

## Checking the file

```sh
go test ./examples/compatible-providers/
```

The test parses the file with the real config loader and checks that every
documented provider is present with models and an API key entry.
