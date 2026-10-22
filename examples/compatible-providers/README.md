# Compatible providers: live model lists and a static fallback

This directory holds the static fallback configuration for the OpenAI-compatible
providers the proxy can read a live model list from, plus a test that keeps the
file valid.

See the [compatible-provider guide](../../docs/compatible-providers.md) for
supported endpoints, discovery and fallback rules, and
[provider exclusions](../../docs/compatible-providers.md#excluding-a-model).

## Using it

`config.yaml` in this directory supplies the configured fallback models.

```sh
cp config.yaml ~/.cli-proxy-api/config.yaml
```

Then edit it: replace the placeholder API keys with your own, and remove the
providers you do not use. The file carries no credentials of its own.

The routing block in the file enables the session-sticky round robin defaults:
a session stays on the provider and credential it was bound to, and mixed routes
balance providers equally rather than in proportion to credential count.

## Checking the file

```sh
go test ./examples/compatible-providers/
```

The test parses the file with the real config loader and checks that every
documented provider is present with models and an API key entry.
