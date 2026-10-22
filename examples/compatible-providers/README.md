# Compatible providers: live model lists and a static fallback

This directory holds the static fallback configuration for the OpenAI-compatible
providers the proxy can read a live model list from, plus a test that keeps the
file valid.

See the [compatible-provider guide](../../docs/compatible-providers.md) for
supported providers, live refresh and fallback behavior, and exclusions.

## Using it

Follow [Fork configuration](../../README.md#fork-configuration) for private
deployment setup and startup, using this directory's `config.yaml` as the source
instead of the root file. This example has enabled providers with placeholder
keys: replace the keys and remove or disable providers you do not use. Its
configured models provide the initial fallback described in the guide.

For the routing block's behavior, see the
[routing guide](../../docs/routing/provider-equal-mixed-round-robin.md).

## Checking the file

```sh
go test ./examples/compatible-providers/
```

The test parses the file with the real config loader and checks that every
documented provider is present with models and an API key entry.
