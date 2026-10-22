# Provider-Equal Mixed Round Robin

## Behavior and Scope

When multiple enabled providers expose the same client-visible model name, built-in `round-robin` selects a provider first, then a credential within that provider. Credential counts do not affect provider share: two providers at the same available priority receive equal shares of unbound selections even when one owns multiple credentials.

Previously, mixed round robin weighted provider selection by ready credential count. Session affinity could then preserve that initial bias. Provider-equal selection now applies in the scheduler, the legacy mixed-selection path used for per-account model aliases, and the round-robin fallback used by session affinity.

This changes the traffic split for deployments with unequal credential counts across providers. Existing healthy session bindings are reused, so equal shares of new selections do not guarantee equal request volume across providers.

Single-provider routing, `fill-first`, and `weighted-round-robin` retain their existing semantics. Explicit routing overrides remain authoritative. Plugin-selected credentials and CLIProxyAPIHome dispatch retain their own scheduling policies; plugin delegation to built-in mixed round robin uses this policy.

## Routing Semantics

### Eligibility and priority

Resolve providers for the requested model and apply existing executor availability, model support, disabled state, cooldown, request eligibility, and tried-credential filtering.

For an unbound selection, only credentials at the highest available priority tier participate. Providers without a ready credential at that tier remain excluded until higher-priority candidates become unavailable. An existing session binding can still reuse a healthy credential at a lower priority.

### Provider selection

Normalize and sort provider keys to give the provider ring a stable order. Requests whose provider lists differ only in order share a cursor scope for the same canonical model. The canonical model removes the thinking suffix.

The scheduler keys its provider cursor by the canonical resolved provider set and model, then rotates only among providers with ready credentials at the winning priority. The legacy provider-equal selector derives its provider set from the available candidates and also includes the route namespace in its key. Availability changes can therefore change the legacy cursor scope even when the resolved route stays the same.

Provider and credential cursors are held in memory. The legacy mixed selector is retained by the manager for the lifetime of the configured selector, so consecutive requests advance its rotation rather than restarting it.

### Credential selection

After selecting a provider, the scheduler selects from that provider's model shard. The legacy selector rotates credentials in stable auth-ID order within the selected provider.

Credential rotation is scoped by provider and canonical model. Traffic for one provider/model pair does not advance another pair's cursor: requests for `deepseek-v4-pro` do not advance `glm-5.2`, and OpenCode Go credentials do not advance Ollama Cloud credentials.

### Session affinity

With session affinity enabled, only its round-robin fallback is replaced by provider-equal selection. Weighted and fill-first fallbacks keep their own behavior, including positive-weight filtering for weighted routing.

Existing identity extraction, binding reuse, inheritance, TTL, and invalidation logic remain in place. A cold or rebound session uses the fallback to select a provider and credential. A request without a usable session identity follows the fallback without storing a session binding.

For explicit session identities, the binding key remains:

```text
route namespace + session identity + canonical model -> auth ID
```

Mixed routes use the literal namespace `mixed`. The auth ID identifies both provider and credential. The binding key does **not** include the canonical provider set. A cached credential is checked against current candidates before reuse; changing the provider set does not by itself create a new binding scope.

### Failover and provider-set changes

An unavailable bound credential triggers fallback selection across eligible providers. There is no guarantee that another credential in the same provider is tried before crossing providers. Rebinding follows the existing `session-affinity-rebind-on` policy; see the `routing` settings in [config.example.yaml](../../config.example.yaml).

Existing retryable-status, cooldown, priority, model-support, and streaming retry boundaries remain authoritative. Provider-equal selection does not add replay after streamed output begins. Invalid client requests retain their existing non-retryable handling.

A recovered provider can participate in new selections without preempting an existing healthy session binding. Removing a provider prevents its credentials from being reused when they are no longer candidates for the route.

## Configuration

Provider-equal mixed selection is part of `round-robin`; no `provider-first` switch or new strategy is required. For the fork's shipped configuration and session-sticky defaults, see [Fork configuration](../../README.md#fork-configuration). Other configurations must explicitly enable session affinity; omitting the setting leaves it off.

The `routing` block in [config.example.yaml](../../config.example.yaml) owns the loader defaults and remaining session-affinity settings. Plain model names remain the client contract; provider prefixes and duplicated aliases are not required to obtain equal provider selection. Unique provider aliases continue to route through one provider.

## Implementation and Verification

The implementation is in [scheduler.go](../../sdk/cliproxy/auth/scheduler.go) for the scheduler path and [selector_provider_equal.go](../../sdk/cliproxy/auth/selector_provider_equal.go) for legacy mixed selection. [conductor_selection.go](../../sdk/cliproxy/auth/conductor_selection.go) installs and reuses the mixed selector. [selector.go](../../sdk/cliproxy/auth/selector.go) retains the session-affinity binding logic.

Regression coverage is split by behavior:

- [scheduler_provider_equal_test.go](../../sdk/cliproxy/auth/scheduler_provider_equal_test.go): unequal credential counts, provider/model cursor scoping, canonical provider order, priority exclusion, and fill-first provider ordering.
- [selector_provider_equal_test.go](../../sdk/cliproxy/auth/selector_provider_equal_test.go): legacy provider equality, provider-equal affinity fallback, and preservation of other strategies.
- [selector_provider_equal_manager_test.go](../../sdk/cliproxy/auth/selector_provider_equal_manager_test.go): manager-owned selector lifetime and preservation of weighted and fill-first affinity fallbacks.

### Live smoke test

With two providers enabled at the same priority and exposing the same alias, enable session affinity and:

1. Confirm the model catalog lists the alias once.
2. Send requests under two distinct session IDs and observe different providers.
3. Repeat each session and observe the same credential.
4. Disable one provider and confirm subsequent requests can use the remaining provider under the configured retry and rebinding rules.
5. Re-enable it and confirm new sessions distribute across both providers while existing healthy bindings remain stable.

Inspect binding decisions through the [routing transition API](../management-api-v8.md#routing-transitions). Use debug logs or routing metadata for the provider that actually served a request when a binding is preserved during temporary fallback. This is a manual verification procedure, not a claim that a live smoke test has run.

## Deferred Design Work

Provider-set-scoped affinity keys and same-provider-first failover remain deferred. Routing transition observability is documented in the [v8 Management API reference](../management-api-v8.md#routing-transitions); the regression files above cover provider-equal selection.
