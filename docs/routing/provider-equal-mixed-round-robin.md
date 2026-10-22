# Provider-Equal Mixed Round Robin

## Behavior and Scope

When multiple enabled providers expose the same client-visible model name, built-in `round-robin` selects a provider first, then a credential within that provider. Credential counts do not affect provider share: two providers at the same available priority receive equal shares of unbound selections even when one owns multiple credentials.

Previously, mixed round robin weighted provider selection by ready credential count. Session affinity could then preserve that initial bias. Provider-equal selection now applies in the scheduler, the legacy mixed-selection path used for per-account model aliases, and the round-robin fallback used by session affinity.

This changes the traffic split for deployments with unequal credential counts across providers. Existing healthy session bindings are reused within their binding scope, so equal shares of new selections do not guarantee equal request volume across providers.

Single-provider routing, `fill-first`, and `weighted-round-robin` retain their existing selection policies. Mixed-route session bindings use the provider-set scope described below with any affinity fallback. Explicit routing overrides remain authoritative. Plugin-selected credentials and CLIProxyAPIHome dispatch retain their own scheduling policies; plugin delegation to built-in mixed round robin uses this policy.

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

Existing identity extraction, binding reuse, inheritance, TTL, and invalidation logic remain in place. A cold or rebound session uses the fallback to select a provider and credential. A request without a usable explicit or inferred session identity follows the fallback without storing a session binding.

For explicit session identities, the binding key is:

```text
route namespace :: session identity :: canonical model -> auth ID
```

Mixed routes use `mixed[<canonical provider set>]` as their namespace. Provider keys are normalized, deduplicated, sorted, then individually percent-encoded before comma-joining, so provider order does not change the scope. Encoding prevents delimiters in a provider name from changing the scope structure: a provider named `a,b` has a different scope from providers `a` and `b`. The set comes from the resolved route providers, not just credentials ready at the winning priority. The auth ID identifies both provider and credential, and a cached credential is still checked against current candidates before reuse.

Changing the route's provider set creates a distinct binding scope even if the previously bound credential remains eligible. Returning to an earlier set can reuse its binding if it is still live and eligible. Single-provider routes keep their plain provider namespace. Longest-common-prefix (LCP) affinity for requests without an explicit session uses the same provider-set scope, in addition to its model and caller scope; selection, successful binding updates, and failure eviction use that same namespace.

Affinity lookup observes scoped mixed bindings without selecting a credential or refreshing TTL. Because lookup accepts no provider set, explicit-session lookup considers matching session/model bindings across mixed scopes and returns `ambiguous` if they identify different credentials after any caller-supplied auth filtering. Lookup validates the complete namespace head before accepting a session/model suffix, rejecting cross-session matches from identifiers containing key separators. Scope syntax is recognized only for the mixed namespace; brackets in a plain provider name remain part of that name.

### Failover and provider-set changes

An unavailable bound credential triggers fallback selection across eligible providers. There is no guarantee that another credential in the same provider is tried before crossing providers. Rebinding follows the existing `session-affinity-rebind-on` policy; see the `routing` settings in [config.example.yaml](../../config.example.yaml).

Existing retryable-status, cooldown, priority, model-support, and streaming retry boundaries remain authoritative. Provider-equal selection does not add replay after streamed output begins. Invalid client requests retain their existing non-retryable handling.

A recovered credential can participate in new selections without preempting an existing healthy session binding within the same scope. Temporary cooldowns and tried-credential filtering do not themselves change the route's provider set. Adding or removing a route provider follows the binding-scope rules above.

## Configuration

Provider-equal mixed selection is part of `round-robin`; no `provider-first` switch or new strategy is required. For the fork's shipped configuration and session-sticky defaults, see [Fork configuration](../../README.md#fork-configuration). Other configurations must explicitly enable session affinity; omitting the setting leaves it off.

The `routing` block in [config.example.yaml](../../config.example.yaml) owns the loader defaults and remaining session-affinity settings. Plain model names remain the client contract; provider prefixes and duplicated aliases are not required to obtain equal provider selection. Unique provider aliases continue to route through one provider.

## Implementation and Verification

The implementation is in [scheduler.go](../../sdk/cliproxy/auth/scheduler.go) for the scheduler path and [selector_provider_equal.go](../../sdk/cliproxy/auth/selector_provider_equal.go) for legacy mixed selection. [conductor_selection.go](../../sdk/cliproxy/auth/conductor_selection.go) installs and reuses the mixed selector. [selector.go](../../sdk/cliproxy/auth/selector.go) retains the session-affinity binding logic.

Regression coverage is split by behavior:

- [scheduler_provider_equal_test.go](../../sdk/cliproxy/auth/scheduler_provider_equal_test.go): unequal credential counts, provider/model cursor scoping, canonical provider order, priority exclusion, and fill-first provider ordering.
- [selector_provider_equal_test.go](../../sdk/cliproxy/auth/selector_provider_equal_test.go): legacy provider equality, provider-equal affinity fallback, and preservation of other strategies.
- [selector_provider_equal_manager_test.go](../../sdk/cliproxy/auth/selector_provider_equal_manager_test.go): manager-owned selector lifetime and preservation of weighted and fill-first affinity fallbacks.
- [session_affinity_provider_set_test.go](../../sdk/cliproxy/auth/session_affinity_provider_set_test.go): canonical provider-set namespaces, scoped mixed bindings and lookup, rejection of cross-session lookup matches from crafted session identifiers, and consistent LCP namespace construction and parsing.
- [provider_set_scope_encoding_test.go](../../sdk/cliproxy/auth/provider_set_scope_encoding_test.go): distinct scopes for delimiter-containing provider names, structural-character encoding, preservation of brackets in plain provider names, and stable LCP namespaces for already-scoped providers.

### Live smoke test

With two providers enabled at the same priority and exposing the same alias, enable session affinity and:

1. Confirm the model catalog lists the alias once.
2. Send requests under two distinct session IDs and observe different providers.
3. Repeat each session and observe the same credential.
4. Remove one provider from the route and confirm subsequent requests use the remaining provider without reusing the old mixed-route binding.
5. Restore the original provider set and confirm new sessions distribute across both providers. A session may reuse its original binding if it is still live and eligible; it need not retain the credential selected while the provider was absent.

Establish selected providers from existing debug logs or routing metadata, not response wording. This is a manual verification procedure, not a claim that a live smoke test has run.

## Deferred Design Work

Dedicated routing-transition events or Prometheus counters are not implemented by this change. Existing session-affinity logs remain available. Same-provider-first failover is also not part of the delivered policy. These extensions would require separate changes; the regression files above do not claim to verify them.
