# Provider- and Model-Scoped Session Routing Design

## Goal

When multiple enabled providers expose the same client-visible model name, distribute new sessions evenly across those providers, keep each session on its selected provider and credential for that model, and fail over before output when the selected route becomes unavailable.

This policy is the default for every round-robin route. It is not specific to OpenCode Go and Ollama Cloud.

## Root Cause

CLIProxyAPI resolves a colliding model to multiple providers, but mixed-provider round robin currently flattens every eligible credential into one pool. Provider traffic therefore scales with credential count. A provider with two credentials receives twice the traffic of a provider with one credential.

Session affinity then preserves the selected credential, including the initial credential-count bias. It does not model equal provider selection followed by provider-local credential selection.

The root fix belongs in CLIProxyAPI's mixed-provider scheduler. Prefixes, duplicated aliases, or an application-side wrapper would hide the collision rather than define correct scheduling semantics.

## Scope

### In scope

- Equal round-robin selection among eligible providers for a requested model.
- Independent credential round robin inside the selected provider/model shard.
- Session affinity scoped by provider set, model, and session.
- Automatic failover before response output begins.
- Independent state for every provider/model pair.
- Documented deployment defaults enabling session-sticky round robin.
- Preservation of explicit user routing overrides.

### Out of scope

- Weighted provider distribution.
- Replaying a request after streamed output begins.
- Reintroducing provider prefixes such as `oc-`.
- Changing provider credentials, subscription state, or enablement.
- Replacing CLIProxyAPI with another proxy layer.

## Routing Semantics

### Eligibility and priority

For each requested model, resolve enabled providers that have at least one ready credential supporting the model. Apply existing auth eligibility, executor availability, model support, disabled state, cooldown, and priority filtering before provider rotation.

For each provider, its current provider priority is the highest ready credential priority for that model. Only providers at the highest available priority tier participate in equal round robin. Lower-priority providers remain failover candidates only when the higher tier becomes unavailable under existing priority rules.

### Provider selection

Canonicalize the eligible provider set by sorting normalized provider keys. Use the same canonical order for the provider ring and its state key:

```text
canonical model + canonical eligible provider set
```

Credential counts do not affect provider share. With two eligible providers, new unbound sessions alternate providers 1:1 even when one provider owns multiple credentials.

### Credential selection

After selecting a provider, select a credential only from that provider's scheduler shard for the canonical model.

Credential round-robin state remains scoped by:

```text
provider + canonical model
```

Traffic for one provider/model pair cannot advance another pair's cursor. Requests for `deepseek-v4-pro` cannot advance `glm-5.2`, and OpenCode Go credentials cannot advance Ollama Cloud credentials.

### Session affinity

Mixed-route session affinity uses one authoritative binding:

```text
session identity + canonical model + canonical eligible provider set -> auth ID
```

The auth ID identifies both the selected provider and credential. This avoids maintaining a second provider cache that could drift from live scheduler state.

A new session advances the provider cursor, selects a credential inside that provider/model shard, and stores the binding. Later requests reuse the bound auth while its provider and credential remain eligible for that model and provider set.

A request without a usable session identity follows provider and credential round robin without storing affinity state.

Use the existing session identity extraction order, including Claude Code, Codex, OpenCode, pi, request-body identifiers, execution metadata, and message-hash fallback.

### Failover

If the bound credential becomes unavailable, try another eligible credential in the same provider/model shard first.

If that provider has no eligible credential for the model, advance to the next healthy provider, select a credential from its provider/model shard, and replace the binding after a successful selection.

Failover is allowed only before output begins. For streaming requests, errors after the first emitted byte are propagated without replay.

Invalid client requests do not trigger failover or rebinding. Existing retryable status, cooldown, priority, and model-support rules remain authoritative.

### Provider-set changes

The affinity and provider-cursor keys include the canonical eligible provider set. Enabling or disabling a provider creates a distinct routing scope, preventing an old binding from targeting a provider outside the current set.

A recovered provider becomes eligible for new sessions. It does not preempt an existing healthy session binding.

## Configuration

Do not add a `provider-first` boolean. Provider-first mixed routing becomes the definition of `round-robin`; this prevents ambiguous combinations with fill-first, weighted round robin, and session affinity.

A deployment that wants session-sticky provider-equal routing sets:

```yaml
routing:
  strategy: round-robin
  session-affinity: true
  session-affinity-ttl: 1h
```

Single-provider routes keep their existing provider/model credential behavior. Fill-first and weighted-round-robin retain their existing semantics unless separately designed later.

If backward compatibility with credential-flattened mixed round robin is required, introduce a fully named versioned strategy rather than a boolean. The preferred outcome remains corrected `round-robin` semantics.

## Components

### CLIProxyAPI mixed-provider scheduler

Extend mixed-provider round robin so it:

- maintains provider cursors per canonical model and canonical provider set;
- selects a provider before selecting a credential;
- delegates credential selection to the selected provider/model shard;
- validates affinity bindings against live eligibility;
- rebinds after credential or provider exhaustion;
- preserves existing priority, cooldown, and retry behavior.

Provider selection must never flatten credentials across providers.

### CLIProxyAPI affinity cache

Reuse the current session identity extraction, TTL, and auth-ID invalidation. Generalize the mixed-route cache key to include the canonical provider set and canonical model.

Do not copy provider eligibility into the affinity cache. Validate the bound auth against live scheduler state on every use. The scheduler remains authoritative.

### Deployment configuration

No new configuration key is required. A deployment opts in through the existing `routing` block shown above.

### Verification

The Go test suite proves the scheduler and affinity behavior directly:

- `sdk/cliproxy/auth/scheduler_provider_equal_test.go` covers equal provider share, cursor scoping, canonical provider sets, and priority-tier exclusion;
- `sdk/cliproxy/auth/selector_test.go` and the session-affinity tests cover binding creation, reuse, and rebinding.

## Error Handling

- No eligible provider: return the existing auth-not-found, unavailable, or cooldown error.
- Every provider cooling down: report the earliest recoverable cooldown across the eligible provider set.
- Invalid request: stop immediately without cursor advancement or rebinding.
- Retryable failure before output: try remaining credentials in the selected provider, then remaining providers.
- Failure after streamed output: propagate without replay.
- Non-round-robin strategy: retain that strategy's existing behavior.

## Observability

Each significant routing transition must use CLIProxyAPI's authoritative event/hook surface and increment a Prometheus-compatible counter:

- provider binding created;
- provider/credential binding hit;
- credential reselected inside a provider;
- provider failover and binding replaced;
- no eligible provider.

Structured logs accompany these transitions and include the requested model, provider key, transition outcome, and a truncated or opaque session identifier. They never include API keys or prompt contents.

Do not add a shadow cache, polling loop, or duplicated provider state.

## Verification

### Go tests

The suite proves:

1. Two providers with unequal credential counts alternate providers 1:1 for one model.
2. Credential selection rotates independently inside each provider/model shard.
3. Different models have independent provider and credential cursors.
4. Different eligible provider sets have independent provider cursors and bindings.
5. New sessions alternate providers while repeated requests remain sticky.
6. A failed credential reselects inside the same provider before crossing providers.
7. An exhausted provider fails over and rebinds the session.
8. A recovered provider receives new sessions without preempting healthy bindings.
9. No-session requests round-robin without creating affinity state.
10. Streaming bootstrap failures can fail over; post-first-byte failures cannot.
11. A provider with lower-priority credentials does not participate while a higher priority tier is healthy.
12. Provider ordering differences representing the same set share one cursor and affinity scope.
13. Routing transitions emit the expected event and increment the corresponding counter exactly once.

### Live smoke test

With two OpenAI-compatible providers enabled and exposing the same alias:

1. Confirm the model catalog lists the alias once.
2. Send requests under two distinct session IDs and observe different providers.
3. Repeat each session and observe the same provider.
4. Disable one provider and observe both sessions succeed through the remaining provider.
5. Re-enable it and confirm new sessions distribute across both providers while existing healthy bindings remain stable.

Establish selected providers from structured debug logs or routing metadata, not response wording.

## Rollout and Compatibility

- Plain model names remain the client contract.
- Unique provider aliases continue to route through one provider.
- Single-provider deployments retain existing provider/model behavior.
- `fill-first` and `weighted-round-robin` are unchanged.
- **Behavior change:** a deployment that relies on mixed round robin across providers with *unequal credential counts* sees the traffic split become equal per provider instead of proportional to credential count. This is the intended correction.

## Baseline Limitation

This change is limited to the Go scheduler. The provider-set-scoped session affinity key and the routing transition observability described above are separate changes; until they land, session affinity on a mixed route is still keyed per provider rather than per provider set.
