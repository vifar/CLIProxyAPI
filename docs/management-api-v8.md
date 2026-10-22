# v8 Management API

The base path is `/v8/management`. Configuration endpoints follow the structure in
[config.example.yaml](../config.example.yaml); operational endpoints are grouped
by function. The existing `/v0/management` API remains supported. Its reference is
available in the [management API guide](https://help.router-for.me/management/api).

## Access

The v8 endpoints use the same management key and remote-access policy as v0.
Send `Authorization: Bearer <management-key>` or `X-Management-Key: <management-key>`.
OAuth callbacks validate a pending login state and do not require a management-key
header. Home mode disables local management endpoints for both versions.

## Configuration endpoints

All paths below are relative to `/v8/management`.

| Path | Methods | Description |
| --- | --- | --- |
| `/config` | GET, PUT, PATCH | Read, replace, or merge the complete configuration as JSON. |
| `/config.yaml` | GET, PUT | Read or replace the complete configuration as YAML. |
| `/config/<section>/<field>` | GET, PUT, PATCH, DELETE | Read or modify a section or field using its path in the v8 tree. |

GET renders the persisted configuration in the v8 layout without migrating the
file or adding omitted runtime defaults. Successful v8 configuration writes save
the latest layout; reads and rejected writes leave the file unchanged.
Historical v8 paths and request bodies remain accepted as aliases.

JSON writes accept the value directly, without a `{ "value": ... }` envelope.
PUT replaces its target. PATCH merges objects and replaces lists and scalars.
Scalar field updates retain existing comments; complete replacements use the submitted document.
DELETE removes a field. Paths identify mapping keys, not array indexes; replace
an entire list to change its entries. Optional per-key `null` overrides inherit
the corresponding group value. Legacy field names are rejected by v8 writes.

| Example path | Value or purpose |
| --- | --- |
| `/config/access/api-keys` | Client authentication keys, for example `["client-key"]`. |
| `/config/api-keys` | All upstream provider groups. |
| `/config/api-keys/codex` | Codex upstream groups. |
| `/config/client/codex/optimize-multi-agent-v2` | Boolean, default `false`; applies to Codex clients across OAuth and API-key routes. |
| `/config/observability/logs/debug` | A boolean, for example `true`. |
| `/config/routing/retry/request-retry` | A number, for example `0`. |
| `/config/plugins/configs/<id>` | A plugin configuration object. |

For example, `PATCH /v8/management/config` with this body disables additional
request retries while preserving other settings:

```json
{
  "routing": {
    "retry": {
      "request-retry": 0
    }
  }
}
```

JSON reads omit TURN usernames and credentials under
`oauth.providers.codex.live-media-relay.ice-servers`; YAML reads include them.
The Home-owned revision fields
`credentials.concurrency.lifecycle-config-revision`,
`credentials.concurrency.observation-barrier-revision`, and `plugins.auth-revision`
cannot be changed through these endpoints.

### Codex multi-agent configuration migration

`client.codex.optimize-multi-agent-v2` is the sole runtime setting. Loading older
YAML accepts `providers.codex.optimize-multi-agent-v2`,
`oauth.providers.codex.optimize-multi-agent-v2`, and the flat
`codex.optimize-multi-agent-v2` path. The client path always wins conflicts,
including explicit `false` or `null`. If it is absent, the historical OAuth path
wins over `providers`, which wins over the flat path.

These aliases now have client-wide semantics, not OAuth-only scope. Loading does
not rewrite legacy-only settings; normalization removes aliases conflicting with
the client path. A successful v8 write migrates the aliases while preserving their
comments. Historical API paths remain usable. Home configuration publishers
need matching client schema support before emitting the new path; older YAML
payloads remain readable.

## Operational endpoints

All paths below are relative to `/v8/management`. Request and response bodies
retain the corresponding business operation's fields.

| Path | Methods | Description |
| --- | --- | --- |
| `/config/upstream/<provider>` | GET, PUT, PATCH, DELETE | Manage shared provider settings. |
| `/server/latest-version` | GET | Get latest release information. |
| `/requests/api-call` | POST | Make an authenticated upstream call. |
| `/routing/cooldown/reset` | POST | Clear credential cooldown. |
| `/routing/model-definitions/<channel>` | GET | Get model definitions. |
| `/observability/logs` | GET, DELETE | Read or clear application logs. |
| `/observability/logs/errors` | GET | List error-log files. |
| `/observability/logs/errors/<name>` | GET | Download an error-log file. |
| `/observability/logs/requests/<id>` | GET | Get a request log. |
| `/observability/usage/api-keys` | GET | Get API-key usage. |
| `/observability/usage/queue` | GET | Get queued usage events. |
| `/observability/usage/compatible-providers` | GET | [List compatible-provider credentials](#compatible-provider-usage-meters). |
| `/observability/usage/compatible-providers/<id>` | GET | [Read a provider usage meter](#compatible-provider-usage-meters). |
| `/observability/routing/transitions` | GET | [Read routing transition counters and recent events](#routing-transitions). |
| `/credentials` | GET, POST, DELETE | List, upload, or delete credential files. |
| `/credentials/models` | GET | Get credential models. |
| `/credentials/download` | GET | Download a credential file. |
| `/credentials/status` | PATCH | Change credential status. |
| `/credentials/fields` | PATCH | Change credential fields. |
| `/credentials/refresh` | POST | Refresh credentials. |
| `/oauth/import?provider=vertex` | POST | Import a Vertex service account using a multipart `file` upload. |
| `/oauth/auth-url?provider=<provider>` | GET | Start built-in or plugin OAuth. |
| `/oauth/siwc/bind` | POST | Start SIWC binding to an existing file-backed Codex OAuth credential. |
| `/oauth/status?state=<state>` | GET | Get login status. |
| `/oauth/session?state=<state>` | DELETE | Cancel a login session. |
| `/oauth/callback` | GET, POST | Submit an OAuth callback. |
| `/plugins` | GET | List installed plugins. |
| `/plugins/<id>` | DELETE | Delete a plugin. |
| `/plugins/store` | GET | List the plugin store. |
| `/plugins/store/<id>/install` | POST | Install or update a plugin. |
| `/plugins/<id>/quota` | GET, POST, DELETE | Read, fetch, or reset plugin quota. |

### Routing transitions

`GET /observability/routing/transitions` returns HTTP `200` with one consistent
snapshot containing:

| Field | Meaning |
| --- | --- |
| `counters` | Rows with `transition`, `model`, `provider`, and `count`, grouped by those first three fields. |
| `totals` | Counts keyed by transition; each equals the sum of its counter rows. Transitions with no recorded events are omitted. |
| `events` | The most recent events, oldest first, up to 200 in the standard service. |

Each event includes `transition` and `model`, with optional `provider`,
`previous_provider`, and `session`. Provider values are executor provider keys.
`previous_provider` identifies the replaced binding's provider when known.
`session` is an opaque correlation identifier: values longer than 20 bytes are
shortened to an eight-byte prefix, `...`, and an eight-character digest of the
complete identifier. Credential IDs, API keys, tokens, and prompt contents are
not included as event fields.

| `transition` | Meaning |
| --- | --- |
| `binding_created` | A new session binding is established, including a child's or fork's first binding when it inherits a parent's credential. |
| `binding_hit` | An existing binding is reused or preserved. |
| `credential_reselected` | A failed or unavailable binding is replaced within the same provider. |
| `provider_failover` | A binding is replaced with one belonging to a different provider; this does not imply all credentials in the previous provider were exhausted. |
| `no_eligible_provider` | Mixed-provider selection returned an error. Provider and session fields are absent. |

These describe binding selections, not completed requests or upstream success.
Retries can contribute additional events. Under `session-affinity-rebind-on: quota`,
a temporary fallback that preserves the original binding is a
`binding_hit`; its `provider` names the preserved binding's provider, even when
another provider serves that request. See the [routing guide](routing/provider-equal-mixed-round-robin.md#failover-and-provider-set-changes)
for selection and rebinding policy.

Binding events come from the built-in session-affinity selector, covering
explicit identities and inferred conversation-prefix (LCP) bindings. Selections
without a session binding do not emit binding events. Mixed-provider selection
errors are counted independently of affinity, including scheduler, plugin, and
Home dispatch paths; Home's local management access restriction still applies.

The standard service installs a process-wide, in-memory recorder on startup.
Counters last for that recorder's lifetime and reset on restart; there is no
persistence or Prometheus exporter. Model and provider names are trimmed and
limited to 128 bytes. Counter cardinality is limited to 256 distinct nonempty
model names and 64 provider names; further names count under `<overflow>` while
totals remain exact. Recent events retain their bounded names rather than the
overflow labels. With no recorder installed, the endpoint returns
`{"counters":[],"totals":{},"events":[]}`. This endpoint has no v0 equivalent.

### Compatible-provider usage meters

These endpoints read provider-reported allowances and balances for configured
OpenAI-compatible API keys. They do not aggregate proxy request statistics and
have no `/v0/management` equivalent. The access policy above applies.

`GET /observability/usage/compatible-providers` returns
`{"credentials":[...]}` without contacting upstream providers. It includes every
nonempty configured key in configuration order, including disabled and
unsupported entries. Each credential contains:

| Field | Meaning |
| --- | --- |
| `id` | Opaque identifier for detail requests; never contains the API key. |
| `provider_name` | Configured provider name. |
| `key_number` | One-based key position within its provider entry. |
| `enabled` | Whether the provider entry is enabled. |
| `supported` | Whether its base URL matches a supported meter adapter. |
| `scope` | `account` for Ollama Cloud, `key` for OpenRouter; defaults to `account` for unsupported entries. |

Use IDs from the current list. They are stable for unchanged credentials within
one process, but change on key rotation, provider name or base URL changes,
provider/key position changes, and server restart.

Supported base URLs use HTTPS, with no userinfo, explicit port, query, or fragment.
Trailing slashes are accepted. Support is determined by the URL, regardless of
the configured provider name:

| Host | Accepted paths | Meter request | Reported data, when available |
| --- | --- | --- | --- |
| `ollama.com` | Empty or `/v1` | `https://ollama.com/api/balance` | Account-wide `session`, `weekly`, and `monthly` windows when reported, or an `included` allowance window; `purchased_remaining` and `included_remaining` balances. |
| `openrouter.ai` | Empty, `/api`, or `/api/v1` | `https://openrouter.ai/api/v1/key` | `key_budget` window when a positive key limit and remaining amount exist; `key_remaining` and `key_spent` balances. |

Meter requests send the selected API key only to the fixed provider endpoint and
do not follow redirects. They use the per-key proxy when configured, otherwise
the global proxy. Management responses omit API keys and upstream error bodies.

`GET /observability/usage/compatible-providers/<id>` returns `credential` with the
fields above, `status`, and the arrays `windows` and `balances` (empty when no
values are available). Windows contain `id`, `used_percent`, `remaining_percent`,
and optional `reset_at` in UTC RFC3339. Percentages are bounded to 0–100. Balances
contain `id`, numeric `amount`, and `currency` (`USD`). A decoded upstream response
also includes `fetched_at` in UTC RFC3339; cached responses retain that timestamp.

| `status` | Meaning |
| --- | --- |
| `success` | At least one window or balance was read. |
| `unavailable` | No adapter matches the configured base URL (no upstream request is made), or the upstream JSON contains no recognized usable meter values. |
| `disabled` | The provider entry is disabled; no upstream request is made. |
| `error` | The upstream request failed, returned a non-2xx status, or returned invalid JSON. `http_status` is included for a non-2xx upstream response. |

These reports use HTTP `200` even when `status` is not `success`; inspect the
report status. An unknown credential ID returns HTTP `404`. Missing runtime
configuration returns HTTP `503`.

Successful reads are cached for 30 seconds per credential; other report statuses
are not cached. Add `?refresh=true` to bypass a cached result. Concurrent reads
for the same credential share an in-flight fetch, including forced refreshes.

## OAuth

The login URL is shared by all providers. Set the required `provider` query
parameter to `claude`, `codex`, `antigravity`, `kimi`, `kimi-ai`, `xai`, `devin`,
`meta`, or a registered plugin provider ID. For example:

```http
GET /v8/management/oauth/auth-url?provider=codex
Authorization: Bearer <management-key>
```

Keep any provider-specific login parameters in the query string. The login
response includes the authorization URL and a session `state`. Use that state
for status queries and cancellation.

Callbacks accept `provider`, `state`, `code`, and `error` as GET query parameters
or POST JSON fields. POST also accepts `redirect_url` containing the complete
callback URL. If `provider` is omitted, it is inferred from the pending state;
an explicit provider must match that state. Poll until the status is `ok` or
`error`; `wait` means the login is still pending. Callback acceptance alone does
not mean credential exchange and persistence have completed.

Import uses `POST /v8/management/oauth/import?provider=vertex`. The `provider`
query parameter is required; Vertex is currently the supported import provider.

### Sign in with ChatGPT (SIWC) binding

SIWC is a second credential partition of an existing Codex credential, not a new
provider. This flow is available only in standalone CPA with local file-backed
Codex OAuth credentials. Home mode and non-file storage backends are not supported.

Start a binding with management authentication:

```http
POST /v8/management/oauth/siwc/bind
Authorization: Bearer <management-key>
Content-Type: application/json

{"name":"codex-example.json"}
```

`name` identifies an existing managed credential by its ID or file name; it is not
an arbitrary filesystem path. The credential must contain nonempty outer Codex
access and refresh tokens. A successful start returns:

```json
{
  "status": "ok",
  "url": "https://auth.openai.com/api/accounts/authorize?...",
  "state": "<random-state>",
  "flow": "siwc_bind",
  "expires_in": 300
}
```

Opening the returned URL starts authorization. Its redirect URI is fixed to
`http://127.0.0.1:1455/auth/callback`. This endpoint does not start a listener on
port 1455: for remote deployments, paste the complete URL from the browser address
bar, even if the loopback page cannot be reached, and submit it to the server:

```http
POST /v8/management/oauth/callback
Content-Type: application/json

{"provider":"codex","redirect_url":"http://127.0.0.1:1455/auth/callback?state=<state>&code=<code>&client_id=<issued-client-id>"}
```

The v8 callback also accepts `state`, `code`, and `client_id` directly as POST JSON
fields or GET query parameters. SIWC requires the **issued** `client_id` from the
callback; the authorization URL's `dynamic_agent_client` is not a substitute.
Error callbacks can supply `error` instead of `code` and `client_id`. Conflicting
parameters are rejected. The target, PKCE verifier, device ID, and redirect URI
are retained on the server and cannot be changed by a callback. Callback values
are handed directly to the SIWC session rather than written to legacy callback
files. Neither callbacks nor status responses return tokens.

Poll `GET /oauth/status?state=<state>` until `ok` or `error`. `wait` means binding
has not completed, including while tokens are being exchanged. Success means the
new `siwc` partition and `use_siwc=true` have been saved and published to the auth
manager. Other credential fields are retained. Rebinding explicitly replaces the
SIWC partition and reuses a valid existing device ID.

`DELETE /oauth/session?state=<state>` cancels a pending binding. Cancellation that
wins the commit gate prevents saving a late token response; cancellation after
commit returns `cancelled:false`. Duplicate callbacks and a second pending binding
for the same credential return `409`. Missing targets return `404`; ineligible
targets and incomplete callbacks return `400`. Deleting or replacing the target
through the v8 credential API invalidates its pending binding. An old server
returns `404` for the start endpoint; clients must not fall back to ordinary Codex
login. Sessions are process-local, expire after five minutes, and do not survive
restart; deployments with multiple independent instances require session affinity.

For Codex entries, `GET /credentials` includes these non-secret summary fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `siwc_bind_supported` | boolean | This credential is eligible for the binding flow. Missing means unsupported. |
| `use_siwc` | boolean | Requests are configured to use the nested SIWC credential. |
| `siwc_bound` | boolean | SIWC access token, refresh token, and issued client ID are present; not a live validity check. |
| `siwc_expires_at` | optional RFC3339 string | Stored SIWC expiration, when available. |

The v0 callback and credential-list contracts are unchanged. SIWC activation,
unbinding, and standalone SIWC credential creation are not separate management
operations in this release.

## v0 compatibility

The `/v0/management` endpoints keep their original paths and payloads, including
provider-specific OAuth login URLs, callbacks, status queries, and cancellation.
For example, `GET /v0/management/codex-auth-url` and
`GET /v8/management/oauth/auth-url?provider=codex` start the same login flow.

Legacy flat configuration endpoints such as `/debug`, `/request-retry`, and
`/codex-api-key` exist under `/v0/management` only.
`/v0/management/api-keys` continues to manage client authentication keys; the v8
equivalent is `/v8/management/config/access/api-keys`.

Legacy-only configuration files keep their layout until a successful v8
configuration write. When both layouts specify a field, the new field takes
precedence and its legacy equivalent is removed. V0 setters keep legacy-only
files in their original layout; existing v8 files are saved in the latest v8
layout. `PUT /v0/management/config.yaml` still replaces the complete file and
accepts legacy, new, or mixed layouts, normalizing v8 documents on save.

Plugin OAuth uses the shared v8 login endpoint. Other plugin-defined HTTP
extensions retain their declared `/v0/management` routes.
