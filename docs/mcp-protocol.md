# MCP protocol eras at `/mcp/{slug}`

A gateway speaks two protocol eras on the same URL (decision 51). The era is chosen **per request**; nothing is
remembered between requests. Written against MCP 2026-07-28 ([changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog))
and the earlier revisions 2024-11-05 to 2025-11-25. Code: `internal/mcpgw` (`era.go`, `modern.go`, `requeststate.go`,
`relay.go`, `stream.go`). The second half of this page is the other direction: [the portal as a client of your
servers](#the-portal-as-a-client-of-your-servers) (`internal/upstream`).

| | Legacy (2024-11-05 to 2025-11-25) | Modern (2026-07-28) |
| --- | --- | --- |
| Opens with | `initialize` | nothing; `server/discover` is optional |
| Every request carries | nothing required | `_meta` `io.modelcontextprotocol/protocolVersion` and `…/clientCapabilities`; headers `MCP-Protocol-Version`, `Mcp-Method` and, for calls and reads, `Mcp-Name` |
| Results | as before | `resultType`, `_meta` `…/serverInfo`; lists and reads also `ttlMs` and `cacheScope` |
| `ping`, `logging/setLevel`, session ids | `ping` answers; no sessions either | removed |
| "Connect your account" | JSON-RPC `-32042` | `input_required` result (clients with URL elicitation); otherwise a tool error or `-32010` with the link in the message |

## Which era a request is

A request is **modern** when its `params._meta` carries a `protocolVersion` that is not a legacy version (so
`2026-07-28`, or something we don't have, which is then refused), or, with no such `_meta`, when its
`MCP-Protocol-Version` header is a date of 2026-07-28 or later. Everything else is **legacy**: `initialize` (whatever it
carries), notifications and responses (no id), and requests without those signs. So a bare `server/discover` (no `_meta`,
no header) is "method not found" as it always was, and old clients see no difference at all: no new header is required of
them, none is validated, and their results are byte for byte what they were (a relayed result keeps whatever fields the
upstream SDK put in it).

`GET` and `DELETE` are `405` in both eras. `Mcp-Session-Id` and `Last-Event-ID` are ignored (the gateway never mints a
session id). JSON-RPC batches are `400`; a foreign `Origin` is `403`; the body is capped at 1 MiB. Authentication is the
same in both eras (API key, OAuth token, service account key).

## Validation (modern requests only)

Checked before the request is looked at, in this order. Each refusal is a JSON-RPC error with the request's id and is
not recorded in the call log (the header check of a tool's `Mcp-Param-*` headers is, as `bad_request` / `header_mismatch`).

| Problem | HTTP | Code |
| --- | --- | --- |
| `_meta` lacks `protocolVersion` or `clientCapabilities` (or capabilities is not an object) | 400 | `-32602` |
| `MCP-Protocol-Version` missing, or different from `_meta` | 400 | `-32020` HeaderMismatch |
| Version not served (`1900-01-01`, `2027-…`) | 400 | `-32022` UnsupportedProtocolVersion, `data: {supported, requested}` |
| `Mcp-Method` missing or different from `method` | 400 | `-32020` |
| `Mcp-Name` missing or different from `params.name` (`tools/call`, `prompts/get`) or `params.uri` (`resources/read`) | 400 | `-32020` |
| `Mcp-Name` or `Mcp-Param-*` with characters a header can't carry, or invalid base64 | 400 | `-32020` |
| A tool with `x-mcp-header` arguments: a present argument without its `Mcp-Param-<Name>` header, a different value, or a header for an absent or null argument | 400 | `-32020` |
| A method we don't implement (including `ping`, `logging/setLevel`, `subscriptions/listen`, `resources/subscribe`, and `resources/*` on a gateway with no resources) | 404 | `-32601` |

`Mcp-Name` is the **exposed** name (`server__tool`, or the `omp://…` URI of a resource); calls to your server use the
original name, and its own `Mcp-Param-*` headers, built from the approved definition. The `Mcp-Name` and `Mcp-Param-*`
values may use the `=?base64?…?=` form; integers compare as numbers. Header names are case-insensitive. `supported` lists
`2026-07-28, 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05`.

Unknown tools, prompts and resources are as before for the gateway's own checks (refused like an unknown name,
recorded as denied): `-32602` for tools and prompts, and for a resource `-32602` (modern) or `-32002` (legacy).

## `server/discover`

Modern requests only. Needs the same authentication as everything else.

```json
{"resultType": "complete",
 "supportedVersions": ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"],
 "capabilities": {"tools": {"listChanged": false}, "prompts": {"listChanged": false},
                  "resources": {"listChanged": false, "subscribe": false}},
 "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "<gateway slug>", "title": "<gateway name>", "version": "<build version>"}},
 "ttlMs": 30000, "cacheScope": "private"}
```

`resources` appears only when the gateway selects a resource or template the caller can see; there are no
subscriptions and no list-changed notifications. There are no `instructions` (the legacy `initialize` result has none).
The capabilities are the same as `initialize` would return.

## Results, caching and order

Every modern result has `resultType: "complete"` and our identity in `_meta["io.modelcontextprotocol/serverInfo"]`
(the same name, title and version as the legacy `serverInfo`; anything else a server put in `_meta` stays; the
server's own `serverInfo` is removed as before). `tools/list`, `prompts/list`, `resources/list`,
`resources/templates/list` and `server/discover` also carry:

- `ttlMs: 30000`, short because grants and selections change at any time and the portal sends no change
  notifications;
- **`cacheScope: "private"`, always.** What a person sees depends on their role and grants, so a shared cache must never
  serve it to someone else. (The HTTP response is also `Cache-Control: no-store`.) Every page of a list has the same
  scope.

`resources/read` results carry `ttlMs: 0` and `cacheScope: "private"`: the contents come live from your server, whose
volatility the portal doesn't know. Call and prompt results carry no cache hints. Lists are sorted by exposed name (a
resource's URI), so the order is stable across requests and pages (paged at 512 KiB with an opaque cursor, as before).

**Schemas.** The modern era allows any JSON Schema as `outputSchema` and any JSON value as `structuredContent`; the
gateway passes them through untouched. For legacy clients it still drops an `outputSchema` that isn't `"type": "object"`
(strict clients reject the whole list otherwise) and a `structuredContent` that isn't an object (GitHub's server returns
arrays; the same data is in the text content). A tool's `x-mcp-header` annotations are listed as approved.

## Consent as a multi round-trip request

Where a call needs your account on another service (a delegated provider, phase 5; a per-person sign-in to an
OAuth-protected server, phase 7), the answer depends on the client. **Except** for a call an agent platform relays for a
person ([agent-platforms.md](agent-platforms.md), decision 66): an agent has no browser, so such a call never gets
`-32042`, a link or an `input_required` result, whatever the client declared; it answers a tool error (a prompt or
resource read: `-32010`) that names the provider and says to connect under Account › My connections.

- **Modern request, `clientCapabilities.elicitation` has a `url` key** (an empty `elicitation: {}` means form only):
  HTTP 200 and

  ```json
  {"resultType": "input_required",
   "inputRequests": {"connect_<provider slug>": {"method": "elicitation/create",
       "params": {"mode": "url", "url": "<APP_URL>/connect/<provider>?request=…",
                  "message": "Connect your GitHub account (repo) to use github__create_issue in the Support gateway."}}},
   "requestState": "…",
   "_meta": {"io.modelcontextprotocol/serverInfo": {…}}}
  ```

  on `tools/call`, `prompts/get` and `resources/read` (the only methods the spec allows it on). The `url` is the link
  `-32042` carries (an opaque id: it signs nobody in), and the connect page's "the person who opens it must be the person
  who asked" check is unchanged. There is no `elicitationId` (removed in 2026-07-28). The message names the provider or
  the server's own sign-in, the scopes, the capability and the gateway, and says whether it is a first connection, more
  access or a reconnection. The call is recorded `needs_authorization` as before and nothing reaches your server.
- **Modern request without URL elicitation:** no `-32042` (2026-07-28 says implementations must not emit it). A `tools/call`
  gets a normal result with `isError: true` and the link in its text ("... Open <link> to connect it, then try again.");
  `prompts/get` and `resources/read`, which have no tool result, get the JSON-RPC error `-32010` with `data.reason`
  (`not_connected`, `missing_scopes`, `needs_reconsent`), `data.provider` and the link in the message. The link is the same
  one, and the call is recorded `needs_authorization` as before.
- **Every legacy request:** the JSON-RPC error `-32042` with the link in `data.elicitations` and in the message, exactly
  as before.

The person opens the link, then the client **retries the original request** with `requestState` echoed and
`inputResponses`. The gateway verifies the state, then re-runs every normal check, so the person may be connected now
(it proceeds and answers normally, `resultType: "complete"`) or not yet (a new `input_required` with the same link and a
fresh state).

- `inputResponses` are ignored except for `action: "decline"` or `"cancel"` on a verified state: a tool call then
  returns the tool error `authorization declined` (`isError: true`), a prompt or read the refusal `-32010` with
  `data.reason: "authorization_declined"`. Nothing is forwarded; recorded `tool_error` / `denied` with error class
  `authorization_declined`. `inputResponses` that isn't an object is `-32602`.
- **`requestState`** is sealed with AES-256-GCM under a key derived by HKDF-SHA-256 from `ENCRYPTION_KEY` (and
  `ENCRYPTION_KEY_PREVIOUS`, so a key rotation doesn't strand someone mid-consent) with its own info string
  `open-mcp-portal/mcp-request-state/v1`, so the client can neither read nor change it. It binds a version byte, the
  **person**, the **gateway**, the **method**, the exposed **name or URI**, a SHA-256 **digest of the request's parameters**
  (`params` without `_meta`, `inputResponses` and `requestState`, canonical JSON, so a retry may change the JSON-RPC id,
  `_meta` and key order but not the arguments), and issue and expiry times (**10 minutes**). It holds no credential, no URL
  and nothing about the provider. A state that is altered, from another key, for another person, expired or for another
  request is refused with `-32602` and a message that says what to do (`requestState is not valid`, `has expired`,
  `was issued for a different request`; a state for another person is "not valid", so nothing is said about whose it
  was), recorded `bad_request` with error class `request_state_invalid`, `request_state_expired` or
  `request_state_mismatch`. It is not single use (a retry only re-runs the checks, so replaying one gains nothing) and
  is never logged.

## Authorization

Personal keys, service-account keys/accounts, OAuth grants and matching platform gateway grants can also limit
tools by trusted class or exact exposed name (OAuth: classes only). Matching grants union; independent layers
intersect. Lists and calls apply the same filter before credentials or consent are requested, in both protocol
eras. Refusals are normal unknown-tool responses and recorded `denied` / `tool_scope`; prompts and resources
are unchanged. An account's live ceiling also limits its existing keys and relayed person calls.

Aligned with the 2026-07-28 authorization pages (diff of `internal/oauth` against them):

| Spec | State |
| --- | --- |
| Protected resource metadata (RFC 9728) with `authorization_servers`; `WWW-Authenticate: resource_metadata` on 401 | already done |
| Authorization server metadata (RFC 8414) at `/.well-known/oauth-authorization-server` | already done |
| Client ID Metadata Documents, advertised as `client_id_metadata_document_supported: true`; the client's `client_id` must equal the document's URL, redirect URIs validated | already done (preferred) |
| `iss` (RFC 9207) in authorization responses, errors included, with `authorization_response_iss_parameter_supported: true` | already done |
| Resource indicators (RFC 8707): `resource` required at `/oauth/authorize` and checked against the gateway; at `/oauth/token` optional but, when sent, must be the one the code or grant was issued for; tokens are accepted only by their own gateway | already done |
| PKCE S256 required; public clients only (`token_endpoint_auth_method: none`) | already done |
| `application_type` (`web` or `native`) in Dynamic Client Registration | **new**: accepted, validated (anything else is `invalid_client_metadata`), echoed in the response, recorded in the audit entry. Omitting it still works (pi doesn't send it). The portal is not an OpenID Provider, so it doesn't restrict redirect URIs by it |
| Dynamic Client Registration is deprecated, kept for compatibility | `/oauth/register` stays. The spec defines no metadata field that marks it deprecated, so the metadata says nothing; prefer metadata documents ([connect-clients.md](connect-clients.md)) |
| Dynamic Client Registration is open, so it is capped | **new in v0.2.1**: at most `OAUTH_MAX_REGISTERED_CLIENTS` (default 1000, `0` = no cap) registrations used in the last 30 days; over it `POST /oauth/register` answers `503` with the OAuth error `temporarily_unavailable` (RFC 6749 §4.1.2.1; RFC 7591 defines no code for it) and stores nothing. A client that identifies itself with a metadata document is unaffected |
| Dynamic Client Registration can be switched off, and its leftovers age out | **new in v0.2.2**: an admin can turn open registration off (Admin › Trusted clients): the authorization server metadata then has no `registration_endpoint` and `POST /oauth/register` answers `403` with the OAuth error `access_denied` (RFC 7591 defines no code for it). A registration that never received tokens is deleted after 24 hours; one address can hold at most `OAUTH_MAX_UNUSED_CLIENTS_PER_ADDRESS` (default 20) registrations that have not received tokens, past it `429 slow_down`. A client should read `registration_endpoint` from the metadata, which is the specified way |
| The authorization endpoint looks at the client only after sign-in | **new in v0.2.2**: `GET /oauth/authorize` without a browser session redirects to sign in before the client's metadata document is fetched or anything about the request is checked; the errors a client would see for a bad `client_id` or `redirect_uri` are shown as a page after sign-in. Metadata document fetches are limited to 20 a minute per source address. Clients are unaffected: they already open the browser and wait for the redirect |
| Refresh tokens have an absolute lifetime | **new in v0.2.2**: `OAUTH_REFRESH_ABSOLUTE_TTL` (default 180 days, `0` = none) after the person last signed the app in; a refresh after that is `400 invalid_grant` (RFC 6749 §5.2) and the client starts a new authorization. A refresh token presented again within 30 seconds of its rotation gets the same `access_token` and `refresh_token` as the first answer (a client that lost the response, or two refreshes at once), and `expires_in` is what is left of the access token; later it is `invalid_grant` and the connection is revoked. A client that stores the new refresh token after every refresh, as OAuth 2.1 requires, is unaffected |
| A trusted client signing in from this computer asks once | **new in v0.2.2**: a trusted metadata-document client with a loopback redirect (`http://localhost:<port>/…`) gets a short confirmation page the first time a person signs it in to a gateway (`Continue` or `Cancel`); `Cancel` is `access_denied` to the redirect. Clients with `https` redirects (claude.ai, vscode.dev) are unaffected. Claude Code's flow is otherwise unchanged |
| Tool-class scopes (`scopes_supported`) | `omp:read`, `omp:write`, `omp:destructive` are advertised by both metadata endpoints and accepted at authorization. Missing scope is unrestricted, including unclassified tools; explicit all-three excludes unclassified tools. Restricted token responses carry canonical `scope` (empty for deny-all); unrestricted responses omit it. Refresh accepts omitted/equal scope only. Out-of-scope tools remain unknown, not `insufficient_scope`; no step-up challenge. See [credential scopes](credential-scopes.md). |
| Client credentials bound to the issuer, re-registration when the authorization server changes (SEP-2352) | a client-side rule; for the portal as a *client* of upstream servers see [Authorization of upstream servers](#authorization-of-upstream-servers) |

Claude Code (a metadata document) and pi (self-registration) are covered by tests in both eras
(`oauth_spec_2026_integration_test.go`).

## The portal as a client of your servers

Where the portal reaches **your** MCP servers (discovery, refresh, test, health checks, and every call a gateway
forwards) it is an MCP client, and speaks whichever era each server speaks. Code: `internal/upstream` (`era.go`,
`modern.go`, `forward.go`, `trace.go`), `internal/mcpgw/relay.go` and `stream.go`. All of it goes through the same
guarded transport as before: the address rule, no redirects, no proxy from the environment, the response bound
(1 MiB, or 4 MiB for a streamed call), the server's own timeout.

### Era negotiation

The era is a property of the server, so the portal learns it once and remembers it, as the specification says
([versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning), "Backward Compatibility", and
[Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#backward-compatibility)).
It tries the modern era first and decides from the answer to one `server/discover` request (with the modern headers
and `_meta`, version `2026-07-28`):

| The server answers | The portal concludes |
| --- | --- |
| `200` with a discovery result | **Modern**, at the newest version both sides speak from its `supportedVersions` (a list with nothing but older versions: **legacy** at the newest of them) |
| `400` with a **recognized modern JSON-RPC error** (`-32020` HeaderMismatch, `-32021` missing capability, `-32022` UnsupportedProtocolVersion) | **Modern**, never a fallback. `-32022` lists `supported` versions: the newest modern one both speak is tried (a version the server rejects although it lists it is tried once more, then it is an error), a list with only older versions means legacy at the newest of them. The others are an error with the server's message |
| `404` with a JSON-RPC `-32601` | **Modern**, a server without the optional `server/discover` |
| `400`, `404` or `405` whose body is empty, plain text, HTML or **not** a recognized modern error; a `200` that is not a discovery result | **Legacy**: `initialize` follows. If that also gets `404` or `405` the error stays what it always was (`not_found` or `unavailable`): the deprecated HTTP+SSE transport is not supported |
| `401`, `403`, `408`, `429`, `5xx`, a timeout, a blocked address | An error, as ever; **never** a reason to fall back |

Prefer the newest mutually supported version (decision 54): the portal speaks `2026-07-28`, then `2025-11-25` and
older through the Go SDK. A legacy server is opened with `initialize` offering `2025-11-25` (the server answers with
what it speaks).

**Cache.** The learned era is kept in memory per replica, keyed by the **server's ID and URL**, for 5 minutes, so a
call doesn't probe again; a changed URL is a different key. A call made on a remembered era that gets an answer
its era doesn't give (a `400`, `404`, `405`, `406` or `415` without a modern error, or a modern error to `initialize`)
forgets the entry, learns the era again and goes on, once, and only when the call can't have run (the server
refused it before starting). A call is never repeated for anything else. The first uncached discovery of a modern
server sends two `server/discover` requests (the probe, then the SDK session's own).

**Recorded.** A refresh, a test or a health check that reads a server stores the era (`legacy` or `modern`), the
version and the time on the server (`mcp_servers.protocol_era`, `protocol_version`, `protocol_negotiated_at`,
migration `00016`; `McpServer.protocol` in the API), so the server page can show what the portal speaks to it. A failed
check leaves what was stored; a new URL clears it. A scheduled check of a server in `oauth` mode (an unauthenticated
challenge probe) doesn't read it and records nothing.

A modern server must implement `server/discover` to be **read** (the Go SDK session needs its result to list
capabilities); calls to a modern server don't need it.

### What a forwarded call looks like

- **Modern server:** one `POST` per call, with `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` (the original tool, prompt
  or URI, base64 when it can't be a plain header value), the tool's `Mcp-Param-*` headers, and `_meta` with the
  protocol version, `clientInfo` (the portal), `clientCapabilities` (below), trace context and progress token. The JSON-RPC
  `id` is fresh for every request (a retry of an input request is a different request). It accepts a JSON or an SSE
  answer. The result may be `complete` or `input_required`.
- **Legacy server:** an SDK session per call (`initialize`, the call, close) declaring **no capability**, so the server
  can't ask for sampling, roots or elicitation.

### Relaying a server's elicitation

A modern server may answer `tools/call`, `prompts/get` or `resources/read` with `resultType: "input_required"`. What
the portal does depends on the **client**:

- **Modern client that declared elicitation** (`clientCapabilities.elicitation`; an empty `{}` means form mode only,
  `url` means URL mode): the portal declares to the server **exactly the modes the client declared, per request**
  (nothing is remembered between requests; no other capability, ever), and returns `input_required` to the client with
  the server's elicitation requests as `inputRequests` and a `requestState` that is the portal's own.
- **Legacy client, or a modern one that declared none:** the server is told it can't ask (no capability). If it asks
  anyway, the call fails with a tool error ("this server asked for input, which your client can't give…"; prompts and
  reads: `-32010`, `data.reason: input_required`).
- **Sampling and roots** requests (deprecated) are never relayed, alone or beside an elicitation: the call fails with the
  tool error "this server asked for something the portal can't provide (sampling/roots)".

What is relayed is validated, then **rebuilt** with only `method`, `mode`, `message` and `requestedSchema` or `url` (the
server's `_meta`, `elicitationId` and any other field are dropped). A request that doesn't pass fails the call as a bad
response from the server (`upstream_error`, JSON-RPC `-32603`, the reason in the message), and nothing of it reaches the
client:

| Limit | Value |
| --- | --- |
| Requests per result | at most 8; keys unique, 1 to 128 characters, no control characters |
| Size | at most 16 KiB of `inputRequests`; a message at most 4 KiB; the server's `requestState` at most 8 KiB |
| Mode | only a mode the client declared (a form request to a URL-only client, or a URL request to a form-only one, is refused) |
| Form | `requestedSchema` is an object of `type: object` whose properties are objects |
| URL | an absolute `https` URL with a host, no user info, no spaces, at most 2 KiB. Plain `http` only to a loopback host in development (`DEV_AUTH` on a loopback `APP_URL`) |

**`requestState`.** It is the same sealed envelope as the consent state ([Consent as a multi round-trip
request](#consent-as-a-multi-round-trip-request); AES-256-GCM, `ENCRYPTION_KEY`-derived, 10 minutes), with purpose
`relay`. It binds the **person**, the **gateway**, the method, the **exposed name or URI**, a digest of the parameters,
the **upstream server's ID**, the keys that were relayed, and the server's own `requestState`, which the client can
neither read nor change. It holds no token or credential of any kind (a test opens it and checks that neither the
identity token the server saw nor the person's key is in it).

**The retry** (the client sends a new JSON-RPC `id`, the same name and arguments, our `requestState` and
`inputResponses`): the portal verifies every binding, with the same refusals as for consent (`-32602`:
`requestState is not valid` for an altered, truncated, foreign or other person's state, `has expired`, `was issued for
a different request`; recorded `bad_request` with `request_state_invalid`, `_expired` or `_mismatch`; a state for another
server is a mismatch too), and re-runs every normal check. Then it calls the server again with the **original
parameters**, the server's own `requestState` and the client's `inputResponses`, **only for the keys that were relayed**
(the rest are ignored, as the specification allows) and each shaped like an elicitation result (`action` of `accept`,
`decline` or `cancel`, `content` an object; anything else is `-32602`). A decline goes to the server that asked, which
decides what it means; the portal doesn't interpret it. The server may answer with another `input_required`: a new state is
sealed and relayed again. A relayed state can be replayed within its ten minutes (a retry only re-runs the call).

**Call log.** A relayed call is recorded `ok` with error class `input_required`; the retry is recorded as any call. A
call that couldn't be relayed is `tool_error` (sampling or roots, no declared elicitation), `denied` (the same for a
prompt or a read) or `upstream_error` (a request that failed validation), each with class `input_required`.

### Streaming

A `tools/call` whose `_meta.progressToken` is a string (up to 256 bytes) or an integer, from a client whose `Accept`
lists `text/event-stream` (either era), is answered as an SSE stream: `200`, `Content-Type: text/event-stream`,
`X-Accel-Buffering: no`, then one `event: message` per server `notifications/progress` for that token (relayed under
the client's own token), then the JSON-RPC response as the last event, then the stream closes. A comment line
(`: keep-alive`) is written every 15 seconds while the call waits. Every other call stays one buffered JSON object.

- The stream starts when the call is about to reach the server. Refusals before that (unknown tool, denied, rate
  limited, consent needed, bad request) are the JSON answers they always were; failures after it are the response event.
- `notifications/message` (logging, deprecated) is not relayed; nor is any other notification.
- **Closing the connection cancels the call to the server** (its connection is closed, or the SDK session is, for
  a legacy server) and the call is recorded `upstream_error` with class `client_cancelled`.
- Bounds: at most 64 progress events and 4 MiB per call, further progress is dropped (the call goes on); progress that
  doesn't increase, or isn't a finite number, is dropped; a message is cut to 1000 bytes. The response is at most 1 MiB
  as ever, and the server's total (progress and response) at most 4 MiB. The server's timeout applies as always.
- A call is recorded once, at the end. Rate limits count it as one request. The recorded response size is the whole
  stream.
- Behind a proxy: [deploy.md](deploy.md#ingress).

### Trace context

`traceparent`, `tracestate` and `baggage` from the client request's `params._meta` (either era) are passed to the
server's `_meta` when they are well-formed (W3C Trace Context and Baggage: `traceparent` exactly
`vv-<32 hex>-<16 hex>-<2 hex>` in lowercase, not version `ff`, not all-zero ids; `tracestate` at most 512 characters and 32 members and only
with a valid `traceparent`; `baggage` at most 2048 characters and 64 members). Anything else is dropped, and when the
client sent none, none is sent. No other client `_meta` entry is passed on.

With **tracing off** (the default; [deploy.md](deploy.md#tracing)) that is all the portal does. With tracing on, the
portal is a hop of the trace: the parent of its span is the request's HTTP `traceparent` header when it has a valid one,
else the valid `traceparent` in `params._meta` (an invalid value starts a new trace), and, when its span is sampled, the
`traceparent` it sends to the server (both eras, every server) names the portal's span as the parent, with the
client's `tracestate` (still only when valid); the trace ID stays the client's. `baggage` is always the client's own,
validated as above, and is never added. When the trace is not sampled, the client's `traceparent` and `tracestate` go on
unchanged, as with tracing off. The portal's spans carry no `_meta`, argument or result content.

### Authorization of upstream servers

For servers in `oauth` mode ([phase7-upstream-oauth.md](phase7-upstream-oauth.md)):

- The client credentials the portal holds for a server belong to the **authorization server's issuer** they were
  registered at (SEP-2352). When the server's resource metadata names another authorization server, saving its sign-in
  registers the portal's client at the new one (a dynamically registered client is never reused across issuers, and
  a client registered by dynamic registration is chosen again, preferring a Client ID Metadata Document where the new
  server offers one), resets the people's connections, and sends the server back to review. A client entered by hand
  (GitHub style) or taken from a platform provider keeps its own rules: a new issuer asks for a new client.
- The portal's dynamic registration requests say `application_type: "web"` (SEP-837).
- Client ID Metadata Documents are still preferred when the authorization server supports them and `APP_URL` is public https.

### Not supported (as a client)

- The deprecated HTTP+SSE transport (a server that answers `404` or `405` to `POST` is an error) and stdio (decision 47).
- Sampling and roots (deprecated) in either era, and server-to-client requests from a legacy server. Logging
  notifications. `subscriptions/listen` and list-changed notifications from servers (the portal re-reads on refresh).
- A modern server that doesn't implement `server/discover` can't be discovered (calls to it work).
- Tasks, completion.


## Limits and not done

- A response is one JSON object (≤ 1 MiB), except a `tools/call` with a progress token from a client that accepts
  `text/event-stream`, which is [streamed](#streaming). No `subscriptions/listen`, no tasks extension, no
  `notifications/message`.
- The gateway originates input requests for consent, and [relays a server's elicitation](#relaying-a-servers-elicitation);
  never sampling or roots.
- No `completion/complete`, logging, sampling or roots, and `ping` only for legacy clients.

## Deviations from the specification

- **Rate limit.** `-32029` (legacy) is inside the range reserved for the specification in 2026-07-28, so modern requests
  get code `429` (the HTTP status) instead. The status, `Retry-After`, and `data` are the same.
- **Refusals** keep our grandfathered codes `-32001` (HTTP-level refusals) and `-32010` (a refusal with a reason), in the
  legacy range the spec tolerates but discourages.
- **A dual-era server accepts `initialize`.** The conformance scenario that expects `initialize` to be "method not found"
  assumes a modern-only server (below).
- `Accept` is not required to list `text/event-stream`: the answer is JSON unless the call asks for progress
  ([Streaming](#streaming)).

## Conformance

The MCP project's suite (`@modelcontextprotocol/conformance` 0.2.0-alpha.12, `server --spec-version 2026-07-28 --suite
all`, plus `2025-11-25`) was run against a portal built from this branch on a scratch database, with a gateway over
`cmd/fakemcp` (`-schema-tools`) and a small proxy that adds the bearer key (the runner can't send one). Results:

- **Pass:** `caching` (8/8), `http-header-validation` (14/14), `http-custom-header-server-validation` (10/10, with the
  `lookup` tool), `sep-2164-resource-not-found`, `tools-list`, `resources-list`, `prompts-list`,
  `server-sse-multiple-streams`, `input-required-result-missing-input-response`, `-unsupported-methods`,
  `-ignore-extra-params`, `-validate-input`, `server-stateless` (20 of 25 checks), and `wire-schema-valid` everywhere.
  Legacy (`2025-11-25`): `server-initialize`, `ping`, `tools-list`, `resources-list`, `prompts-list`.
- **Can't pass by design or fixture** (a gateway is not the suite's "everything server"): scenarios that call named
  fixtures (`test_simple_text`, `test_input_required_*`, `test_missing_capability`, …) fail with "Unknown tool" because
  exposed names are `server__tool` and the gateway originates no input requests of its own (the
  `input-required-result-*` scenarios; ours is covered by `mcp_consent_mrtr_integration_test.go`); `completion/complete`,
  logging, sampling, subscriptions and SSE-stream scenarios test features the portal doesn't offer;
  `sep-2575-http-server-method-not-found-404-initialize` expects a modern-only server;
  `dns-rebinding-protection/localhost-host-valid-accepted` sends an `Origin` that is not the portal's `APP_URL` (the
  portal accepts only its own origin).

Reproduce: `go build ./cmd/open-mcp-portal ./cmd/fakemcp`, run both (scratch database, `DEV_AUTH=true`), `python3
scripts/dev-seed.py`, create a key, put a header-adding proxy in front, and run the commands above.

### As a client

The suite's client scenarios for 2026-07-28 run a mock server and a command under test. The portal's upstream client has
no command of its own, so `cmd/upstream-conformance` (a small development tool, not part of the portal)
drives `internal/upstream`: it negotiates the era, lists, calls every tool with parameter headers from the listed
definition, and answers input requests by accepting and echoing the server's `requestState`. Results (suite
`0.2.0-alpha.12`, `client --spec-version 2026-07-28`):

- **Pass:** `tools_call` (2/2), `request-metadata` (5/5, including "retries with a supported version"),
  `http-standard-headers` (6/6), `http-custom-headers` (18/18), `http-invalid-tool-headers` (12/12),
  `sep-2322-client-request-state` (5/5), `json-schema-ref-no-deref` (1/1), `json-schema-2020-12-preservation` (9/9).
- The suite found two bugs, both fixed: the JSON-RPC `id` of a retry was the same as the first request's (MRTR requires a
  different one), and a server that rejects a version it lists was an error on the first rejection instead of being
  retried once.
- **Not run:** the `auth/*` client scenarios. They drive an interactive authorization-code flow in the client, and the
  portal's sign-in to an upstream server is a browser flow with a person (phase 7); its parts are covered by
  `upstream_oauth_integration_test.go` and `upstream_oauth_issuer_integration_test.go` instead (RFC 9207 `iss`
  checks, resource indicators, issuer change). So are `authorization-server-migration` and the `iss-*` scenarios.

```
go build -o /tmp/omp-upstream-conformance ./cmd/upstream-conformance
npx @modelcontextprotocol/conformance@0.2.0-alpha.12 client --command /tmp/omp-upstream-conformance \
    --scenario http-custom-headers --spec-version 2026-07-28
```
