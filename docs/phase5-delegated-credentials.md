# Phase 5: Delegated credentials (design)

Status: **backend built** (see "As built" at the end; the web UI is built separately from the same contract). Decisions 25–30 in [decisions.md](decisions.md) are defaults the assistant
accepted under the instruction "continue until both are done". The contract is in [`../api/openapi.yaml`](../api/openapi.yaml)
(tags `auth-providers` and `connections`). Builds on decisions 7–8, 12, 19 and 21–24. Inspired by Arcade's tool-level
authorization (`requires_auth=GitHub(scopes=[…])`) and MCP 2025-11-25 URL-mode elicitation (`URLElicitationRequiredError`, `-32042`).

## Goal

A tool can act **as the person** on a third-party service. Examples: create a GitHub issue as them, or read their
Google Drive. A platform admin configures the provider's OAuth app once. A server's team says which provider and scopes
its capabilities need. The first call asks the person to connect their account in a browser. After that, the gateway
sends their token with each call that needs it and refreshes it. The client and the model never see the token.

## Data model (migration `00010_delegated_credentials`)

| Table | Columns (main) |
|---|---|
| `auth_providers` | id, slug (unique, immutable), name, kind `oauth2`, preset, enabled, client_id, client_secret (sealed with `ENCRYPTION_KEY`, AAD = provider ID), client_secret_hint, token_auth_method, pkce, authorization_url, token_url, revocation_url, userinfo_url, default_scopes `text[]`, scope_param, scope_separator, token_response_format, extra_authorize_params `jsonb`, logo_url, revision, created_by, timestamps |
| `mcp_servers` (+) | auth_provider_id (nullable, FK `RESTRICT`), auth_scopes `text[]` |
| `mcp_capabilities` (+) | requirement_mode `inherit`/`none`/`scopes` (default `inherit`), requirement_scopes `text[]` |
| `provider_connections` | id, user_id, provider_id (unique together), status `active`/`needs_reconsent`, scopes `text[]` (granted), account_label, access_token and refresh_token (sealed, AAD = connection ID + field), expires_at, connected_at, refreshed_at, last_used_at, last_error_class |
| `provider_connect_requests` | id_digest (SHA-256 of a random 32-byte ID, base64url), user_id, provider_id, required_scopes, gateway_id, capability_id, **server_id** and **server_origin** (the server the link was made for, and its origin then; F-3), exposed_name, reason (`not_connected`, `missing_scopes`, `needs_reconsent`, `server_not_allowed`), created_at, expires_at (+10 min), used_at |
| `provider_server_grants` (migration `00017`, F-3, decision 60) | id, connection_id (FK `CASCADE`), server_id (FK `CASCADE`), origin (scheme, host and port of the server's URL when the person consented), scopes `text[]` (what they consented to), consented_at; unique on (connection, server). Platform providers only: an `oauth` server's connection is already for one server |
| `provider_auth_states` | state_digest, user_id, session_digest, provider_id, scopes asked, code_verifier (sealed), request_digest, return_to, created_at, expires_at (+10 min). Single use |
| `mcp_calls` (+) | provider_slug; outcome `needs_authorization` |

`ENCRYPTION_KEY_PREVIOUS` still decrypts, as for server headers. Expired requests and states are deleted when new ones
are written and by the retention loop.

## Roles

| Action | Who |
|---|---|
| Configure providers (create, edit, turn off, delete) | platform admins |
| Read the provider configuration and presets | platform admins and auditors |
| List providers for picking (`GET /v1/auth-providers`: id, slug, name, kind, preset, default scopes, logo) | any active signed-in person |
| Set a server's requirement and capability overrides | team editors, admins and owners (the registry's write roles); platform roles never through team routes |
| Review requirements (part of server review) | platform admins |
| See, connect and disconnect your own accounts | every person (browser session for connect) |
| See someone's connections (metadata) | platform admins and auditors; revoke: platform admins only |
| Use capabilities that require a provider | people only; service accounts are refused (decision 29) |

## Auth providers (decision 25)

Generic OAuth 2.0 authorization code. PKCE S256 is on by default; turn it off only where the provider rejects it. The
token endpoint uses `client_secret_post` (the default), `client_secret_basic` or `none`; `none` makes a public client and
requires PKCE. `tokenUrl`, `revocationUrl` (RFC 7009) and `userinfoUrl` are dialled through `internal/upstream`'s address
guard and the internal-network allowlist (decision 20): no proxy, no redirects, 10 s, responses ≤ 64 KiB.
`authorizationUrl` is only visited by browsers, but it must still be https (plain http only on loopback in
development). Every URL is checked like a server URL: no user info, query or fragment.

There are two settings for Slack's non-standard user-token flow. `scopeParam` is `user_scope` instead of `scope`, and
`tokenResponseFormat` `slack_authed_user` reads the token from `authed_user`. Reserved `extraAuthorizeParams` keys are
refused. The redirect URI is always `<APP_URL>/connect/callback`, shown on the provider record for the admin to register.

Presets only pre-fill the form. Check the values against each provider's documentation when building:

| Preset | Endpoints (authorize · token · revoke · userinfo) | Notes |
|---|---|---|
| GitHub | `github.com/login/oauth/authorize` · `/access_token` · none · `api.github.com/user` | PKCE supported (2025). OAuth-app tokens don't expire. Send `Accept: application/json` |
| Google | `accounts.google.com/o/oauth2/v2/auth` · `oauth2.googleapis.com/token` · `/revoke` · `openidconnect.googleapis.com/v1/userinfo` | `access_type=offline`, `prompt=consent`, `include_granted_scopes=true`. Use full scope URLs |
| Microsoft Entra ID | `login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize` · `/token` · none · `graph.microsoft.com/oidc/userinfo` | `tenant` defaults to `organizations`; add `offline_access` for refresh |
| Atlassian | `auth.atlassian.com/authorize` · `/oauth/token` · none · `api.atlassian.com/me` | `audience=api.atlassian.com`, `prompt=consent`, `offline_access`. PKCE off |
| Slack | `slack.com/oauth/v2/authorize` · `slack.com/api/oauth.v2.access` · none · none | `user_scope`, comma separator, `slack_authed_user`. PKCE off |
| GitLab | `{host}/oauth/authorize` · `/oauth/token` · `/oauth/revoke` · `/oauth/userinfo` | `host` defaults to `gitlab.com` (self-managed) |

Changing `clientId` marks every connection `needs_reconsent` and erases its tokens; `auth_provider.update` records
`connectionsReset`. Turning a provider off refuses its calls and new connections; connections are kept. Delete is
`409 in_use` while any server requires the provider. Otherwise delete erases every connection and revokes it at the
provider where possible.

## Requirements (decision 26)

- **Server:** optional `requirement` `{providerId, scopes}`. Empty scopes mean the provider's default scopes. Only an
  enabled provider can be newly chosen.
- **Capability override** (`PUT …/capabilities/{id}/requirement`, If-Match = the server's revision): `inherit`, `none`, or
  `scopes` (the same provider with other scopes; `409 no_server_requirement` without one). Removing the server's
  requirement, or changing its provider, resets `scopes` overrides to `inherit`.
- The token goes to the **server**. Overrides decide where consent is asked and which scopes are sent, not which of
  the server's code can see a token. One provider per call.
- **Review:** under `approval_required`, a published server goes back to `pending` (`mcp_server.publish_request`, reason
  `requirement_changed`) when any capability's effective requirement **widens**. That means a provider where there
  was none, another provider, or a scope that wasn't in effect before. Removing or narrowing a requirement never needs
  review, because it sends less. Under `self_publish` the server stays published. Reviewers see the requirement and
  the overrides.
- **Views:** `McpServer.requirement`, `McpCapability.requirementOverride` and `requires` (the effective requirement),
  and `requires` on catalog capabilities, gateway capabilities and gateway options. In `MyGatewayDetail`, `requires.connected`
  says whether a call would be forwarded now. Admin › Servers filters with `?provider=`.

## Runtime (decisions 27–29)

*Calls an agent platform relays for a person (decision 66, [agent-platforms.md](agent-platforms.md)) use the person's
connection as below, but an agent has no browser: where step 3 gives a consent link, such a call answers a tool error
(a prompt or resource read: `-32010`) naming the provider and saying to connect under Account › My connections, makes no
consent request, and is recorded `needs_authorization` with class `needs_connection`. For `server_not_allowed` the
message names the server and says to allow it under Account › My connections ("Allow servers…", see "Allowing a server
from My connections" below); it never holds a link. A service account that is the relay itself, with no person named,
is a service account here too (step 1).*

The existing checks (credential, person active, gateway, grant, selection, role, availability) run first, so anything
not allowed still looks like "not found". Then, for `tools/call`, `prompts/get` and `resources/read` of a capability
with an effective requirement:

1. **Service account:** JSON-RPC `-32010` "This tool needs a person's GitHub account; service accounts can't use it".
   `data.reason` is `service_account`. Recorded as `denied`, class `service_account`. Lists still show the tool.
2. **Provider turned off:** `-32010`, `data.reason` `provider_disabled`. Recorded as `denied`, class `provider_disabled`.
3. **No active connection, granted scopes that don't cover the required ones, or (platform providers) no grant for
   this server:** the gateway creates (or reuses for the same person, capability, scopes, server and server origin) a
   connect request and answers `-32042`. Nothing is forwarded. Recorded as `needs_authorization` with class
   `not_connected`, `missing_scopes`, `needs_reconsent` or **`server_not_allowed`** (connected with covering scopes,
   but the person hasn't allowed this server to use the account, or only for other scopes, or at another origin).
   The messages name the server and its team ("Allow Status (Platform tools) to use your GitHub account (repo) …").
   At most 20 open requests per person; the oldest is dropped.
4. **Access token expires within 60 s:** refresh it while holding a row lock (`SELECT … FOR UPDATE`), so replicas
   never use a rotating refresh token twice. `invalid_grant` or a 400/401: erase the tokens, mark the connection
   `needs_reconsent`, audit `provider_connection.refresh_failed`, then go to step 3. A network error, 5xx or timeout:
   `-32010` `provider_unavailable` (recorded as `upstream_error`), and the connection is kept. An expired token with
   no refresh token counts as a failed refresh with reason `expired`.
5. **Forward** with `MCP-Gateway-Provider: <slug>` and `MCP-Gateway-Provider-Token: <access token>` (bare, no
   `Bearer`). The identity JWT (decision 19, unchanged) gains `provider: "<slug>"`. Calls without a token never get
   these headers or the claim. `last_used_at` is updated at most once a minute.

### Which servers and scopes are sent (F-3, decision 60)

A platform provider's token is sent only to a server the person **allowed**, at the **origin** they allowed it, for
the scopes they were shown:

- A person's consent is a row in `provider_server_grants`: (connection, server, origin, scopes). `Credential` sends the
  token only when the connection is active and its scopes cover the capability's, **and** there is a grant for the
  calling server whose origin equals the origin of the URL the call goes to now (scheme, host and port, from
  `registry.OriginOf`; case, a trailing slash, a default port and the path don't count) and whose scopes cover the
  requirement. A grant for another origin is never honoured, whatever else happened.
- A server's URL moving to **another origin**, its requirement naming another provider (or none), or its deletion deletes
  its grants (audit `mcp_server.provider_grants_reset`: the reason, a count, and for a move the old and new origin; no
  names or secrets). People then consent again. A path-only edit changes nothing. Disconnecting, deleting a provider
  and deleting a person delete their grants by cascade.
- A server that widens its requirement needs consent again for the new scopes (the grant covers what the person was
  shown); a grant is widened, never narrowed, by a later consent for the same server and origin.
- **Not changed:** the connection is still one token per person and provider, and **still holds the union** of every
  scope the person ever granted (the provider round trip asks for `union(granted, asked, required)`; downscoping is not
  part of this fix). A server the person allowed therefore receives all of those scopes, not only the ones it asked
  for, and keeps receiving the token until they disconnect or its origin changes. Per-call scope minimisation and a
  per-provider list of teams or servers allowed to require a provider are hardening H-5 in
  [threat-model.md](threat-model.md), not done.
- `oauth`-mode (server-bound) providers have no grants: their connection is for one server and URL already
  ([phase 7](phase7-upstream-oauth.md)).
- **After the upgrade nobody has a grant** (no backfill, deliberately: a backfill would grandfather any malicious
  server). Each person sees one consent prompt per server the first time they call it, and confirms once.

```json
{"jsonrpc": "2.0", "id": 7, "error": {"code": -32042,
 "message": "github-tools__create_issue needs your GitHub account (repo). Open https://mcp.example.com/connect/github?request=Zk3… to connect it, then try again.",
 "data": {"elicitations": [{"mode": "url", "elicitationId": "Zk3…",
   "url": "https://mcp.example.com/connect/github?request=Zk3…",
   "message": "Connect your GitHub account (repo) to use github-tools__create_issue in the support gateway."}]}}}
```

The gateway is stateless (JSON responses, no session stream), so it never sends `notifications/elicitation/complete`.
The person retries the call; the spec allows manual retry. Client capabilities are only sent on `initialize`, so the
gateway can't tell whether a later request comes from a client that supports URL elicitation. Every legacy client
therefore gets `-32042` (a modern 2026-07-28 request states its capabilities each time: with URL elicitation it gets an
input request, without it a tool error or `-32010`, [mcp-protocol.md](mcp-protocol.md)), and the `message` carries the link for clients that only show errors. The URL contains only an opaque
ID: no personal data, and it doesn't sign anyone in. Static header names `MCP-Gateway-Provider` and
`MCP-Gateway-Provider-Token` become reserved (`400 invalid_auth_header`), like `MCP-Gateway-Identity`.

```text
Client          Gateway /mcp/{slug}            Browser (person)          Provider              MCP server
  │ tools/call ──►│ checks pass; no connection
  │◄── -32042 ────│ (url /connect/github?request=R)
  │ shows link ──────────────────────────────►│ /connect/github?request=R (web app, signed in as same person)
  │               │◄── GET /v1/connect/requests/R, POST /v1/me/connections/start {providerId, requestId}
  │               │──── authorizeUrl (state, PKCE) ─►│── authorize ─────►│ consent
  │               │◄──────────── /connect/callback?code&state ───────────│
  │               │── token exchange (guarded) ──────────────────────────►│
  │               │ seal tokens, mark R used ──► 303 /connect/done "Go back and try again"
  │ tools/call ──►│ token valid (refresh if needed) ── JWT + MCP-Gateway-Provider[-Token] ─────────────►│
  │◄── result ────│◄──────────────────────────────────────────────────────────────────────────────────│
```

## Connect and callback

- **`/connect/{provider}?request=R`** is a web-app route; the server serves the SPA, as it does for `/oauth/consent`. A
  signed-out person goes to sign-in and comes back. The page loads `GET /v1/connect/requests/R`. For another person's
  or an unknown request it shows "This link was made for someone else" (404). For an expired or used one it shows
  "This link expired. Run the tool again." (410). Otherwise it shows a confirm page: who is signed in, the tool and
  gateway, the **server and its team** the link was made for ("Allow Status (Platform tools) to use your GitHub
  account"), the provider, the account connected now, and **each scope** (already granted, or new). Continue calls
  `POST /v1/me/connections/start {providerId, requestId}` (CSRF token, same origin, browser session only), then sends
  the browser to `authorizeUrl`. When the person is **already connected with covering scopes** and only the server's
  grant is missing (reason `server_not_allowed`), the button is "Allow <server>" and calls
  `POST /v1/connect/requests/R/confirm` instead: the grant is recorded, the link is used up and nothing is sent to the
  provider (`409 connect_required` when the account no longer covers the scopes; the page then offers the provider).
  A link is for one server at one origin: it can allow only that server, and once the server moved to another origin
  (or requires another provider) the link answers `410 connect_request_server_changed` everywhere.
- **Allowing a server from My connections (decision 68, #60).** An agent's call never returns a consent link, so the
  person can allow a server with no call of their own: Account › My connections › a connection › **Allow servers…**.
  - `GET /v1/me/connections/{id}/allowable-servers` lists the servers that **require the connection's provider** and
    that the person **may use through a gateway now** (`gateways.ReachableServers`: the offers of the gateways they can
    use, so their teams' servers on their teams' gateways and published servers with approved capabilities on gateways
    granted to them; another team's private server, or a server on no gateway they can use, is not listed). Each item
    has the server and its team, the origin its URL has now, the scopes its capabilities ask of the account (the union
    over the capabilities the person may use), `covered` (the connection is active and already has them) and `allowed`.
  - `POST /v1/me/connections/{id}/allow-server {serverId, origin, scopes}` records the same `provider_server_grants`
    row as the confirm step, bound to the **server's origin now** and **the scopes it requires** (the grant is
    widened, never narrowed, as for a link), with nothing sent to the provider. `origin` and `scopes` are what the list
    showed: `409 server_changed` when the origin differs or the server asks for a scope that wasn't shown (a narrower
    requirement is fine). Other refusals: `404 connection_not_found`; `404 server_not_found` (no such server, or one the
    person may not use; the same answer for both); `422 server_does_not_require_provider`; `409 connect_required` (the
    connection isn't active or lacks the scopes; `details.scopes` names them, and the page starts the provider round
    trip as for a link); `409 not_platform_provider`; `400 invalid_allow`. The server row is locked while the grant is
    written, so an edit of its address or provider (which deletes its grants) can't slip between the check and the
    write. Audited as `provider_connection.server_allow` with `viaRequest` false.
  - `DELETE /v1/me/connections/{id}/allowed-servers/{serverId}` takes back one server's allowance (`404
    server_grant_not_found` when there is none); the connection stays. Audited as `provider_connection.server_revoke`.
  - All three are the person's own, in a browser session only (no `x-omp-token-scopes`: automation tokens get `403
    token_not_allowed`; API keys and service-account keys are not accepted on `/v1`), and allow and take back share
    one limit of 20 a minute per person (`429 slow_down`).
- **Start** asks for the union of the granted scopes (if active), the request's or caller's scopes, and, with neither,
  the provider defaults. A new token therefore replaces the old one without losing scopes. It stores a single-use
  state (256-bit, digest stored) bound to the **session digest, person, provider, request and return path**. With
  PKCE, the verifier is sealed. 20 per minute per person.
- **`GET /connect/callback?code&state`** is a server route outside the contract; the contract test skips `/connect/`.
  1. Delete the state before any other check; missing or expired shows an error page.
  2. The browser session must be the one that started the flow (else "Sign in as the person who started
     connecting"). This stops OAuth CSRF (an attacker's account attached to someone else's session); the state names
     the provider, which defeats mix-up attacks. A provider `error` goes to `/connect/done?provider=…&result=denied`.
  3. Exchange the code (with the verifier) at the token URL through the guard; JSON and form-encoded responses are
     accepted. Granted scopes are the response's `scope` when present, else those asked for. `userinfo` gives
     `accountLabel` (5 s; a failure is ignored).
  4. Upsert the connection as `active`, mark the request used, **record the grant for the request's server** (at its
     origin, for the request's scopes, merged with an earlier grant at the same origin; only when this callback used the
     request up and the provider granted every required scope; audit `provider_connection.server_allow`), audit
     `provider_connection.create`, then `303` to
     `returnTo` or `/connect/done?provider=…&result=connected|missing_scopes`. The done page lists any required scope
     the provider didn't grant, so a renamed scope can't loop silently.
- **Open redirects:** `returnTo` must be a same-origin path: it starts with one `/`, has no `//`, `\` or scheme, and is
  at most 2000 characters (`400 invalid_return_to`). The callback only redirects to that path or to fixed web-app
  routes. The authorization URL is built from stored settings only.
- **Proactive connect:** "Connect" on Account › My connections (default scopes) and on a My gateways capability
  (`requires.scopes`) call start without a request.

## Refresh, status and revocation (decision 29)

- Refresh happens on demand before forwarding (step 4). There's no background refresh in this phase. A rotated
  refresh token replaces the stored one in the same transaction.
- `needs_reconsent` erases the tokens but keeps the row, scopes and label, so the person sees what to reconnect.
- Disconnect (Account › My connections, or a platform admin on the person's page) erases the tokens and deletes the
  row, and with it the person's grants for that account (the servers are asked again after reconnecting). Where `revocationUrl` exists, it then calls RFC 7009 with the refresh token (else the access token) on a
  best-effort basis. The audit records `providerRevoked` (`true`, `false` or `not_supported`).
- A suspended person keeps their connections; their requests are refused at authentication as today. Leaving a team
  changes nothing, because connections are personal.

## Security

- Tokens and the client secret are **never** returned, logged, audited, recorded in calls or health, or put into
  errors. Token-endpoint error bodies are reduced to an error code. A sentinel test covers responses, audit,
  `mcp_calls` and logs.
- A token is sent only to the registered URL of a server whose effective requirement for **that capability** names
  **that provider** and that **the person allowed** at the origin that URL has now (F-3, see "Which servers and scopes
  are sent"). It is never sent on lists, discovery, test, refresh or health checks, and never to another server.
- Consent links are single-person, expire after 10 minutes, are used once, and need that person's browser session (the
  MCP spec's phishing guidance). The confirm page always shows the scopes before the provider is contacted.
- CSRF: start is a CSRF-protected POST from a browser session, and the callback state is bound to that session.
- The gateway doesn't check that the provider account belongs to the person (for example, by matching email).
  `accountLabel` is informational. Servers that care can check it with the provider.
- Server authors: verify the JWT first, check that its `provider` claim equals `MCP-Gateway-Provider`, and use the
  token only with that provider's API. [upstream-identity.md](upstream-identity.md) gets a "Provider tokens" section.

## Audit (decision 30)

- `auth_provider.create/update/delete` (target `auth_provider`; before/after without the secret; `clientSecretChanged`,
  `connectionsReset`, `connectionCount`).
- `provider_connection.create` (`scopes`, `reconnect`, `viaRequest`), `provider_connection.refresh_failed` (system
  actor; `reason`), and `provider_connection.revoke` (`reason` `user`/`admin`/`provider_deleted`, `providerRevoked`).
  These use target `provider_connection` with label "person · provider". `provider_connection.server_allow` (F-3:
  `server`, `serverId`, `origin`, `scopes`, `viaRequest`: true for a consent link's confirm or callback, false from My connections)
  records a person allowing a server and `provider_connection.server_revoke` (`server`, `serverId`, `origin`, `scopes`)
  taking one back;
  `mcp_server.provider_grants_reset` (target `mcp_server`, in the team's log; `reason` `origin_changed`,
  `provider_changed` or `server_deleted`, `grantsDeleted`, and `oldOrigin`/`newOrigin`) records grants ending.
- `mcp_capability.requirement_set`; `mcp_server.update` carries the requirement before and after.

## UI

- **Admin › Auth providers:** list (name, preset icon, enabled, servers, connections); create (pick a preset, which
  pre-fills the fields and asks for its URL parameters; the redirect URI is shown with a copy button); record with
  Overview, Settings (secret "keep") and Delete (lists the servers when `in_use`).
- **Admin › Users › person › Connections:** metadata and Disconnect (auditors read only).
- **Team › Servers › server:** a "User authorization" section in Settings with a provider picker and scope chips. A
  warning says when saving sends the server back to review. The Capabilities tab has a requirement column and an
  override dialog. Admin review shows both.
- **Gateway pickers, Capabilities tab and catalog:** a "Needs GitHub · repo" badge, plus "Service accounts can't use
  this" in team and service-account views. **My gateways › gateway:** "Connected" or a Connect button per
  capability.
- **Account › My connections:** provider, account, scopes, **allowed servers** (name, team and origin; read-only,
  disconnecting removes them all), status, last used, expiry; Connect, Reconnect, Disconnect.
- **`/connect/{provider}`** confirm page and **`/connect/done`** result page (connected, denied, missing scopes,
  expired, wrong person).

## Tests that must exist

- Authz matrix for every new operation; secrets and tokens never appear in responses, audit, `mcp_calls` or logs (sentinel).
- Provider validation: URL rules through the guard (private, blocked, http), reserved parameters, `none` without
  PKCE, `in_use` delete, clientId change resets connections, turned-off provider refused.
- Requirement rules: overrides, reset on provider change and removal, widening vs narrowing under both policies.
- Runtime against a fake provider and `cmd/fakemcp`: `-32042` shape and message link, request reuse and cap; the retry
  after consent forwards both headers and the `provider` claim; nothing is sent without a requirement or with
  `none`; missing scopes and the union request; refresh before expiry, rotation, concurrent refresh on two replicas,
  `invalid_grant` leading to `needs_reconsent` and `-32042`, a provider outage returning `-32010` without forwarding;
  service account and disabled provider refused; calls recorded with `providerSlug`.
- Connect flow: state single use and expiry; another session or person refused; another person's request is 404, an
  expired one 410; `returnTo` open-redirect cases; provider `error`; mix-up (state of provider A on B's callback);
  form-encoded and Slack responses; userinfo failure tolerated; revocation called and failures recorded.
- F-3 (`security_f3_integration_test.go`): the URL-change reproduction (the second host receives no token; a path-only
  edit keeps working; a stored origin that isn't the server's is not honoured), a second server with fewer scopes, a
  link for one server can't allow another (or a server that moved; another person's, used and expired links), confirm
  without a request to the provider, the three consent answer shapes for `server_not_allowed`, resets on provider
  change, removal and delete, cascades, the connections list, and the secret sentinel.
- Allow from My connections (`allow_server_integration_test.go`): the list and the grant without a call, bound to the
  current origin and scopes like a link's (rows and audit compared), a moved server and a widened requirement refused, a
  server that doesn't require the provider, another team's private server, the catalog path through a gateway granted to
  the person, a connection that doesn't cover the scopes, take back, session-only and the rate limit, and an agent's
  relayed call that gets the link-free message before and succeeds after.
- Reserved header names refused on servers. Vitest for every new screen, including the confirm page's scope list
  and wrong-person state.

## Not in this phase

Team-owned providers; non-OAuth per-person secrets (API keys); credentials for service accounts (for example,
client credentials); several accounts per provider; a server asking for re-consent after the provider answers 401;
`notifications/elicitation/complete`; background refresh; token exchange (RFC 8693) for internal APIs; matching the
provider account to the person.

## Build notes

Until the backend serves the new routes, `TestRoutesMatchOpenAPI` ("documented but not served") and the authz-matrix
classification test fail, and `make check-generated` reports stale types. Build the backend first, then run
`make generate`. New required response fields (`requirement`, `requirementOverride`, `requires`) need web fixtures
updated. A test fake OAuth provider (httptest, and `cmd/fakemcp -oauth` for local use) issues expiring and rotating
tokens.

## As built (backend)

Code: `internal/providers` (`providers.go` provider CRUD, `presets.go`, `endpoint.go` guarded token/revocation/userinfo
exchanges, `connections.go`, `connect.go` consent links, start and callback, `runtime.go` credentials and refresh),
`internal/registry/requirements.go` (requirements, effective requirement, widening, overrides), `internal/mcpgw/delegated.go`
(the runtime steps), `internal/httpapi/providers.go`, migration `00010_delegated_credentials.sql`, `cmd/fakeoauth` and
`internal/testutil/fakeoauth.go`. Every contract operation is served; no setting was added.

- **Providers.** URLs go through `upstream.Client.NormalizeURL` (the same rules and reasons as MCP servers, plus
  `details.field`); the token, revocation and userinfo endpoints are dialled with the guarded dialer (allowlist,
  development allowance, pinned addresses), no proxy, no redirects, 10 s (userinfo 5 s), bodies ≤ 64 KiB. Token requests
  are form-encoded with `Accept: application/json`; answers may be JSON or form-encoded, `scope` may be space- or
  comma-separated. An OAuth `error` (also in a 200, as GitHub does) or a 4xx is a refusal; 5xx, 429, network errors,
  timeouts and malformed answers are "unavailable". Error bodies are reduced to the error code. The secret is sealed
  (AAD `auth_provider:<id>`); `clientSecret: ""` on update removes it (only allowed with `none`). Slugs `done` and
  `callback` are reserved (`422 invalid_slug`, `details.reason` `reserved`). Create is serialized by an advisory lock so
  the limit of 100 holds. The refresh request also sends `redirect_uri` (GitLab wants it). Delete revokes connections at
  the provider first (four at a time, at most a minute), then deletes and audits in one transaction.
- **Presets** (checked October 2026 against the providers' docs and, for Google, Microsoft and GitLab, their OpenID
  configuration): GitHub (`read:user`; no RFC 7009 endpoint), Google (`openid`, `…/auth/userinfo.email`;
  `access_type=offline`, `prompt=consent`, `include_granted_scopes=true`), Microsoft Entra ID (`{tenant}`, default
  `organizations`; `openid profile email offline_access User.Read`; userinfo `graph.microsoft.com/oidc/userinfo`),
  Atlassian (`read:me offline_access`, `audience`, `prompt=consent`, PKCE off), Slack (`user_scope`, comma,
  `slack_authed_user`, PKCE off; no RFC 7009 endpoint: `auth.revoke` isn't one), GitLab (`{host}`, default `gitlab.com`;
  `openid read_user`; revoke and userinfo). Not verified: whether Atlassian's token endpoint accepts form-encoded
  requests (its docs show JSON bodies; the gateway sends forms) and whether Google/Atlassian/Slack accept the extra
  `redirect_uri` on refresh (RFC 6749 says unknown parameters are ignored); Google and Atlassian PKCE support isn't stated
  on the pages checked (Google's discovery lists S256). `AuthProviderPreset.redirectUri` (added) is the redirect URI to
  register before a provider exists.
- **Requirements.** The effective requirement is computed in Go (`registry.Effective`) everywhere it is shown or used:
  server views, capability lists, catalog, gateway selections, gateway options and the runtime. Widening is checked per
  capability (all capabilities, gone ones too) before and after the change; a URL change and a widening in one PATCH
  produce one review with reason `url_changed`. A provider change or removal resets `scopes` overrides
  (`mcp_server.update` metadata `overridesReset`). A turned-off provider can be kept but not newly chosen
  (`422 provider_not_found`). The override PUT answers the capability (`McpCapability`) with the server's new revision as
  ETag; its audit has `widened`.
- **Runtime.** After the existing checks, for `tools/call`, `prompts/get` and `resources/read` of a capability with a
  requirement: service account → `-32010` `{reason: service_account, provider}`; provider off → `-32010`
  `provider_disabled`; no usable connection → `-32042` (message with the link; `data.elicitations[0]` with `mode`,
  `elicitationId` = the request ID, `url`, `message`), recorded `needs_authorization` with the reason; refresh when
  `expires_at` is within 60 s, under `SELECT … FOR UPDATE` (a waiting replica sees the new token and doesn't refresh
  again; tested with concurrent calls); unavailable provider → `-32010` `provider_unavailable`, recorded
  `upstream_error`. A token that can't be decrypted (rotated `ENCRYPTION_KEY` without the previous key) also becomes
  `needs_reconsent` (class `config`). Refused calls that name a capability also record `providerSlug`.
- **Consent links.** IDs are 32 random bytes (base64url); stored as a base64url SHA-256 digest plus the ID sealed
  (AAD = digest) so a repeated call returns the same link while it stays valid for at least 2 more minutes. Expired and
  used links answer `410` for a day, then the cleanup loop (every 15 minutes, with sessions) deletes them; expired states
  are deleted at once.
- **Start and callback.** States are 32 random bytes, stored as a hex SHA-256, bound to the hex SHA-256 of the session
  ID; the PKCE verifier is sealed (AAD = state digest). `GET /connect/callback` always answers `303`, to the request's
  `returnTo` when connected with every required scope, else to `/connect/done?…&result=` `connected`,
  `missing_scopes` (with one `missing=` per scope not granted), `denied` (provider `error`), `expired` (unknown, used or
  expired state), `wrong_person` (another or no session) or `error` (exchange failed, provider turned off). A reconnect
  keeps the held refresh token when the provider sends none (Google). Accounts are labelled from userinfo
  (`preferred_username`, `email`, `login`, `username`, `name`). Start is rate limited per person (20/min, `429 slow_down`,
  in memory per process).
- **Audit.** As designed; connection entries carry `name` ("person · provider"), `provider` and `userId` metadata; the
  audit log resolves live labels for `auth_provider` and `provider_connection`.

**Local development:** `make fake-oauth` runs `cmd/fakeoauth` on `http://127.0.0.1:8092` (client `fake-client`, secret
`fake-secret-0123456789`; `-ttl 2m` to watch refreshes, `-auto` to skip its consent page). The fake MCP server's
`provider_token` tool reports the provider header, a SHA-256 prefix of the token (never the token), the identity token's
`provider` claim and whether they match.

**Tests:** `internal/providers` (URL rules through the guard without the development allowance, a blocked resolved
address never dialled, token answer parsing incl. form, GitHub-style errors in a 200 and Slack, return paths);
`internal/httpapi/providers_integration_test.go` (the whole flow against the fake provider and fake MCP server: -32042
shape and reuse, request ownership 404/410, open redirects, state single use, wrong person, signed out, expired state,
denial, mix-up, PKCE and scopes in the authorization URL, headers and claim verified by the server, override `none`,
resources, `connected`, missing scopes and the union, refresh with rotation, concurrent refresh, outage, refused refresh,
expired without refresh token, revocation, service account, turned-off provider, reserved headers and slugs, provider
validation, presets, `in_use`, client ID change, delete, request cap, admin views, requirement review under both policies,
and a sentinel over responses, audit, `mcp_calls` and logs); the authz matrix covers all 14 operations.

**Not built / gaps:** as listed under "Not in this phase"; the start rate limit is per process.

