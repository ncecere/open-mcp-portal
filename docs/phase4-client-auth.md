# Phase 4 — Client sign-in (OAuth) and service accounts (design draft)

Status: **built** (backend, UI and the Phase 4 QA follow-ups; see "As built" at the end). Builds on decisions 12, 15–17; open questions answered as decisions 21–24.
Grounded's OAuth server (`internal/oauth`, `docs/mcp.md` "Signing in with OAuth") is the reference, not a dependency.

## Goal

1. Interactive MCP clients (Claude Code, Claude Desktop/claude.ai, VS Code, Cursor) connect to `/mcp/{slug}` with
   no key: the person signs in with the company IdP in a browser, approves the client once, and the client gets
   short-lived tokens it refreshes itself.
2. Headless agents, CI and scripts use **service accounts**: team-owned identities whose keys don't depend on a
   person staying on the team.

## OAuth: the gateway as authorization server

Follows the MCP authorization spec (OAuth 2.1, RFC 9728 protected-resource metadata, RFC 8414, RFC 8707
resource indicators, PKCE S256, RFC 9207 `iss`), like Grounded.

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/oauth-protected-resource/mcp/{slug}` | Resource metadata: `resource` = `<APP_URL>/mcp/{slug}`, authorization server = `<APP_URL>` (already advertised in today's `401`) |
| `GET /.well-known/oauth-authorization-server` | AS metadata: code + PKCE S256 only, public clients (`none`), CIMD supported, DCR endpoint (left out while an admin has turned open registration off) |
| `GET /oauth/authorize` | Authorization code + PKCE; requires `resource=<APP_URL>/mcp/{slug}` exactly; signs the person in (existing OIDC session or redirect) then shows consent in the SPA |
| `POST /oauth/token` | `authorization_code` and `refresh_token` grants |
| `POST /oauth/register` | Dynamic Client Registration (public clients only; `403` while an admin has turned it off; rate limited; at most `OAUTH_MAX_REGISTERED_CLIENTS` live registrations and `OAUTH_MAX_UNUSED_CLIENTS_PER_ADDRESS` unused ones per address; a registration that never received tokens expires after 24 hours, one that did after 30 days unused) |
| `POST /oauth/revoke` | RFC 7009 |

- **Clients:** Client ID Metadata Documents preferred (fetched with the SSRF guard, ≤16 KiB, no redirects, cached);
  DCR for older clients, marked **Unverified** on the consent page. Redirect URIs: https, or http on loopback
  (any port).
- **Tokens** (*proposed*, Grounded's values): code 60 s single use; access token `ompat_…` 1 h; refresh token
  `omprt_…` 30 days, rotated on every use, never beyond `OAUTH_REFRESH_ABSOLUTE_TTL` (180 days by default) after the
  person last signed the app in; a rotated token presented again inside 30 s gets the same pair, later it revokes the
  connection. Opaque, stored as HMAC digests with `API_KEY_PEPPER`.
- **One connection per gateway** (*proposed*): a token is bound to one gateway (`resource`), matching how
  clients add one URL per server. Access is still re-checked on every request.
- **Consent** per person, client and gateway; shows the client (verified host or "Unverified"), the gateway, and
  what it can do. **Trusted clients** (decision 12): platform admins keep an allowlist of client IDs that skip the
  consent screen, seeded with Claude (`https://claude.ai/oauth/mcp-oauth-client-metadata`), Claude Code
  (`https://claude.ai/oauth/claude-code-client-metadata`) and VS Code (`https://vscode.dev/oauth/client-metadata.json`).
  DCR clients can't be trusted (their IDs change). Since v0.2.2 a trusted client asks once, as a short notice, the first
  time a person signs it in to a gateway with a loopback redirect (decision 62).
- **Connected apps:** Account › Connected apps lists clients per gateway with last use and Disconnect; platform admins
  see and disconnect anyone's (user detail page). Suspending a user or removing their access stops tokens at the
  next request.
- **Audit:** `oauth.client_register`, `oauth.consent`, `oauth.grant_confirmed`, `oauth.token_issue`, `oauth.revoke`
  (reason), never a token.
- **Calls:** principal kind `oauth` with the client name.

## Service accounts

- Team-owned; created, edited, disabled and deleted by team **owners and admins**. Fields: name, description,
  **team role** used for minimum-role checks (*proposed*: `member` or `editor`; never owner/admin), enabled.
- **Keys:** `omp_sa_…`, HMAC digest, always expire (max 365 days), at most 2 active per account so keys can be
  rotated without downtime; optionally limited to gateways like personal keys. Shown once.
- **Access** (*proposed*): the team's own gateways (with the account's role), and platform gateways granted to the
  team (a team grant covers the team's service accounts). No direct grants to individual service accounts.
- **Identity JWT:** `sub` = service account ID, new claim `principal_type` = `service_account` (and `user` for
  people), `name` = account name, `teams` = [owning team], no `email`. Upstream docs updated.
- A service account outlives its creator; the team's owners/admins are its responsible people. Archiving the team
  stops it.
- **Calls:** principal kind `service_account`.

## UI

- Team › Service accounts: list, create, record (keys with create-once secret, rotate, revoke; role; enabled).
- Account › Connected apps; Admin › Users › person › Connected apps.
- Admin › Trusted clients (allowlist editor).
- Consent page (`/oauth/consent`) in the SPA, Grounded-style.
- Connect snippets: OAuth becomes the default for Claude Code / VS Code / Cursor (no header); API-key variants stay
  available for headless use.

## Tests that must exist

- Full OAuth flow with a fake client against httptest: metadata, PKCE (plain refused), resource mismatch →
  `invalid_target`, code reuse, refresh rotation and reuse detection, revoke, suspended user, removed access.
- CIMD fetch rules (private address, redirect, size, content type); DCR rate limit and expiry.
- Trusted client skips consent; untrusted/DCR never does.
- Service accounts: authz matrix, key rotation, role/minRole, team grant coverage, archived team, JWT claims.
- Secrets never in responses (beyond creation), audit or logs.

## Resolved questions

All four recommendations accepted (decisions 21–24).

## As built (backend)

Code: `internal/oauth` (authorization server: `authorize.go`, `clients.go`, `metadata.go`, `token.go`, `grants.go`,
`trusted.go`), `internal/serviceaccounts`, `internal/ratelimit`, `internal/httpapi/oauth.go` (protocol endpoints),
`oauth_consent.go` and `service_accounts.go` (`/v1`), and changes to `internal/mcpgw` (three principal kinds),
`internal/gateways` (`ServiceAccountCaller`, `UsableByServiceAccount`), `internal/identity` (`principal_type`),
`internal/calls`, `internal/auth` (`SessionUser`, `LoginURL`). Migration `00008_client_auth.sql`. People's guide:
[connect-clients.md](connect-clients.md); server authors: [upstream-identity.md](upstream-identity.md).

**OAuth.** Always on (no setting). Grounded's rules, adapted:

- **Endpoints** (outside the OpenAPI contract; the contract test skips `/oauth/` and `/.well-known/`):
  `GET /.well-known/oauth-protected-resource/mcp/{slug}` (`resource`, `authorization_servers` = `[APP_URL]`,
  `bearer_methods_supported`, `resource_name` = instance name; served for **any** well-formed slug without looking the
  gateway up, so it doesn't reveal which gateways exist; a malformed slug is `404`), `GET /.well-known/oauth-authorization-server`
  (code + `S256` only, `none` auth, `client_id_metadata_document_supported`, `authorization_response_iss_parameter_supported`,
  registration and revocation endpoints; no `scopes_supported`: there are no scopes, a `scope` parameter is ignored and
  the token response has none), `GET /oauth/authorize`, `POST /oauth/token`, `POST /oauth/register`, `POST /oauth/revoke`
  (`GET` on the three POST endpoints is `405`, never the web app). The `/mcp` 401 challenge is unchanged.
- **Authorize order** (as of v0.2.2; see "As built: v0.2.2" for what changed). The **browser session** comes first:
  none → `302` to sign in and back (`/auth/login?next=…` with OIDC; the web app's sign-in page `/?next=…` with only the
  development login), before the client is looked at. Signed in: a suspended person gets a page. Then a query > 8000
  characters, a repeated parameter, an unknown/unfetchable client, a missing or
  unregistered `redirect_uri` or a `state` over 1000 characters: an HTML **page** (400, never a redirect). Then errors go
  back to the client with `state` and `iss`: `unsupported_response_type`, `invalid_request` (no PKCE, `plain`, malformed
  challenge), `invalid_target` (resource missing or not exactly `<APP_URL>/mcp/{slug}`). The resource must be a gateway they may use **now**
  (exists, enabled, team not archived, access); otherwise `invalid_target` (unknown, off and no-access look the same,
  checked only after sign-in). Then a **remembered** consent (active grant for person + client + gateway) or a
  **trusted** client issues the code at once; anyone else is sent to `/oauth/consent?<the same query>`.
- **Consent API.** `GET /v1/oauth/consent` re-checks the request: problems are `400` with code `oauth_<error>` (for
  example `oauth_invalid_request`, `oauth_invalid_client`), a resource that isn't a gateway the caller can use is
  `404 gateway_not_found`. `client.trusted` is true only for metadata clients on the list. `POST` (CSRF token) with
  `allow` creates the grant (audited `oauth.consent`, metadata `how: allowed`, or `oauth.grant_confirmed`, `how:
  confirmed`, for the first-use notice below) and a code; `deny` returns `access_denied`. `notice` in the GET answer says
  the page is that notice. The query is re-validated on POST, so the page can't widen anything.
- **Clients.** Metadata documents are fetched with `internal/upstream`'s address guard (`Client.GuardedDial`): public
  addresses; internal ones only inside the allowlist of internal networks (decision 20); loopback, link-local and
  metadata never — except with the development allowance, which also accepts a document at a plain-`http` loopback URL
  (production: https only). No proxy, no redirects, 5 s, ≤ 16 KiB, `application/json` (or `+json`), `client_id` must
  equal the URL, cached for `max-age` clamped to 1 min–1 h (10 min default). DCR: public clients only, IDs `ompcl_…`,
  10/min/address, unused registrations deleted after 30 days, or 24 hours when they never received tokens (on the
  next registration; an expired one is refused at once); audited `oauth.client_register` by the system with the client IP. Since v0.2.1 at most
  `OAUTH_MAX_REGISTERED_CLIENTS` (default 1000, `0` = no cap) registrations used within the 30 days may exist: the
  count, the deletion of expired ones and the insert run in one transaction under an advisory lock, and over the cap
  the answer is `503 temporarily_unavailable` (OAuth error body, no `Retry-After`: a slot frees only when a
  registration has gone unused for 30 days), logged, not audited. Metadata-document clients aren't rows and never count.
- **Trusted clients.** `oauth_settings` (one row, own revision), seeded with Claude, Claude Code and VS Code. Entries
  must be https metadata-document URLs with a path (`422 invalid_client_id`, `details.index`, `details.reason`
  `not_metadata_url`/`duplicate`/`too_many`; a label over 100 characters is `400 invalid_label`). Read from the database
  on every authorization (no cache). A trusted client's first connection is still audited `oauth.consent` (`how: trusted`).
- **Tokens.** Code `ompac_` 60 s single use (deleted before any check); access `ompat_` 1 h; refresh `omprt_` 30 days,
  rotated; reuse within 30 s gets the same pair again (v0.2.2; v0.2.1 minted another), later reuse revokes the grant
  (`refresh_reuse`); past the absolute lifetime the grant is revoked (`expired_absolute`, v0.2.2). Stored as hex
  HMAC-SHA256 of `"oauth:" + token` under `API_KEY_PEPPER` (no previous-pepper support: rotating the pepper signs every
  client out). An access token is accepted only by `/mcp/{slug}` of its gateway (another gateway: `401 invalid_token`
  with that gateway's challenge) and never by `/v1`. Every request re-checks token expiry, grant, person active (`401`),
  and access to the gateway (`404`, recorded `denied`), like API keys. Grants are deleted with their gateway.
- **Revocation.** RFC 7009: a refresh token revokes the connection, an access token only itself; another client's
  token or junk is a no-op `200`. Connected apps: `DELETE /v1/me/oauth-grants/{id}` (reason `user`), platform admins
  `DELETE /v1/admin/users/{id}/oauth-grants/{id}` (reason `admin`; auditors `403`). Unknown user on the admin list: `404`.
- **Rate limits** per address (shared in PostgreSQL since v0.2): 60/min on authorize, token and revoke, 10/min on
  register; `429 slow_down` with `Retry-After`. Registration also has the global cap above (`503`, not `429`: it
  isn't about the caller's rate).
- **Audit:** `oauth.client_register` (target `oauth_client`), `oauth.consent`, `oauth.token_issue` (`grantType`),
  `oauth.revoke` (`reason`; `token: access` for a single access token) on target `oauth_grant` (label
  "client · gateway"; team set for team gateways on consent and revoke), `settings.oauth_clients_update` (target
  `platform_settings`/`oauth_clients`). Actions by a client carry `via: oauth` and `client`. Never a token.

**Service accounts.** Names `^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$` unique per team (`409 name_taken`), at most 100 per
team (`409 too_many_service_accounts`), role `member`|`editor` (`400 invalid_role`). Owners/admins write (platform roles
`403` through team routes, like gateways); members and platform staff list/get; owners/admins and platform staff list
keys. Archived teams are read-only (`409 team_archived`). Keys `omp_sa_` + 43 characters (prefix stored `omp_sa_` + 8),
HMAC with the pepper, 1–365 days (default 90), at most 2 active (`409 too_many_keys`), not for a turned-off account
(`409 disabled`), optional `gatewayIds` (≤ 50 after de-duplication, each one the **account** can use now, else
`422 gateway_not_usable`). Revoking a revoked key is a no-op. Deleting an account deletes its keys; call records keep
its name (`mcp_calls.service_account_name`, `key_name`).

- **Runtime.** A turned-off or deleted account, an archived team, or a revoked/expired key is `401` at the next request.
  Access: the team's own gateways (role used for `minRole`) and platform gateways with a **team grant** to its team
  (user and group grants never cover it). Key scopes behave like personal ones (`key_scope`).
- **Identity JWT:** every token now has `principal_type` (`user` | `service_account`); a service account's has `sub` =
  its ID, `name`, `teams` = [its team], no `email`; OAuth calls' `client` is the client's name, with `client_verified`
  (QA follow-ups below).
- **Call records:** `principal_kind` `api_key` | `oauth` | `service_account`; `user_id` is NULL for service accounts
  (a CHECK ties the columns to the kind). `CallPrincipal`: `userId`/`email` for people, `apiKeyName` for keys,
  `oauthClientName` for OAuth, `serviceAccountId`/`serviceAccountTeamSlug` for accounts. `?serviceAccount=` filters
  team and admin call lists. Team call lists mean "through the team's gateways, to its servers, or by its service
  accounts" (the last added by the QA follow-ups below).
- **Audit:** `service_account.create/update/delete` (target `service_account`) and `service_account_key.create/revoke`
  (target `service_account_key`, label "account · key"), all with the team; never a secret.

**Contract:** no changes to `api/openapi.yaml` were needed for the backend; the QA follow-ups below added some.

**Tests:** `internal/oauth` (address guard with netpolicy entries for documents, cache, PKCE, redirect matching, resource
shape, trusted-list validation), `internal/httpapi/oauth_integration_test.go` (discovery, authorize validation as page vs
redirect, sign-in redirect, consent allow/deny/CSRF, remembered and trusted consent, registered clients never trusted,
code reuse, wrong verifier, refresh rotation and reuse revocation, revoke endpoint, token bound to its gateway, connected
apps, DCR expiry, document fetch rules, rate limits, re-checks without reaching the server, token sentinel),
`service_accounts_integration_test.go` (management, key limits and rotation, role vs `minRole`, team-grant coverage,
off/archived/expired/revoked/deleted refusals, JWT claims verified by the fake server, scope, call filter, secret
sentinel), and the authz matrix for every new operation.

**Not built / gaps:** rate limits on `/mcp` itself; per-tool scopes or step-up; private-use redirect schemes; CORS on
the OAuth endpoints; previous-pepper support; DCR expiry runs only when someone registers (an expired registration is
refused regardless); rate counters are per process.

## As built: QA follow-ups

**Contract changes** (additive; existing clients keep working):

- `GET /v1/teams/{team}/service-accounts/{serviceAccountId}/gateways` (`listServiceAccountGateways`; members and above,
  platform staff read any team): the gateways the account can use now, as `MyGateway` items ordered by name: its team's
  enabled gateways (`access: [team_member]`) and enabled platform gateways granted to its team (`access: [team_grant]`).
  `capabilityCount` is what the account reaches (availability, and its role for `minRole` on team gateways). Empty
  while the team is archived; a turned-off account still lists them. `gateways.Service.ListForServiceAccount`,
  `serviceaccounts.Service.Gateways`, query `ListGatewaysForServiceAccount`.
- `GET /v1/admin/service-accounts` (`adminListServiceAccounts`; platform admins and auditors): a `ServiceAccountPage`
  (new schema) ordered by (name, id) with `q` (account name, team slug or name), `team` (slug or ID; unknown lists
  nothing), `cursor`, `limit`. Query `AdminListServiceAccounts`.
- `GET /v1/teams/{team}/calls` (and Admin › Calls' `team` filter) also lists calls made by the team's service accounts
  through **any** gateway (a platform gateway granted to the team, or a refusal on another team's gateway); documented in
  the operation's description. Index `mcp_calls_service_account_team_idx`.
- `CallPrincipal.serviceAccountExists` (service_account: false once the account is deleted) and
  `CallPrincipal.oauthClientVerified` (oauth: true for metadata-document clients, false for registered ones). Calls now
  record the client's kind (`mcp_calls.oauth_client_kind`); older records read it from the grant while it exists.
- Identity JWT: `client_verified` (bool) whenever `client` is an OAuth client's name; absent otherwise.
  [upstream-identity.md](upstream-identity.md) says a registered client's `client` is self-asserted.

Migration `00009_call_principals.sql` (a nullable column and an index).

**Behaviour and UI:** Client ID Metadata Document fetches are logged at info level ("oauth client metadata document
fetched": host, HTTP status, outcome such as `ok`, `http_status`, `blocked_address`, `redirect`, `too_large`, and the
duration; never the document or its path). The "Can't connect this app" page follows the person's color mode (the
app's `/color-mode.js`, CSP `script-src 'self'`, dark styles; the system's setting without script). Service account
Overview's Access card and the key dialog's "Limit to gateways" use the new endpoint (counts per the account's role;
granted platform gateways listed and choosable). Admin › Calls' service account filter lists every team's accounts
(searchable, "name (team)"; the chosen team's when a team is chosen). Call rows: a deleted service account is plain
text ("Deleted service account · team · Key: …"), service account rows name the key, apps that registered themselves
read "via <name> (unverified)". The key dialog shows "Next: finish the rotation" only when another key was active
before the new one (captured when Create is pressed), once. The sign-in page reached from `/oauth/…` says an app is
waiting to connect. Suspend-user and team-grant dialogs say what they cover. The service account header says "Never
used"/"Used …" and shows one notice for turned off and/or archived. The trusted-client dialog focuses the first
invalid field.

**Tests:** `TestServiceAccountGatewaysAndAdminList` (role vs `minRole`, team grant vs person grant, other team's and
turned-off gateways, archived team, 404s, admin list search/team/paging/403/400), `TestServiceAccountsAtTheGateway`
(team call list includes the account's calls through platform and other teams' gateways; `serviceAccountExists`
before and after delete; no `client_verified` for keys), OAuth flow tests (`client_verified` true/false in the JWT,
`oauthClientVerified`, recorded kind; the error page's color mode and CSP), `TestMetadataDocumentFetchLogging`, the
authz matrix for both new operations, the doctor's migration version. Vitest: service accounts (Access card, key
scope with a platform gateway, rotation note only after a previous key, one combined notice, "Never used"), calls
(unverified apps, deleted accounts, key names, admin filter without a team), sign-in note, trusted-client focus,
suspend and grant wording.

## As built: v0.2.2 hardening (H-1, H-3, H-4, H-8)

Migration `00018_oauth_hardening.sql` (expand only). Decisions [62 and 63](decisions.md); threat model
[section 9](threat-model.md#9-hardening-ideas-not-findings).

**Nothing is fetched before sign-in (H-3).** `GET /oauth/authorize` without a session sends the browser to sign in with
the whole query and looks at nothing: the client's metadata document is not fetched and no reason is given, whatever
the client, redirect or resource. The two requests malformed on their face (a query over 8000 characters, a repeated
parameter) get one generic "Can't connect this app" page with no reason and no code, the same bytes for both. After
sign-in the request is checked as before and a bad client gets the same pages with their reasons; a person with a bad
client now learns it after signing in rather than before. Fetches that the cache doesn't answer are counted per source
address (the address the portal sees, `TRUSTED_PROXIES` applied) at **20 a minute**, in the same PostgreSQL counters as
the other limits; over it, the signed-in person gets a `429` page (`slow_down`) and the consent page's own check answers
`429 oauth_slow_down`. Cache hits and anonymous requests don't count. Tests: `TestOAuthAuthorizeAnonymousFetchesNothing`,
`TestOAuthMetadataFetchCapPerAddress`, `TestMetadataFetchesAreLimitedPerAddress`.

**Open client registration (H-4).** Three controls on top of `OAUTH_MAX_REGISTERED_CLIENTS`:

- *The switch.* Admin › Trusted clients › "Allow open client registration" (`oauth_settings.open_registration`, on by
  default; the same `PUT /v1/admin/settings/oauth-clients` and revision as the trusted list, so it is session-only: a
  platform token can't change it, decision 58). Off: the authorization server metadata leaves out
  `registration_endpoint` and `POST /oauth/register` answers `403 access_denied` (before the body is read; nothing
  stored or audited). Apps already registered keep working, and apps that use a metadata document, such as Claude Code,
  are not affected. Audited in `settings.oauth_clients_update` (`openRegistration` before and after).
- *Shorter life when never used.* `oauth_clients.authorized_at` is set when a registered client first receives tokens. One
  that has none 24 hours after it registered is gone (it no longer resolves, and the next registration deletes the
  row); one that has lives until it has been unused for 30 days, as before. Upgrade: registrations that already had a
  grant keep working.
- *Per-address cap.* `OAUTH_MAX_UNUSED_CLIENTS_PER_ADDRESS` (default 20, `0` = no cap): one source address can hold at
  most that many registrations that have not received tokens yet (`oauth_clients.registered_from`, the address as the
  portal saw it); the next is refused with `429 slow_down` and stores nothing. A registration that signs in stops
  counting, and unused ones leave after 24 hours. It counts only unused registrations **on purpose**: those are the only
  ones a caller can create without a person (receiving tokens takes someone signing in), and behind an ingress without
  `TRUSTED_PROXIES` every caller shares one address, so counting the used ones too would turn the cap into a limit of 20
  apps for the whole company. The count and the insert run under the same lock as the global cap.
- `open-mcp-portal doctor` prints an info line: whether registration is on, and the live registrations against the cap.

Tests: `TestOAuthRegistrationSwitch`, `TestOAuthUnusedRegistrationsAgeOut`, `TestUnusedRegistrationAgesOutAfter24Hours`,
`TestOAuthRegistrationsPerAddress`, `TestUnusedRegistrationsPerAddress*`, `TestRegistrationSwitchOff`, the doctor test,
and `TestOAuthTrustedRegisteredAndConnectedApps` (a dynamically registered client, the way pi signs in, completes the
authorization code + PKCE flow, refreshes and is revoked). **Not done:** a browser-only (`Sec-Fetch`) check, which would
break the native apps and CLIs that register; the open-redirector point of OA-2 is unchanged.

**First-use notice for trusted loopback clients (H-1).** A trusted client (a metadata document on the admins' list) with
a loopback redirect (`http` on `localhost`, `127.0.0.1` or `::1`, any port) and no grant for this person and gateway
gets the consent page's *notice* variant instead of an immediate code: who trusts it, what it receives and where
("on this computer, at localhost:54321"), Continue and Cancel. Continue creates the grant (audited
`oauth.grant_confirmed`, `how: confirmed`) and the code; later sign-ins are silent, on any port. Cancel is
`access_denied`. It is asked again after the app is disconnected (the grant is the memory), for another gateway and
for another person, and never for a trusted client with an `https` redirect (the usual Claude and VS Code web
redirects). People who already connected a trusted client before the upgrade have grants and are not asked. This is
Claude Code's normal desktop flow: its metadata document (`https://claude.ai/oauth/claude-code-client-metadata`, read
on 2026-10-20) lists `http://localhost/callback` and `http://127.0.0.1/callback`, which `matchRedirect` accepts on any
port, and it opens the browser at `http://localhost:<port>/callback`; the only change is one confirmation page the
first time. `TestOAuthTrustedLoopbackFirstUseNotice` walks that flow end to end (document with
`http://localhost/callback`, trusted by an admin, authorize with `localhost:54321`, notice, deny and continue, code
exchange with PKCE, the token on `/mcp`, second sign-in silent, another person, another gateway, disconnect, an `https`
redirect unaffected). **Residual:** after the first confirmation a local process can still start a flow with the
trusted client's ID and a loopback redirect without being asked, and one that drives the person's real browser can
press Continue; the notice narrows the silent window, and it gives the person a chance to refuse a flow they did not
start. Real Claude Code was exercised on a real deployment at v0.2.1 (status.md); the notice version has been tested
against the fake client only.

**Refresh tokens (H-8).** `OAUTH_REFRESH_ABSOLUTE_TTL` (default `180d`; `0` turns it off; `180d` or Go durations such as
`4320h`, 1 hour to 10 years). The lifetime is counted from `oauth_grants.authorized_at`: set when a grant is created and
set again whenever the person completes an authorization for a grant that already exists (signing the app in again).
A refresh at or after `authorized_at + TTL` revokes the grant (`expired_absolute`) and answers `invalid_grant`; the
access token it had stops at once (it would have been refused within the hour anyway). Connected apps shows "Sign-in
expires" per app (`OAuthGrant.expiresAt`; "Expired" past it for a grant nobody has refreshed since). **Upgrade:** every
grant active when `00018` runs gets one whole window from that moment, however old it is, so nobody is signed out by the
upgrade; the first re-sign-in a client is asked for is one TTL later. **Inside the grace**, a refresh token that was
rotated less than 30 seconds ago gets the pair its rotation issued, not another one: the pair is derived from the
presented token under the pepper, so nothing is stored in the clear and a repeat creates no rows
(`TestOAuthRefreshGraceReturnsTheSamePair`: three repeats, same tokens, same row count, audited with `repeat: true`; the
absolute lifetime applies there too). Outside the grace the grant is revoked, as before. A client that refreshes twice
at once therefore holds one chain, not two. Tests also: `TestOAuthRefreshAbsoluteLifetime`,
`TestOAuthRefreshAbsoluteLifetimeConfig` (`0` keeps today's behaviour), `TestOAuthMigration00018KeepsWhatWorks` (the
migration's Down and Up on a database with a 400-day-old grant).

## Browser sessions (#37, decision 76)

Browser sign-ins are separate from OAuth connected apps, API keys and provider connections. Account › Sessions
(`/settings/sessions`) lists active sign-ins, newest first: browser/device parsed from the self-reported user agent,
stored address, sign-in time, last recorded activity and absolute expiry. The current session is marked. A person can
sign out any one, or choose **Sign out everywhere**; **Keep this session signed in** is optional and off by default.
The adjacent **Connected apps** link manages MCP clients independently. Admin › Users › person has a Sessions card
for **platform admins only**; auditors cannot list or revoke browser sessions.

API (all **browser-only**, no `x-omp-token-scopes`):

- `GET /v1/me/sessions` (`listMySessions`), `DELETE /v1/me/sessions/{sessionId}` (`revokeMySession`);
- `POST /v1/me/sessions/revoke-all` (`signOutEverywhere`), optional body `{keepCurrent: true}`; no body or false
  ends the current session too;
- `GET` / `DELETE /v1/admin/users/{userId}/sessions` (`adminListUserSessions`, `adminRevokeUserSessions`).

IDs are session row UUIDs, never secrets or cookie digests. Unknown and foreign session IDs are both
`404 session_not_found`; an unknown admin target is `404 user_not_found`. A revoked session's next request is
`401`. Self-revocation clears its cookie. Every write checks CSRF and Origin. The mutation, cancellation of
`provider_auth_states` bound to ended session IDs and audit (`session.revoke`, `session.revoke_all`,
`session.admin_revoke`, target user, metadata `{count}` only) commit together. Logout cancels its bound states too.
A callback still requires a valid session identity; signing in again cannot complete the old flow. Already-running
requests are not cancelled. Other credentials are untouched and no notification is emitted.

`SESSION_TTL` is still the absolute limit (default 12h). Optional `SESSION_IDLE_TIMEOUT` defaults to `0` (off),
and when enabled accepts 5m through `SESSION_TTL`; 8h is suggested. `RequireSession`, `SessionUser` and
`SessionIdentity` all check both limits before touching activity. A recent session needs only a read; a stale one
uses a conditional write, at most once a minute across replicas. Idle expiry is measured from the recorded activity,
so it may occur up to a minute earlier than the last request plus the timeout. At either boundary the browser gets
the existing expired-session response and signs in again. Cleanup deletes idle and absolute-expired rows.
Migration `00028_session_activity.sql` adds `last_seen_at NOT NULL DEFAULT now()` and an index; sessions present
at upgrade receive one idle window from then, retaining their original absolute expiry. The old release still works
with the expanded schema, but does not enforce idle expiry or update activity; finish a rolling upgrade before
relying on the idle control.

Tests: `TestBrowserSessions`, `TestSignOutEverywhere`, `TestSessionActivityAndIdleExpiry` (injected clock),
`TestSessionRevocationAuditRollback`, `TestSessionRevocationCancelsConnect`, `TestSignOutOthersKeepsCurrentConnect`,
the authorization and token matrices, config `TestSessionIdleTimeout`, and Vitest `sessions.test.tsx` (including axe).
No new dependency. OAuth refresh absolute lifetime (H-8) was already implemented separately (decision 63).
