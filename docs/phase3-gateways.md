# Phase 3 — Gateways (design draft)

Status: **built** (backend and UI; see "As built" at the end). Open questions were answered as decisions 15–19 in
[decisions.md](decisions.md). Items still marked *proposed* (key rotation period, call outcomes) are defaults that may be
tuned.

## Goal

A gateway is a curated set of capabilities at `/mcp/{slug}`. A client connects with a credential, sees only what
it may use, and every upstream call carries a signed identity of the user. Calls are recorded as metadata.

## Data model

| Table | Columns (main) |
|---|---|
| `gateways` | id, slug (global, immutable), name, description, owner_kind `team`/`platform`, team_id (team gateways), enabled, capture_payloads (Phase 6; stored now, default false), revision, timestamps |
| `gateway_capabilities` | gateway_id, capability_id, min_team_role (team gateways only; nullable), added_by/at |
| `gateway_grants` | gateway_id, subject_kind `team`/`user`/`group`, team_id / user_id / group (exactly one), added_by/at |
| `signing_keys` | kid, alg `ES256`, private key (encrypted with `ENCRYPTION_KEY`), public JWK, state `next`/`active`/`retiring`/`retired`, created_at, activated_at, retire_after |
| `api_keys` | Grounded's personal keys: prefix, HMAC digest, user_id, name, expires_at, revoked_at, last_used_at (*proposed*: Phase 3, see Q1) |
| `mcp_calls` | time, gateway, server, capability, method, principal (user / key), client name, outcome, error class, latency, request/response bytes, request_id. No arguments or results |

`users.groups` (last-seen IdP groups from the configured groups claim) comes back from Grounded for group grants.

## Who may build what

- **Team gateways** — team owners/admins create and edit (decision 16). They may select:
  - any capability of the team's own servers (private or published, enabled, listed), and
  - approved capabilities of published catalog servers.
  Access: the team's members, filtered by each capability's optional minimum role.
- **Platform gateways** — platform admins create and edit. Only approved capabilities of published servers.
  Access: explicit grants to teams, users or SSO groups. No minimum-role setting.
- Auditors read everything; members can read the team's gateways and copy their connection details.

## Runtime (`/mcp/{slug}`)

- Streamable HTTP, stateless; `POST` only at first (`GET`/`DELETE` → 405). JSON responses; upstream SSE streams
  are relayed for `tools/call`.
- Methods (the 2026-07-28 era adds `server/discover` and drops `ping`; [mcp-protocol.md](mcp-protocol.md)): `initialize`, `ping`, `tools/list`, `tools/call`, `prompts/list`, `prompts/get`, and (follow-up, see
  "Resources" under "As built") `resources/list`, `resources/templates/list`, `resources/read`.
- Exposed names: `{server-slug}__{name}` for tools and prompts; titles and descriptions as approved.
- Every list and every call re-checks: credential valid, user active, gateway enabled, caller granted, capability
  still selected, role satisfied, server enabled, and either team-owned (team gateway) or published with the
  current fingerprint approved. A failed check on a call looks like "not found".
- Limits: 1 MiB request/response, the server's timeout, SSRF guard on every dial. Sampling, elicitation and roots
  are refused.
- Unauthenticated: `401` with `WWW-Authenticate: Bearer resource_metadata=".../.well-known/oauth-protected-resource/mcp/{slug}"`
  so Phase 4's OAuth slots in without changing clients.

## Identity sent upstream

- JWT, ES256, `kid` header. Claims: `iss` (APP_URL), `aud` (server URL), `sub` (user ID), `email`, `name`,
  `teams` (slugs), `gateway` (slug), `tool` (exposed name), `client` (key/client name), `iat`, `exp` = 5 min, `jti`.
- *Proposed* header: `Authorization: Bearer <jwt>` when the server has no static `Authorization` header (servers can
  act as ordinary OAuth resource servers and validate against JWKS); otherwise `MCP-Gateway-Identity: <jwt>`.
- `GET /.well-known/jwks.json` publishes the next, active and retiring keys. A new key is generated on first use and
  rotated every 30 days; the next key is published a day before it signs, and retiring keys stay published for one day
  after rotation.
- `docs/upstream-identity.md` will show servers how to verify the token (Go, Python, TypeScript snippets).

## Management API (to be added to `api/openapi.yaml`)

```text
GET/POST          /v1/teams/{team}/gateways
GET/PATCH/DELETE  /v1/teams/{team}/gateways/{gatewayId}
GET/PUT           /v1/teams/{team}/gateways/{gatewayId}/capabilities      (whole selection, If-Match)
GET               /v1/teams/{team}/gateway-options                       (selectable capabilities)
GET/POST          /v1/admin/gateways
GET/PATCH/DELETE  /v1/admin/gateways/{gatewayId}
GET/PUT           /v1/admin/gateways/{gatewayId}/capabilities
GET/POST/DELETE   /v1/admin/gateways/{gatewayId}/grants[/{grantId}]
GET               /v1/me/gateways                                        (what I can connect to, with URLs)
GET/POST/DELETE   /v1/me/api-keys[/{keyId}]                              (if Q1 = yes)
GET               /v1/teams/{team}/calls, /v1/admin/calls                (call metadata, filters)
GET               /.well-known/jwks.json                                 (outside OpenAPI, like /mcp)
```

## UI

- Team › Gateways: list, create (takeover), record with Overview (URL + "Connect" snippets for Claude Code,
  VS Code, Cursor), Capabilities (picker grouped by server, own vs catalog, min role), Activity (calls), Settings.
- Admin › Gateways: same plus Access (grants: teams, users, SSO groups) and the platform-wide call log.
- Workspace › My gateways: everything the person can use, with connect snippets.
- Account › API keys (if Q1 = yes).

## Tests that must exist

- Authz matrix for every new operation; a foreign team's capabilities can't be selected.
- Runtime: list shows only allowed items; revoke grant / unpublish server / change fingerprint / disable gateway /
  suspend user / revoke key between `tools/list` and `tools/call` → the call is refused without contacting the
  upstream.
- JWT: signature verifies against JWKS, `aud` is the server URL, expiry ≤ 5 min, rotation keeps old tokens valid
  until expiry; the client's credential is never forwarded upstream.
- No arguments/results in `mcp_calls` or logs.

## Resolved questions

1. Personal API keys ship in Phase 3 (own implementation). OAuth and service accounts in Phase 4.
2. Team gateways: owners and admins edit; members read and connect.
3. Team gateways are members-only; cross-team sharing uses platform gateways.
4. Tools and prompts first; resources later.
5. Identity header as proposed.

## Gateway access requests (v0.6.0, #32)

Decision 83 and [access-requests.md](access-requests.md) describe the implemented opt-in request workflow.
Session-only `/v1/admin/gateways/{id}/access-settings` manages discoverability and at most 50 named stewards;
stewards decide only that gateway's requests, never their own, and gain no other management/MCP authority.
User or administered-team requests and grant decisions are transactional. `GatewayGrant.expiresAt` and optional
`GatewayGrantCreate.expiresInDays` (1–365, otherwise permanent) add temporary grants without changing existing
permanent ones. All effective-grant SQL and final MCP/approval transport checks enforce expiry; cleanup is
not enforcement. Migrations `00043`–`00045` are expand-only. **Drain previous serving/background-worker
replicas before enabling requests or expiry:** schema compatibility does not mean older images enforce
deadlines or deliver the new private notice types. Publication/acceptance evidence belongs in
[status](status.md), not a local version string.

## As built (backend)

Code: `internal/gateways` (service, availability, grants), `internal/mcpgw` (`/mcp/{slug}`), `internal/identity`
(signing keys, JWKS, rotation loop), `internal/apikeys`, `internal/calls`, migration `00004_gateways.sql`. Server authors:
[upstream-identity.md](upstream-identity.md). Where this differs from or adds to the design above:

- **Gateway options** (`GET /v1/teams/{team}/gateway-options`, `GET /v1/admin/gateway-options`) answer a page
  `GatewayOptionPage {items, nextCursor}`, ordered by server name, server ID, name, ID (keyset cursor). Parameters: `q`
  (name, title, server name or slug), `kind` (`tool`, `prompt`, `resource`, `resource_template`), `server` (server ID),
  `cursor`, `limit` (default 100, at most 500). The picker searches on the server (debounced), filters by kind and
  server, and loads more by cursor; the selection is kept apart from what is loaded, so it survives paging and search.
- **Selection.** New capabilities must be offered by gateway-options; capabilities **already selected may stay** in a
  `PUT` even while unavailable (for example a catalog server that left the catalog), since every call re-checks them.
  Exposed names and exposed URIs must be unique **case-insensitively and across every kind** (`409 name_taken` for two tools; `422 name_clash` for other collisions). Other
  errors: `400 duplicate_capability`, `400 invalid_role`, `422 min_role_not_allowed` (minRole on a platform gateway; the
  contract only says "must be absent"), `422 too_many`, `422 capability_not_selectable` (`details.capabilityIds`, and
  `details.reasons` mapping each ID to `unsupported_template` or `not_offered`).
- **Per-selection tool curation (#30, decision 80).** Owners/admins may constrain top-level arguments to fixed or allowed values, rename tools and rewrite their descriptions for one gateway only. Policies are fingerprint-bound; stale policy stays unavailable even after catalog reapproval. Selection omission preserves policy, explicit null clears it, and every explicit edit requires the current `expectedFingerprint` plus gateway `If-Match`. The model sees a narrowed copy; call checks and fixed-value injection precede consent and retry binding. Constraint values are never audited. See [gateway-curation.md](gateway-curation.md) for the schema subset, bounds, API semantics and mixed-version rollback warning.
- **Availability order:** `gone` (also any kind that can't be selected), `team_archived` (the server's team, or a team gateway's
  own team, is archived), `server_disabled`, `curation_stale`, then for catalog capabilities `not_published`, `not_approved`, `changed`.
  A team gateway's own servers need no approval. `GatewayStats` (SQL) mirrors the Go rule; a test checks they agree.
- **Archived teams.** Archiving changes no data, so unarchiving restores everything. While a team is archived its team
  gateways answer `/mcp/{slug}` with `404` (lists and calls recorded as denied, `errorClass` `team_archived`), drop out
  of My gateways, and show every selected capability as `team_archived`; its servers leave the catalog,
  gateway-options and the health loop, and other teams' and platform gateways mark their capabilities `team_archived`
  (kept in a selection, not addable). Every list and call re-checks this.
- **Access.** Platform admins and auditors read every gateway but can only *use* a team gateway if they are members, and a
  platform gateway if granted. Group grants match `users.groups` exactly (case-sensitive); `/v1/me` returns the stored groups and
  `MyGateway.groups` names the caller's groups a gateway is granted to. Platform admins may switch a team gateway off/on (`PATCH enabled`), nothing else (`403 team_gateway`);
  `GET …/grants` of a team gateway is `[]`.
- **Runtime.** Lists are served from the stored, approved definitions (name replaced by the exposed name) without
  contacting servers, paged at 512 KiB with an opaque cursor. Calls are buffered (the SDK client reads an upstream SSE
  stream; no relay), response ≤ 1 MiB. Negotiated versions: 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05. An
  `MCP-Protocol-Version` header outside these (and older than 2026-07-28) is `400`. Requests of the 2026-07-28 era
  (chosen per request) are served too, with `server/discover`, header validation, `resultType` and cache hints:
  see [mcp-protocol.md](mcp-protocol.md). Without the modern signs `server/discover` is "method not found", so
  older clients are unaffected. JSON-RPC batches are `400`. A foreign `Origin` is `403`. Unknown
  or disabled gateways and no access are HTTP `404`; refused calls are JSON-RPC `-32602 Unknown tool/prompt`.
  Notifications get `202`. `clientInfo.name` is recorded when the same request carries it (`initialize`, or the
  2026-07-28 `_meta` `io.modelcontextprotocol/clientInfo`); otherwise omitted.
- **Call records.** Denied rows carry `errorClass`: `gateway_disabled`, `no_access`, `role`, `unknown`, or an
  unavailability reason. Upstream failures use the registry's error classes; JSON-RPC invalid params from the server is
  `bad_request`. Initialize and ping are not recorded. `mcp_calls` is append-only (trigger, like `audit_log`).
- **Identity JWT.** Adds `nbf` (iat − 30 s). `prompts/get` carries `prompt` instead of `tool`. `client` falls back to the
  API key's name. A replica caches the active key for 1 minute; the rotation loop (advisory lock
  `omp.signing-key-rotation`) checks hourly. The first key on an empty table is created on first use or at start-up
  and signs at once. After that the loop creates the next key (state `next`: published in the JWKS, not signing) at
  least `SIGNING_KEY_PREPUBLISH` (default 24h, 0–7 days) before the active key has signed for 30 days, and promotes it
  once the active key is due and the next key has been published that long (a late next key delays the rotation).
  Verifiers should still refetch the JWKS for an unknown `kid`. Retiring keys stay published for 1 day, then their
  private key is erased (migration `00005_signing_key_next`).
- **API keys.** `omp_` + 43 URL-safe characters; HMAC-SHA256 with `API_KEY_PEPPER` (32 bytes base64, required by
  `serve`, the `.env.example` value refused off loopback). Revoking a revoked key is a no-op `200`.
- **API key scopes** (follow-up; migration `00006_gateway_resources_key_scopes`, table `api_key_gateways`).
  `ApiKeyCreate.gatewayIds` (optional, at most 50, `400 too_many_gateways` beyond; duplicates collapse) limits a key to
  those gateways. Each must be one the creator can use when the key is created (exists, enabled, a team gateway's team
  active, and access), otherwise `422 gateway_not_usable` with `details.gatewayIds`. Empty or absent: every gateway the
  owner can use. `ApiKey.gateways` lists `{id, slug, name, exists}` by name (empty = all). On `/mcp/{slug}` a key used
  outside its scope is `404`, recorded `denied` with error class `key_scope` (checked before the gateway's switch and
  the owner's access). A scope never widens access: the owner's access is checked on every request as before. The
  scope entry has no foreign key, so deleting a gateway leaves it (shown with `exists: false` and the slug and name as
  they were); a key whose gateways are all gone works nowhere, and Account › API keys warns about it. The create
  dialog has an optional "Limit to gateways" multi-select of My gateways; after creation, "Connect a gateway" offers
  only the key's gateways. `api_key.create` (after) and `api_key.revoke` (before) audit `gatewayIds`.
- **Audit.** `gateway.create/update/delete/capabilities_set` (target `gateway`, team set for team gateways),
  `gateway.grant_add/grant_remove` (target `gateway_grant`), `api_key.create/revoke` (target `api_key`), all with live
  labels.
- **Not built yet:** payload capture (`capture_payloads` stays
  false), rate limits on `/mcp`, resource subscriptions.

Results relayed from upstream servers have `_meta["io.modelcontextprotocol/serverInfo"]` removed: clients talk to the
gateway, and the upstream's own name and version are not theirs to see. Other `_meta` entries pass through unchanged.

### Resources and resource templates (follow-up to decision 18)

Kinds `resource` and `resource_template` are selectable under the same rules as tools and prompts (own team's
servers; approved capabilities of published servers), with the same availability, minimum roles and re-checks.

- **Exposed URIs** (*proposed default*): a resource `status://services` of server `status` is
  `omp://status/status://services`; a template gets the same literal prefix before the original template, so its
  RFC 6570 variables are unchanged: `omp://status/status://services/{service}`. Server slugs can't contain `/` or
  `:`, so the slug always ends at the first `/` after `omp://`. Exposed URIs share the name-clash rule with names.
- **Supported templates:** RFC 6570 level 1 simple `{var}` and level 2 reserved `{+var}` expressions, one variable
  each. Templates with any other operator (`{#…}`, `{/…}`, `{?…}`, `{.…}`, `{;…}`, `{&…}`), several variables or
  modifiers aren't offered by gateway-options, and selecting one is `422 capability_not_selectable` with reason
  `unsupported_template` (`gateways.TemplateSupported`; the SQL in `ListGatewayOptions` uses the same pattern).
- **Matching** (`gateways.MatchTemplate`): literals match exactly; `{var}` matches one or more unreserved characters or
  percent-encoded octets, `{+var}` also reserved characters (`:/?#[]@!$&'()*+,;=`). No variable may be empty, and no
  matched value may contain a `.` or `..` path segment, also when written `%2e` or separated by `%2f` / `%5c`.
- **Runtime:** `initialize` advertises `resources` (`subscribe: false`, `listChanged: false`) when the gateway selects
  any resource or template; otherwise the resources methods are "method not found". `resources/list` and
  `resources/templates/list` serve the approved definitions (name, title, description, mimeType, annotations as
  approved) with `uri` / `uriTemplate` rewritten, paged like the other lists. `resources/read` strips the prefix, finds
  the server by slug and allows the read only if the original URI equals a selected resource's URI or matches a
  selected template, for that caller, right now; anything else is JSON-RPC `-32002 Resource not found`, recorded
  `denied` (`unknown`, or the capability's reason such as `role`) and never sent upstream. An allowed read is forwarded
  with the identity JWT (claim `resource` = the exposed URI read; see [upstream-identity.md](upstream-identity.md)),
  and the result's `contents[].uri` are rewritten to the exposed form. The 1 MiB bound and the `_meta` serverInfo
  scrub apply. A server's own `-32002` passes through (outcome `bad_request`, class `not_found`).
  `resources/subscribe` and `resources/unsubscribe` are "method not found".
- **Records:** `mcp_calls.method` accepts the three resources methods (migration `00006`); `exposed_name` is the
  exposed URI the client asked for.
- **UI:** the picker, the gateway's Capabilities tab and My gateways list resources and templates with their exposed
  URI and kind.
