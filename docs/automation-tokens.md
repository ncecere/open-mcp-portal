# Automation tokens (design)

Status: **built in v0.2 (roadmap B)** (backend; the web screens follow). Decision 55 fixed the two kinds; decision 58 is the scope mechanism. The
contract is in [`../api/openapi.yaml`](../api/openapi.yaml) (tag `automation-tokens`, the `x-omp-token-scopes` extension, `GET /v1/token`).
Migration `00015_automation_tokens.sql`. Reference, not copied: Open Model Gateway's admin API tokens (`identity.md`: bearer
credentials never cross between inference and management), and this project's own `internal/apikeys` and service account keys.

## Goal

CI and scripts call the management API without a browser session: a **team publisher token** registers, refreshes and publishes a
team's servers from a pipeline; a **platform-admin token** reads the platform's state (monitoring, reports) and provisions teams
and gateways. They are **separate from MCP credentials in both directions**: `omp_`, `omp_sa_` and `ompat_` never authorize `/v1`,
and an automation token never authorizes `/mcp/*`. Nothing here lets a token mint tokens, grant `platform_admin`, or read recorded
call contents.

## Kinds

| | Platform-admin token | Team publisher token |
|---|---|---|
| Prefix | `ompadm_` + 43 URL-safe characters (stored prefix `ompadm_` + 8) | `omppub_` + 43 (stored `omppub_` + 8) |
| Owner | the platform | one team; survives its creator leaving the team or the company |
| Made by | platform admins (browser session) | the team's owners and admins (browser session) |
| Scopes | `platform:read`, `platform:write` | `servers:read`, `servers:write` |
| Acts as | `platform:read`: a platform auditor. `platform:write`: a platform admin, but only for the operations below | members for reads; editors for create/update/test/refresh; admins for publish/unpublish. Never more |
| Limits | at most 20 active; expiry 1-365 days (default 90); name 1-100 characters; shown once | at most 20 active per team; same |
| Standing | refused (`401 invalid_token`) unless its **creator is still an active platform admin**; comes back if they are restored | none: valid while the team exists. Archived teams follow the normal read-only rules (`409 team_archived` on writes) |

A write scope includes its read scope: creating with `servers:write` stores `[servers:read, servers:write]`, so an operation's
annotation lists only the minimum and the check is "the token holds any listed scope". Scopes of the other kind are `400 invalid_scopes`.

## Authentication (`/v1/*` only)

1. A request with an `Authorization` header is authenticated as a token and **only** as a token (a cookie is ignored). It must be
   exactly `Bearer <token>`; anything else is `401 invalid_token`. Browser requests never carry one, so there is no CSRF or `Origin` rule
   for tokens and no cookie is ever set on a token response.
2. **Shape check before any lookup**, by one shared classifier (`internal/credentials`, used by `/v1` and `/mcp`): `ompadm_`/`omppub_`
   plus 43 characters is a token. `omp_`, `omp_sa_`, `ompat_`, `omprt_`, `ompac_` and everything else is `401 invalid_token` on `/v1`
   ("MCP credentials aren't accepted here"); a token on `/mcp/{slug}` gets the existing `401` challenge, never a lookup.
3. Failed attempts per address (hashed) share the sign-in limit (`LOGIN_ATTEMPTS_PER_MINUTE`): `429 rate_limited` with `Retry-After`.
4. HMAC-SHA256 digest with `API_KEY_PEPPER`, then `API_KEY_PEPPER_PREVIOUS` (re-digested on use and audited
   `automation_token.pepper_rehash`, as keys). Unknown, expired, revoked, creator-not-admin, deleted team: all `401 invalid_token`, one message.
5. **Per-token rate limit** through the shared limiter (bucket `t:<token id>`, `REQUESTS_PER_MINUTE`): `429 rate_limited`.
6. **Operation check.** No `x-omp-token-scopes` on the route: `403 token_not_allowed`; the four token-management operations answer
   `403 session_required` instead (an absolute rule, tested separately). Scopes without overlap: `403 token_not_allowed` with
   `details.requiredScopes` and `details.tokenScopes`.
7. **Team check.** On `/v1/teams/{team}/...` the path team (slug or ID) must be the token's team, else `404 team_not_found`, exactly what a
   non-member gets. A platform token never reaches team routes (no annotation).
8. The handler gets an `authz.Actor{Kind: automation_token, TokenID, TokenName, TokenKind, TeamID, PlatformRole}` with no user ID. User-reference columns stay NULL
   (`created_by`, `updated_by`, `publish_requested_by`, `triggered_by` are nullable); the audit entry names the token. `last_used_at` is written at most once a minute.

## Operations that accept tokens (`x-omp-token-scopes`)

63 operations; every other one answers a token `403 token_not_allowed`. A contract test compares the annotations with the route table.

| Scope | Operations |
|---|---|
| `platform:read` (39) | every `GET /v1/admin/**` **except** `adminGetCallPayload`: `adminListUsers`, `adminGetUser`, `adminListTeams`, `adminGetTeam`, `adminListAudit`, `adminGetAuditEntry`, `adminListMcpServers`, `adminGetMcpServer`, `adminListMcpCapabilities`, `adminListMcpHealthChecks`, `adminGetPublishingSettings`, `adminGetNetworkSettings`, `adminGetTeamPublishing`, `adminListGateways`, `adminGetGateway`, `adminListGatewayCapabilities`, `adminListGatewayOptions`, `adminListGatewayGrants`, `adminListCalls`, `adminGetCall`, `adminGetTrustedClients`, `adminListUserOAuthGrants`, `adminListServiceAccounts`, `adminListAuthProviders`, `adminGetAuthProvider`, `adminListAuthProviderPresets`, `adminListUserConnections`, `adminGetLimitSettings`, `adminGetTeamLimits`, `adminGetCaptureSettings`, `adminGetRetentionSettings`, `adminGetTeamRetention`, `adminGetUsage`, and the new `adminGetOverview`, `adminGetNotificationSettings`, `adminListNotificationDestinations`, `adminGetNotificationDestination`, `adminListNotificationDeliveries`, `adminListAutomationTokens` |
| `platform:write` (11) | `adminCreateTeam`, `adminUpdateTeam`, `adminCreateGateway`, `adminUpdateGateway`, `adminSetGatewayCapabilities`, `adminAddGatewayGrant`, `adminRemoveGatewayGrant`, `adminUpdateLimitSettings`, `adminUpdateTeamLimits`, `adminRevokeUserOAuthGrant`, `adminRevokeUserConnection` |
| `servers:read` (5) | `listTeamMcpServers`, `getTeamMcpServer`, `listTeamMcpCapabilities`, `listTeamMcpHealthChecks`, `getTeamPublishing` |
| `servers:write` (7) | `createTeamMcpServer`, `updateTeamMcpServer`, `testTeamMcpServer`, `refreshTeamMcpServer`, `detectTeamMcpServerAuth`, `publishTeamMcpServer` (request publication; under `self_publish` it publishes at once, as policy says), `unpublishTeamMcpServer` (withdraw) |
| any of the four (1) | `getToken` (`GET /v1/token`): kind, name, scopes, team, expiry, for CI debugging; `401 invalid_token` without a token |

**Never for tokens** (they answer `token_not_allowed`, or `session_required` where marked ★):

- ★ create or revoke tokens (all four operations), so a token can't mint or kill tokens;
- **people and authority:** `adminUpdateUser` (the only way to grant `platform_admin` or suspend someone), `adminAssignOwner` (owning a team lets a person mint its tokens), members, invites, service accounts and their keys;
- **decisions:** `adminReviewMcpServer`, `adminApproveMcpCapability`, `approveTeamMcpCapability` (the review gate stays human), `setTeamMcpCapabilityRequirement`;
- **settings that widen trust or touch data:** publishing policy and overrides, internal networks and its URL check, trusted OAuth clients, capture patterns and its tester, retention (platform and team), auth providers (create, update, delete, and who may use one: `adminGetAuthProviderAccess` and `adminSetAuthProviderAccess`, session-only, decision 69);
- **destruction:** `deleteTeamMcpServer`, `adminDeleteGateway`, deleting anything; **session-bound steps:** `authorizeTeamMcpServerSetup` (a person must sign in);
- **recorded contents:** `getTeamCallPayload`, `adminGetCallPayload`, and everything under `/v1/me/**` and notification management. A defence in depth: the capture service refuses actors of kind `automation_token` even if an annotation were added by mistake.
- Field rule: `updateTeamMcpServer` with a changed `capturePayloads` is `403 token_not_allowed` (`details.field`), since only owners and admins may switch capture and a token is not a person who accepted the notice.
- Field rule (decision 73): `createTeamMcpServer` and `updateTeamMcpServer` with `machineOAuth`, or `authMode` `machine_oauth` on a server not already in it, are `403 token_not_allowed` (`details.field` `machineOAuth` or `authMode`) **even on a server with no credentials**: a token must not choose where a client secret goes. A server already in the mode is protected like one with credentials (no URL, mode, client or `sendIdentity` change).

**Decisions to review:** the platform write list is "provisioning that is reversible and doesn't widen trust or who is trusted" (teams, gateways, grants, limits, revoking a person's consent); trust-widening settings and deletes wait for a separate scope in v0.3/v0.5 (Terraform).
`adminAssignOwner` is excluded although team provisioning wants it; a platform token creates an ownerless team and a person assigns the owner. A platform token dies with its creator's platform-admin role; team tokens don't.

## Data model (`00015_automation_tokens.sql`, expand-only)

| Table / column | Contents |
|---|---|
| `automation_tokens` | `id uuid`, `kind` (`platform_admin`\|`team_publisher`), `team_id uuid` (FK `teams` ON DELETE CASCADE; set iff team_publisher), `name`, `prefix` (CHECK `^(ompadm\|omppub)_[A-Za-z0-9_-]{8}$` and matching kind), `digest` (UNIQUE, hex HMAC), `pepper_id bytea`, `scopes text[]` (CHECK subset of the four, non-empty, matching kind), `created_by uuid` (FK users ON DELETE SET NULL; `created_by_name` kept), `created_at`, `expires_at` (CHECK `> created_at` and `<= created_at + 365 days`), `revoked_at`, `revoked_by`, `last_used_at`. Indexes on (`team_id`, `created_at DESC`) and (`kind`, `created_at DESC`) |
| `audit_log` (+) | `actor_kind` CHECK widened to add `automation_token`; `actor_token_id uuid`, `actor_token_name text`, `actor_token_kind text` (name and kind are snapshots; CHECK ties them to the kind; added `NOT VALID` then validated); index (`actor_token_id`, `occurred_at DESC`) |

The previous release can't list audit entries of the new actor kind (like Phase 4's call principals), so create no token until every replica runs the new release. At most 20 active
(unrevoked, unexpired) per team (`teams` row `FOR UPDATE`) and 20 for the platform (transaction advisory lock) are counted in the creating transaction (`409 too_many_tokens`).
Expired and revoked rows are listed for 30 days and then deleted by the cleanup that already removes expired sessions; the audit log keeps names.
`keyrotation` and `doctor` count `automation_tokens` among the digests still on the previous pepper.

## Audit

`automation_token.create` and `.revoke` (target `automation_token`, label = name, team set for team tokens; metadata kind, scopes, expiry; never the prefix beyond the stored one, never a secret) by the person; `automation_token.pepper_rehash` by the system.
Every other audited action done with a token has `actor_kind = automation_token`. `AuditActor` gains `automationTokenId/Name/Kind`; `AuditEntry.via` is null (it describes how a *person* acted);
`actorKind=automation_token` filters both audit lists. A team sees its own token's actions, and a platform token's actions on the team, in its audit log. Authentication failures are not audited (limited, and counted in `omp_automation_token_auth_total{result}`).

## Security: what a token can never read or do

Never: mint or revoke tokens, change roles or suspend anyone, review or approve, widen trust settings, delete, read captured payloads, read anything under another team, read any secret
(server header values, provider and token secrets, webhook secrets and URLs) or reach `/mcp`. Secrets are shown once, hashed with the pepper, never logged, audited, captured (`ompadm_` and `omppub_` join the capture redaction rule and `apikeys`' prefix tests)
and never in a URL. Revocation applies on the next request. The access log records the route pattern, never the header.

## UI

- **Admin › Automation tokens** (`/admin/automation-tokens`, platform admins write, auditors read): table (name, prefix, scopes, status incl. "blocked: creator is no longer a platform admin", created by, expires, last used), **Create** dialog (name, scope checkboxes with plain wording, expiry select, default 90 days), a **show-once** secret panel with copy and a `curl` / GitHub Actions snippet, **Revoke** with confirmation. A banner says tokens never work on `/mcp`.
- **Team › Settings › Automation tokens** (tab `automation-tokens`; owners and admins, platform staff read-only): the same, for `servers:*`; copy explains that the token can publish but not approve or delete.
- Account › API keys gets one line: "Automation (CI) tokens are made by team admins under Team settings."

## Tests that must exist

- **Matrix** (`authz_matrix_policy_test.go`): `adminListAutomationTokens` own=platform; `adminCreateAutomationToken`/`adminRevokeAutomationToken` own=padmin; `listTeamAutomationTokens` team own=admins, foreign=platform; create/revoke team own=admins, foreign=none; `getToken` is token-only (every session caller `401`).
- **Token matrix** (new): for every operation, callers {platform-read, platform-write, publisher-read, publisher-write own team, publisher-write other team, expired, revoked, creator demoted, MCP key, OAuth token}: annotated + scope held: not 401/403-token, other team `404`; unannotated: `403 token_not_allowed`; the four management operations `403 session_required`; no `500` from a nil user anywhere.
- **Contract:** `x-omp-token-scopes` present exactly on the route table's token routes (`route.Token`); values are valid scopes; no `*:write` on a GET; no annotation on payload, token-management or `/v1/me` operations; the 63 listed above.
- Authentication: shape check before lookup, `/mcp` rejects both prefixes without a lookup and `/v1` rejects MCP credentials, cookie ignored, no CSRF needed, per-token and failed-attempt limits, pepper rotation re-digest, `last_used_at` once a minute, expiry boundaries, 20-token limits (race of two creations), team deleted, creator leaving (team token lives, platform token blocked then restored).
- Audit shows token name and kind; `capturePayloads` field rule; capture refuses token actors; secret sentinel in responses (beyond creation), audit, logs and captures; prefix tests (`LooksLikeKey` false for both prefixes, redaction matches both).
- Vitest for both screens (create, show-once, revoke, blocked row, read-only for auditors and platform staff).

## As built

`internal/automation` (service), `internal/credentials` (the shared shape classifier), `internal/httpapi/tokenauth.go` (the middleware), `internal/tools/tokenscopes` (generator), migration `00015_automation_tokens.sql`.

- **The allow-table is generated** from `x-omp-token-scopes` into `internal/httpapi/apitypes/tokenscopes.gen.go` (`apitypes.TokenOperations`, keyed by the router's `METHOD pattern`) by `go generate`, part of `make generate`: nothing is read at run time, so there is no spec to fail to load, and an operation not in the table is `403 token_not_allowed`. `TestTokenScopesMatchSpecAndRoutes` checks the table against the spec and the route table (63 operations, 39/11/5/7 per scope).
- **Authentication** is in `api.session`: on `/v1/*` a request with an `Authorization` header is a token request and only that; the session middleware isn't involved. A **cookie sent with it is ignored** (the design and the threat model say so; the brief's `400 ambiguous_credentials` is not implemented). Order: shape (`credentials.Classify`; `omp_`, `omp_sa_`, `ompat_`, `omprt_`, `ompac_` are `401 invalid_token` without a lookup), lookup (current then previous pepper), expiry, revocation, creator standing, per-token limit (`t:<id>`), operation, team. Failed attempts count per address in their own bucket (`tokenfail`, `LOGIN_ATTEMPTS_PER_MINUTE`): bad tokens from a shared address never use up sign-in attempts and a valid token isn't refused for them.
- A token's `authz.Actor` has `Kind automation_token`, no user ID, a `PlatformRole` of `platform_admin` (with `platform:write`) or `platform_auditor`, and `TeamRole()` (publisher: admin with `servers:write`, member for reads, own team only). Services that read a member's role call `Actor.TeamRole`; user-reference columns are NULL for tokens. `GET /v1/token` is token-only.
- **Every token mutation is audited as the token** (`actor_kind automation_token`, ID, name, kind; no user). The services audit their own changes; when a token's successful non-GET request wrote no entry (a manual test, a probe), the middleware writes `automation_token.request` with the route.
- **Field rule** (threat-model 10.2, beyond the design): `updateTeamMcpServer` with a token refuses `capturePayloads`, and on a server that already holds credentials also `url` (changed), `authHeaderName`, `authValue`, `credentials` (the parts of a static credential, decision 70), `authMode`, `oauth`, `requirement` and `sendIdentity` (changed): `403 token_not_allowed` with `details.field`. Since decision 72 it also refuses `personSecret` and switching any server to `authMode` `person_secret` (even one with nothing yet to steal: that would send people's own keys to its URL), and creating a server with either (`createTeamMcpServer`; `details.field` `personSecret` or `authMode`); decision 73's `machineOAuth` and `machine_oauth` are refused the same way, see below, and the person secret operations (`/v1/me/server-secrets`, `/v1/connect/secret-requests`, `/v1/admin/users/{id}/server-secrets`) have no token scope at all. **`tls`** (a server's CA bundle and mTLS client certificate and key, decision 74) is refused on create and update whatever the server holds, and on a server that holds a client key the URL can't be changed either: a key and a trusted CA are credentials and trust settings, which tokens never set. `detectTeamMcpServerAuth` is limited to 10 a minute **per token**. **`governance`** (decision 88: owner, on-call contact, sensitivity, lifecycle, sunset date, replacement) is refused whole on `updateTeamMcpServer` whatever the server holds and whatever else the request sends (`details.field governance`), and `maxSensitivity` of a gateway on create and update (`details.field maxSensitivity`): who is accountable for a server and what a gateway may serve are people's decisions. The transfer operations and the platform's governance settings have no token scope at all, so they answer `403 token_not_allowed`.
- Notification management and recorded contents aren't annotated; `notify` also refuses token actors on every write and on team destinations (defence in depth). The capture service refuses token actors (`internal/capture` only records calls through gateways, which tokens never reach).
- `keyrotation` and `doctor` count automation tokens among digests on the previous pepper (`automation_token` kind). `key.expiring` for platform tokens goes to platform admins, for publisher tokens to the team's owners and admins. `ompadm_` and `omppub_` (and the webhook secret prefix `ompwhs_`) join the capture redaction rule; `apikeys.LooksLikeKey` and `serviceaccounts.LooksLikeKey` are false for both.
- Known and left as designed: `platform:write` still includes gateway grants and capability selection, limit changes and team archiving (a leaked platform token can widen access; every such change is audited as the token). Recommended for v0.3: a separate scope for grants and capability selection, tighten-only limits.
- Tests: `TestTokenMatrix` (every operation x ten kinds of credential, built from the session matrix's builders: scope held, wrong scope, other team, token management, expired, revoked, creator demoted, MCP key, OAuth token, no `500` anywhere), `TestTokensNeverReachMCP`, `TestTokenCallsAreAuditedAsTheToken`, `TestTokenFieldRules`, `TestTokenStandingRules` (revocation, expiry boundary, demote and restore, suspended creator, creator deleted, archived team, deleted team), `TestTokenPreviousPepper`, `TestTokenRateLimits`, `TestAutomationTokenLifecycle`, `TestAutomationTokenLimits` (a race for the last slot), `TestPlatformWriteMutationsAreAuditedAsTheToken`, and the units in `internal/automation` and `internal/credentials`.
