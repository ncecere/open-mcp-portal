# Open MCP Portal — specification

Status: **approved direction; phases 1–7 shipped**. This is the original architecture and phase plan, not the
current delivery checklist; see [docs/status.md](docs/status.md) and [docs/roadmap.md](docs/roadmap.md).
Product decisions are recorded in
[docs/decisions.md](docs/decisions.md); this document turns them into architecture, data model, API and
build phases. Items marked *proposed default* were not interview answers and may be changed.

## 1. Objective

A self-hosted, central place where a company's teams register the MCP servers they build, publish them to a
company catalog, curate them into gateways and give people and agents governed access, similar to Arcade.

Success means:

- A team registers a remote MCP server; the portal discovers its tools, resources and prompts.
- A platform admin approves it into the company catalog (or a trusted team self-publishes).
- A team or platform admin builds a gateway from selected tools and grants it to teams, users or SSO groups.
- Claude Code, VS Code, Cursor or a headless agent connects to `/mcp/{slug}`, sees only what it may use and
  calls tools; every upstream call carries a signed identity of the user.
- Later, tools that need the user's GitHub/Google/internal-API token get it from the portal's token vault.
- Admins can see health, usage and an audit trail; call payloads are only kept where a team opted in.

Out of scope: hosting or running agents, building MCP servers, an LLM gateway, and trusting external agent platforms to impersonate people. See [platform retirement](docs/platform-retirement.md). Ordinary MCP clients, including the pi coding client, remain supported.

## 2. Architecture

```text
MCP clients (Claude Code, VS Code, Cursor, agents)
   │  OAuth access token or API key
   ▼
/mcp/{slug} ── authenticate ── gateway policy ── rate limit ── upstream client ──► team MCP servers
                                                     │              (Streamable HTTP, signed identity JWT,
                                                     ▼               later: brokered OAuth token)
Browser ── /auth/*, /v1/* ── management API     call records, audit, usage
   │
   ▼
React SPA (embedded in the Go binary)
```

One Go binary, modes `serve` (API + MCP endpoints + UI + background loops) and `migrate`. Stateless; several
replicas share PostgreSQL. Background work (health checks, discovery sync, retention, key rotation) runs as
leader-elected loops using a PostgreSQL advisory lock — no job queue or Valkey in the first releases.

### Package layout

```text
cmd/open-mcp-portal/     main: serve | migrate | doctor
internal/app/             dependency wiring only
internal/config/          env/YAML config, validation, safety checks (from Grounded)
internal/store/           pgx pool, goose migrations, advisory locks; queries/ + dbgen/ (sqlc)
internal/auth/            OIDC login, dev personas, browser sessions, CSRF (from Grounded)
internal/authz/           Actor, platform and team roles, pure rules (from Grounded)
internal/audit/           append-only audit writes inside the caller's transaction
internal/teams/           teams, members, invites (from Grounded, no classifications)
internal/platform/        platform admin: users, teams, settings
internal/httpapi/         routes, middleware, respond helpers, SPA, apitypes/ (oapi-codegen)
internal/httpx, apperr/   shared HTTP and error helpers (from Grounded)
-- later phases --
internal/registry/        MCP servers, discovered capabilities, publishing and approval
internal/upstream/        guarded MCP client (SSRF guard), transports, credential references
internal/gateways/        gateways, tool selections, access grants, effective access
internal/mcpgw/           /mcp/{slug} server: per-caller catalog, call execution
internal/identity/        signing keys, identity JWTs, JWKS
internal/oauth/           OAuth authorization server for MCP clients (from Grounded)
internal/apikeys/         personal and service-account keys (from Grounded)
internal/vault/           auth providers, per-user tokens, consent (Phase 5)
internal/calls/           call records, payload capture, retention
internal/limits/          rate limits with team overrides
api/openapi.yaml          management API contract (source of truth)
migrations/               goose SQL, embedded
web/                      React app
deploy/                   compose and Kubernetes (Kustomize)
```

## 3. Conventions (from Grounded)

- `net/http` routing; no framework. Strict JSON decoding (unknown fields rejected).
- Success `{"data": ...}`; error `{"error": {"code", "message", "details?"}}`; `X-Request-ID` on every response.
- UUID IDs; teams, gateways and servers also have immutable URL slugs.
- Cursor pagination (`cursor`, `limit`, default 50, max 200); search with `q`.
- Edits use `revision` + `ETag`; client sends `If-Match` (missing → 428, stale → 412).
- Every mutation authorizes, mutates and writes the audit entry in one transaction.
- Server checks are authoritative; UI permission gates only explain.
- OpenAPI drives generated Go types (`internal/httpapi/apitypes`) and TypeScript (`web/src/api/schema.gen.ts`);
  a contract test checks registered routes against the spec. sqlc generates `internal/store/dbgen`.
- Secrets are never returned, logged or audited; only references and "configured" states.

## 4. Identity and roles

As Grounded: OIDC (code + PKCE + nonce), identity key `(issuer, subject)`, one-time bootstrap platform admin,
server-side sessions (cookie secret, SHA-256 digest stored, CSRF token), loopback-only dev personas.
Account › Sessions lists active browser sign-ins, revokes one or all (optionally keeping the current session);
platform admins alone list and revoke another person's sessions. These five operations are browser-only, never
available to automation tokens. Revocation and count-only audit are transactional and cancel pending connect
states bound to the ended session; connected apps, keys and provider connections are unaffected. Sessions have
an absolute `SESSION_TTL` and an optional `SESSION_IDLE_TIMEOUT` (default off; 5m through the absolute lifetime).
Every session entry point checks both limits and records activity at most once a minute. See decision 76 and
[the client-auth design](docs/phase4-client-auth.md#browser-sessions-37-decision-76).

| Role | Can |
|---|---|
| `platform_admin` | Everything administrative: users, teams, catalog approval, platform gateways, policies, settings |
| `platform_auditor` | Read all admin pages and audit/call metadata; no changes |
| team `owner` | Team admin plus manage owners |
| team `admin` | Members, servers, team gateways, keys, team settings |
| team `editor` | Register and edit the team's servers and gateways (proposed default) |
| team `member` | Use gateways granted to them; view the team catalog |

Platform roles do not grant team content (captured payloads) unless stated. Last owner / last platform admin
protections as in Grounded.

## 5. Domain model (later phases)

**MCP server** (team-owned): slug, name, description, URL, transport (`streamable_http`), upstream auth
(none, or one static header whose value is encrypted with `ENCRYPTION_KEY` as in Grounded; only a 4-character
hint is ever returned), timeout, enabled, publish state (`private` → `pending` → `published` | `rejected`),
revision, last refresh/health. Teams can't set environment variables, so env-var secret references are not used
for team servers.

**Capability**: server, kind (`tool` | `resource` | `resource_template` | `prompt`), upstream name, exposed
name, definition JSON, fingerprint (SHA-256 of canonical definition), state (`active` | `changed` | `gone`),
annotations (read-only/destructive hints shown in UI, never trusted for authorization).

*Proposed default — change detection:* if a published server's capability fingerprint changes, the new
version is held (`changed`) and gateways keep serving nothing for that tool until a platform admin (or the
team, under `self_publish`) approves the change.

**Publishing policy**: platform setting `approval_required` | `self_publish` with per-team override.

**Gateway**: owner (team or platform), slug, name, description, enabled, selected capabilities (each with an
optional minimum team role), access grants (team | user | SSO group), payload capture setting.

**Gateway access requests** (decision 83, unreleased #32): platform gateways opt into discoverability and
private user/team requests. Platform admins and named gateway-specific stewards decide, never the requester;
stewardship is not gateway/admin/MCP access. Decisions create grants and audit atomically. Optional grant
expiry is enforced by effective-access queries and final transport/approval deadlines without a sweeper.
All new workflow APIs are browser-session-only; notifications use private inbox/email metadata only.
See [access requests](docs/access-requests.md) and [status](docs/status.md) for implementation/acceptance state.

**Sensitive-call approval** (decision 82): owner-managed server/gateway rules gate exact tool calls.
Human reviewers cannot approve their own requests; service-account separation of duties also applies.
Approvals bind merged arguments, definition, destination and live authority, and authorize one actual
transport attempt, never an automatic replay. Session-only review uses redacted sealed previews; private
notifications and attention links contain metadata only. See [tool approvals](docs/tool-approvals.md).

**Identity JWT** (sent upstream as `Authorization: Bearer` or a configurable header): `iss` = gateway URL,
`aud` = server URL, `sub` = user ID, `email`, `name`, `teams`, `gateway`, `tool`, `exp` ≤ 5 minutes, `jti`. Signed ES256; keys rotate; published at `/.well-known/jwks.json`.

**Call record**: time, caller (user / service account / key), client, gateway, server, capability, outcome,
error class, latency, request/response bytes; optional captured payload (truncated, redacted) with retention.

**Auth provider / user token (Phase 5)**: admin-configured OAuth apps; a server (with per-capability overrides)
declares the required provider and scopes; missing consent returns an authorization URL (JSON-RPC `-32042`); tokens
encrypted at rest, refreshed by the portal. See [docs/phase5-delegated-credentials.md](docs/phase5-delegated-credentials.md).

## 6. MCP endpoint behaviour

- `POST /mcp/{slug}` Streamable HTTP, stateless JSON responses first; SSE responses where upstream streams.
- Authentication: OAuth access token from the portal's own authorization server, or API key. Unauthenticated
  requests get `401` with `WWW-Authenticate` pointing at protected-resource metadata.
- `tools/list`, `resources/list`, `prompts/list` return only capabilities allowed by every check.
- Every `tools/call`, `resources/read`, `prompts/get` re-checks: key/user active, gateway enabled and granted,
  tool selected and role satisfied, server enabled and published (or same team), capability active, rate limit.
- Not-allowed and not-existing look the same (not found) to the caller.
- Exposed tool names: `{server-slug}__{tool}` (proposed default), so tools from different servers never clash.
- Limits: 1 MiB request/response by default, upstream timeout per server, no redirects, SSRF guard (adapted
  from Grounded `internal/mcpclient/guard.go`), development HTTP only for loopback.
- Sampling, elicitation and roots are not forwarded in the first release.

## 7. Phases

1. **Foundations** — config, store, migrations (identity, teams, audit), OIDC/dev sign-in, sessions, users,
   teams, members, invites, platform admin, audit, OpenAPI + generation, Grounded UI shell, admin and team
   pages, compose for Postgres. *In progress.*
2. **Registry** — MCP servers, discovery, health, publishing/approval, catalog UI, fake MCP server for dev.
   Roles (proposed default): members and platform staff read; editors register, edit, test and refresh; owners
   and admins delete, publish and unpublish (and approve changes under `self_publish`); platform admins review.
   Team-private servers need no approval for the team's own use; the catalog only shows capabilities whose
   current fingerprint is approved.
3. **Gateways** — gateways, selections, grants, `/mcp/{slug}`, identity JWT + JWKS, call metadata.
4. **Client auth** — OAuth authorization server for MCP clients, trusted-client consent skip, API keys,
   service accounts, "Connect" instructions in UI.
5. **Delegated credentials** — auth providers, token vault, consent flow, "My connections". *Designed*
   (decisions 25–30): [docs/phase5-delegated-credentials.md](docs/phase5-delegated-credentials.md); contract in
   `api/openapi.yaml` (tags `auth-providers`, `connections`). Missing consent returns MCP `-32042` with a
   single-person consent link; tokens reach servers in `MCP-Gateway-Provider-Token`.
6. **Operations** — *Designed* (decisions 31–38): [docs/phase6-operations.md](docs/phase6-operations.md); contract in
   `api/openapi.yaml` (tags `limits`, `retention`, `usage`; call detail and captured payloads; capture and rate-limit
   fields on gateways and servers). Rate limits per person, credential, service account and gateway counted in
   PostgreSQL (HTTP 429, JSON-RPC `-32029`, outcome `rate_limited`); opt-in payload capture per gateway or server
   (redacted, 16 KiB per part, sealed, views audited); retention with team overrides; hourly usage rollups and
   dashboards; Prometheus on `METRICS_ADDR`; `API_KEY_PEPPER_PREVIOUS` and `rotate-keys`; GitHub Actions CI.
   Kubernetes manifests are done ([docs/deploy.md](docs/deploy.md)). #33/decision84 adds per-server forwarded-
   attempt quotas, replica-local concurrency/breakers and bounded trusted-read retries, a **locally validated v0.7.0
   candidate, not yet published**; [upstream protection](docs/upstream-protection.md) specifies authorization/spend ordering,
   rollout and the separate unfinished failover stage.
7. **Upstream OAuth** — *Designed* (decisions 39–44): [docs/phase7-upstream-oauth.md](docs/phase7-upstream-oauth.md);
   contract in `api/openapi.yaml` (`McpServer.authMode`/`oauth`, `detectTeamMcpServerAuth`, `authorizeTeamMcpServerSetup`,
   `ProviderRef.kind`/`server`). The portal acts as an MCP client to servers that are OAuth resource servers themselves
   (GitHub's `https://api.githubcopilot.com/mcp/`). Discovery follows the MCP authorization spec 2025-11-25: RFC 9728
   metadata from the 401, RFC 8414/OIDC (path insertion), PKCE S256, `resource`, then CIMD, DCR, a client entered by
   hand, or a linked platform provider. A server-bound provider row (kind `mcp_server`) reuses Phase 5's connections,
   `-32042` consent links, refresh and revocation. Each person's token goes in `Authorization: Bearer` and the identity
   JWT in `MCP-Gateway-Identity`. Capabilities are read as the setup person; scheduled health checks use nobody's token.

## 8. Commands

```sh
make deps-up          # Postgres on 127.0.0.1:55442
make generate         # sqlc + oapi-codegen + openapi-typescript
make check-generated
make test             # go test ./... (integration tests use OMP_TEST_DATABASE_URL)
make web-test         # typecheck + vitest
make web              # build UI into web/dist
make run              # serve on 127.0.0.1:8088 with DEV_AUTH
make web-dev          # Vite on :5175, proxies to :8088
```

## 9. Testing bar

- Pure policy tables for authz; integration tests per route against a real Postgres; route/OpenAPI contract test.
- Every later phase adds authz-matrix cases (platform role × team role × foreign team) and secret-leak tests.
- UI: typecheck, Vitest component tests, Playwright for core flows.

## 10. Boundaries

**Always:** server-side authorization, audit in the same transaction, generated contracts, no secrets in
responses/logs. **Ask first:** new dependencies beyond the Grounded set, changing roles or decisions, real IdP
or cluster use. **Never:** trust tool annotations or model output for authorization, store payloads without
opt-in, forward the client's own token upstream.
