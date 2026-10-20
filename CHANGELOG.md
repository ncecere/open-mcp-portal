# Changelog

Notable changes to Open MCP Portal, one entry per release. Design notes for each phase are in [`docs/`](docs/), and
[`docs/status.md`](docs/status.md) records what was verified.

The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor releases may include
breaking changes; the entry says how to adapt.

## Unreleased

Documentation only: the [roadmap](docs/roadmap.md) is rewritten around what v0.2.1 shipped and what is still open, with an [issue](https://github.com/ncecere/open-mcp-portal/issues?q=is%3Aissue+is%3Aopen+label%3Aroadmap) and implementation plan for each item; the threat model's hardening table links its issues and no longer lists Trivy as open.

- **Dockerfile base images are pinned by digest** ([#11](https://github.com/ncecere/open-mcp-portal/issues/11), threat model H-9). `node:22-alpine`, `golang:1.26` and `gcr.io/distroless/static-debian12:nonroot` keep their tag and carry the digest of their multi-arch index, so the same commit builds on the same bases. Dependabot's `docker` entry now ignores only the version of `golang` and `node` (a toolchain change stays deliberate), so their digest updates arrive in its weekly pull request.
- **The sign-in state cookie is `__Host-omp_oidc_state` on https, and a missing `TRUSTED_PROXIES` is reported** ([#10](https://github.com/ncecere/open-mcp-portal/issues/10), [deploy.md](docs/deploy.md#behind-a-proxy-trusted_proxies), threat model H-7). The cookie that ties a sign-in to its browser had no `__Host-` prefix, so a sibling subdomain could set or shadow it; now it is host-only, `Secure`, `Path=/` on https (the development http origin keeps `omp_oidc_state`). The old name is still accepted for this release, so a person who is mid sign-in during the upgrade is not sent back; it will be removed in v0.3. Behind a proxy with `TRUSTED_PROXIES` empty, every request appears to come from the proxy, which makes per-address rate limits and audit addresses useless without saying so: when a request carries `X-Forwarded-For` or `Forwarded` and `TRUSTED_PROXIES` is empty (non-loopback `APP_URL`), the portal logs one warning, at most once a minute, and `doctor` prints an info check. No change for installs that set `TRUSTED_PROXIES`.

## [0.2.1] - 2026-10-18

Small changes since v0.2.0 ([release notes](docs/releases/v0.2.1.md)). No migration.

- **Test connection sends the identity token** ([registry.md](docs/registry.md#health), [upstream-identity.md](docs/upstream-identity.md#what-a-test-sends), decision 61). Found with DeepWiki's public server, which refuses any `Authorization` header on a call while registration, Test, refresh and health checks all passed. A manual Test of a server with **Send identity token** on now sends the identity token of the editor who pressed it (`gateway` `omp:test`, no `tool`, `client` `Test connection`). If the server answers `401` or `403` to that and accepts the same request without the token, the Test fails (class `auth`, the server's HTTP status) with "Turn off Send identity token for this server, or have the server accept the token." Refresh and scheduled checks still send no token, and an automation token's Test (no person) sends none. **Not caught:** a server that accepts the request and refuses only when a tool runs (HTTP 200 with `isError`, which is what DeepWiki does) still passes Test. The help text of the switch says what is sent and that some public servers refuse it. No API contract change.
- **Cap on dynamically registered OAuth clients** ([deploy.md](docs/deploy.md), threat model H-4). `OAUTH_MAX_REGISTERED_CLIENTS` (default `1000`, `0` = no cap) bounds the clients registered through the open `POST /oauth/register` that were used in the last 30 days; over it the endpoint answers `503 temporarily_unavailable`. Clients that use a metadata document aren't counted. **Upgrade note:** an installation with more than 1000 live registrations stops accepting new ones until some expire; set the variable higher (or `0`) first if that matters. The per-address limit (10 a minute) is unchanged.
- Kubernetes smoke test: `make k8s-smoke` ([`scripts/k8s-smoke.sh`](scripts/k8s-smoke.sh), [docs/deploy.md](docs/deploy.md#smoke-test)) applies the Kustomize base, through the new test overlay `deploy/kubernetes/overlays/smoke`, to a three-node kind cluster with a throwaway PostgreSQL and the fake MCP server, and checks the migrate init container, `doctor`, spreading over nodes, the PodDisruptionBudget, the API and `/mcp/{slug}` in both protocol eras, a rolling update and a pod deletion with no failed request, and the SIGTERM drain; `SMOKE_CNI=calico` enforces and tests the NetworkPolicies. `.github/workflows/k8s-smoke.yml` runs it on demand, weekly and on pushes to `main` that touch `deploy/**`, the `Dockerfile` or the script (not yet run on GitHub). It does not cover ingress, TLS, OIDC, kindnet's missing NetworkPolicy enforcement, zones or upgrades.
- Dependencies: Go `kin-openapi` 0.149.0 to 0.151.0, `go-jose` 4.1.5 to 4.1.6, `goose` 3.28.0 to 3.29.0; the web group (React 19.3.1, TanStack Query and Router, lucide-react, Vitest). `govulncheck` and `npm audit` report nothing.
- Documentation: a public server that refuses any `Authorization` header (found with DeepWiki's `https://mcp.deepwiki.com/mcp`) fails on its first call while **Send identity token** is on, because the token travels as `Authorization: Bearer`; documented in [registry.md](docs/registry.md) and the docs site's troubleshooting page. Claude Code 2.1.280 was run against the 2026-07-28 revision, over an API key and over OAuth on a real deployment ([status.md](docs/status.md)).
- The example Kubernetes overlay pins v0.2.0's digest.
- Repository: `web/node_modules`, a local symlink committed by mistake in v0.2.0, is no longer tracked, and `.gitignore` ignores it whatever its type.

## [0.2.0] - 2026-10-18

Support for the MCP 2026-07-28 revision, pilot readiness (admin overview, notifications, automation tokens) and fixes from
a security review ([release notes](docs/releases/v0.2.0.md)). Migrations `00014` to `00017`.

**MCP 2026-07-28, server side** ([docs/mcp-protocol.md](docs/mcp-protocol.md), decision 51). Gateways at `/mcp/{slug}`
now speak the new protocol era next to 2024-11-05 to 2025-11-25, chosen per request; legacy clients see no change.

- `server/discover` (supported versions, capabilities, identity); required `_meta`, `MCP-Protocol-Version`,
  `Mcp-Method` and `Mcp-Name` validated against the body (`400`, `HeaderMismatch` `-32020`; unsupported version
  `-32022` with the supported list; unknown methods `404` `-32601`); `Mcp-Param-*` headers validated for tools with
  `x-mcp-header`.
- Results carry `resultType` and `_meta` `serverInfo`; lists, discovery and reads carry `ttlMs` and
  `cacheScope: "private"` (lists differ per person, never public); lists sorted by exposed name.
- Any JSON Schema `outputSchema` and any JSON `structuredContent` pass through to modern clients (legacy clients
  still get object schemas only); resource not found is `-32602` (legacy `-32002`); `ping` and `logging/setLevel`
  are method not found; the rate-limit code is `429` instead of `-32029` for modern requests.
- "Connect your account" as a multi round-trip request: modern clients that declare URL elicitation get an
  `input_required` result with the existing connect link and a sealed `requestState` (AES-GCM, key derived from
  `ENCRYPTION_KEY`; bound to the person, gateway, request and parameters; 10 minutes) and retry; declines return
  "authorization declined". A modern client that did not declare URL elicitation gets no `-32042` (the revision forbids it): a tool call answers a tool error and a prompt or resource read `-32010`, with the same link in the message. Legacy clients keep `-32042`.
- Dynamic client registration accepts and echoes `application_type` (`web` or `native`); documented as deprecated.
- `cmd/fakemcp -schema-tools`; `secrets.Box.Derive`. The MCP conformance suite was run against a gateway
  (results in docs/mcp-protocol.md).

**MCP 2026-07-28, client side** ([docs/mcp-protocol.md](docs/mcp-protocol.md#the-portal-as-a-client-of-your-servers),
decisions 51 and 54). How the portal talks to your servers. Migration `00016` (three nullable columns on `mcp_servers`).

- **Era negotiation per server.** Discovery, refresh, test, health checks and forwarded calls try the modern era first
  (`server/discover`) and fall back to `initialize` only by the specification's rule (a `400` whose body is not a
  recognized modern error; `404` and `405` from an HTTP+SSE-only server stay errors). The newest mutually supported
  version is used. The era is cached in memory per server ID and URL for 5 minutes. The last negotiated `protocol`
  (`era`, `version`, `negotiatedAt`) is stored on the server by refresh, test and health checks and returned by the API
  (`McpServer.protocol`; cleared when the URL changes).
- **Elicitation is relayed.** An upstream `input_required` result reaches a modern client that declared elicitation as
  `inputRequests` (validated, bounded, https URLs only) with a sealed `requestState` bound to the person, gateway, call
  and upstream server; the retry goes back to the server with the original parameters, the answers and the server's own
  state. The portal declares to the server exactly the elicitation modes the client declared, per request. Sampling and
  roots are refused with a tool error. Legacy clients keep getting no relay. Recorded `ok` with error class
  `input_required`.
- **Streaming.** A `tools/call` with `_meta.progressToken` from a client that accepts `text/event-stream` is answered
  as SSE: the server's progress (at most 64 events, 4 MiB), then the response; `X-Accel-Buffering: no`, a keep-alive
  comment every 15 s; closing the connection cancels the upstream call. [deploy.md](docs/deploy.md#ingress) has the
  ingress settings.
- `traceparent`, `tracestate` and `baggage` pass from the client's `_meta` to the server's (validated).
- Upstream OAuth: dynamic registration says `application_type: "web"` (SEP-837); a client registered by dynamic
  registration is registered again, and chosen afresh (a Client ID Metadata Document is preferred), when the resource
  metadata names another authorization server (SEP-2352).
- A request id of its own for every modern request, a retry included (found by the conformance suite, which passes its
  client scenarios for this revision except the interactive `auth/*` ones: `cmd/upstream-conformance`).
- `cmd/fakemcp -protocol legacy|modern|both`, `-mrtr-tools`, `-stream-tools`.

### Security

Fixes from the [threat model](docs/threat-model.md) review (section 8). Two additive API changes need a client update:
approving now names what was reviewed. People re-consent once per server for provider tokens (F-3).

- **Another origin never keeps a server's stored header value (F-1).** A URL edit that changes scheme, host or port is
  refused with `422 auth_value_required` unless the same request sends a new `authValue` or removes the header; in `oauth`
  mode it erases the connections and sends the server back to the setup sign-in. The audit entry names `oldOrigin` and
  `newOrigin`. Path, trailing-slash and case edits are unchanged.
- **Approvals are bound to what the reviewer saw (F-2).** `McpServer.reviewDigest` is new and read-only. Approving a
  server (`adminReviewMcpServer`) must send it as `expectedDigest`, approving a capability (`adminApproveMcpCapability`,
  `approveTeamMcpCapability`) must send `expectedFingerprint`: `400 expected_digest_required` or
  `expected_fingerprint_required` without it, `409 changed_since_review` when the server or capability changed in
  between. Publishing accepts an optional `expectedDigest`. The web UI sends them; scripts that approve (such as
  `scripts/dev-seed.py`) read the digest first.
- **Provider tokens are bound to a server and its origin (F-3, decision 60).** A platform provider's token (GitHub,
  Google, ...) used to go to whichever server required the provider, at whatever URL it had, so an editor could make a
  server "require" GitHub, or re-point one, and receive teammates' tokens with no prompt. Now the token is sent only to
  a server the person **allowed**, at the origin (scheme, host, port) it had when they allowed it, for the scopes they
  were shown. A call without that gets consent with the new reason `server_not_allowed` (the same three answer shapes
  as before: `-32042`, the modern URL-elicitation request, or a tool error with the link), and nothing is forwarded.
  **After upgrading, every person consents once per server** the first time they call it (no backfill, on purpose: it
  would grandfather any malicious server). When the person's account already has the scopes, the consent page just
  asks "Allow <server> (<team>)" and records the grant without going to the provider. A server's grants end when its
  URL moves to another origin, it requires another provider, or it is deleted (a path-only edit keeps them);
  disconnecting deletes the account's. Migration `00017` (table `provider_server_grants`; two nullable columns on
  `provider_connect_requests`; a consent link made before the upgrade is refused as expired, run the tool again).
  API (additive): `POST /v1/connect/requests/{id}/confirm`, `ConnectRequest.server` and reason `server_not_allowed`,
  `ProviderConnection.allowedServers`; Account › My connections lists the allowed servers. **Not changed:** the token
  still holds the union of every scope the person granted, a server they allowed receives all of them, and there is no
  per-provider allow-list of teams or servers (H-5).
- **Sign-in `next` refuses control characters (F-4).** `/auth/login?next=/%09/evil.example` ended in a redirect to
  `//evil.example`; sign-in and the connect flow now share one path rule (`internal/safepath`).
- `serve` refuses an `ENCRYPTION_KEY` equal to the `API_KEY_PEPPER`; the main listener's `ReadHeaderTimeout` (10 s) and
  `IdleTimeout` are pinned by a test; CI runs `govulncheck` and `npm audit --audit-level=high` (none reported).

**v0.2 pilot readiness, web UI.** Admin Overview (replaces the redirect to Users) and a team attention card; a bell and inbox in the header, notification preferences per event and channel, team and platform webhook destinations (shown as a host, the signing secret shown once), a test email; Automation tokens pages (platform and team); the protocol a server last negotiated on its overview; the consent page names the server and team and allows it without a round trip (F-3); the review dialogs send what the reviewer saw (F-2).

**v0.2 pilot readiness, backend** (migrations `00014`, `00015`; designs: [admin overview](docs/admin-overview.md), [notifications](docs/notifications.md), [automation tokens](docs/automation-tokens.md)).

- Admin overview and team attention: `GET /v1/admin/overview` and `GET /v1/teams/{team}/attention` (failing and changed servers, lapsed sign-ins, pending reviews, expiring keys and tokens, connections, gateways, rate limits, notification failures), computed per request with exact totals.
- Notifications: in-app inbox, email through `SMTP_*` (off without `SMTP_HOST`; STARTTLS required, certificates always verified, verified addresses only), signed (HMAC-SHA256) and Slack-compatible webhooks. Eight events, per-person preferences, team and platform destinations, delivery log, retries with backoff, `doctor` check. Webhooks reach public https addresses only; internal ones only through the new `NOTIFY_WEBHOOK_ALLOWED_NETWORKS`, never the MCP servers' allowlist.
- Automation tokens: platform-admin (`ompadm_`) and team publisher (`omppub_`) tokens for `/v1`, scoped by `x-omp-token-scopes`, expiring, revocable, audited as the token; never valid for `/mcp`. Create no token until every replica runs this release.
- Upgrade notes: users must sign in once for their email to count as verified; `API_KEY_PEPPER_PREVIOUS` also covers tokens; the new `go.mod` entries are indirect.

## [0.1.0] - 2026-10-17

The first release ([release notes](docs/releases/v0.1.0.md)): a self-hosted portal where teams register MCP servers, publish them to a company catalog, curate
gateways and give people and agents governed access. Migrations `00001` to `00013`.

**Foundations** (Phase 1). Configuration from environment variables or a YAML file (`OMP_CONFIG_FILE`, `<NAME>_FILE`
secrets), PostgreSQL 17 with forward-only expand/contract migrations, OIDC sign-in plus a loopback-only development
sign-in, sessions with CSRF and Origin checks, users, teams, members and invites, platform admins and auditors, an
append-only audit log, and the web UI shell (workspace and admin modes, team switcher, command palette). The OpenAPI
contract (`api/openapi.yaml`) is enforced by a route test and an authorization matrix over every operation.

**Registry and catalog** (Phase 2). Team-owned remote MCP servers with discovery of tools, resources, resource
templates and prompts, change detection and review, scheduled health checks, encrypted static header values
(`ENCRYPTION_KEY`), a company catalog with approval or self-publishing policies, and an SSRF guard. Platform admins
allow internal networks and hosts (decision 20, `UPSTREAM_ALLOWED_NETWORKS`).

**Gateways** (Phase 3). Curated sets of capabilities served at `/mcp/{slug}` (Streamable HTTP, stateless), granted to
teams, people or SSO groups; tools and prompts exposed as `{server}__{name}`, resources as `omp://{server}/{uri}`.
Every upstream call carries a short-lived ES256 identity JWT (JWKS at `/.well-known/jwks.json`, rotating and
pre-published keys). Personal API keys (`omp_`, HMAC digests with `API_KEY_PEPPER`), optionally limited to some
gateways. A call log without arguments or results.

**Sign-in for MCP clients and service accounts** (Phase 4). An OAuth 2.1 authorization server for `/mcp/{slug}`:
PKCE S256, Client ID Metadata Documents and dynamic registration, one gateway per connection, per-person consent,
trusted clients, rotating refresh tokens (`ompat_`, `omprt_`, `ompac_`, `ompcl_`). Team service accounts with
expiring keys (`omp_sa_`, two active for rotation).

**Delegated credentials** (Phase 5). Auth providers (presets for GitHub, Google, Microsoft Entra ID, Atlassian, Slack
and GitLab), server requirements and capability overrides, consent links (JSON-RPC `-32042`), each person's tokens
sealed, refreshed under a row lock and revocable, sent to servers in `MCP-Gateway-Provider-Token`. The Gmail example
server in `examples/mail-mcp`.

**Operations** (Phase 6). Rate limits shared by every replica (per person, credential, service account and gateway),
opt-in payload capture (redacted, truncated, sealed, audited views), retention, hourly usage rollups and reports,
Prometheus metrics (`omp_*`, `METRICS_ADDR`), pepper and encryption key rotation (`open-mcp-portal rotate-keys`),
`doctor`, a distroless image, a demo Compose file, a Kustomize base and overlay, and CI.

**Per-person OAuth to upstream servers** (Phase 7). Servers in `oauth` mode (such as GitHub's hosted MCP server):
sign-in discovery (RFC 9728, RFC 8414, OIDC), DCR, CIMD, a manual client or a linked platform provider, a setup
sign-in that reads capabilities, each caller's own token with refresh and step-up, and a per-server `sendIdentity`
switch.

**Fixes since Phase 7**, found by running Claude Code, pi and GitHub's hosted MCP server end to end. An empty token scope from a provider (GitHub Apps) counts as no scope information; tool lists
drop `outputSchema` values that aren't objects and relayed results drop `structuredContent` that isn't an object (MCP
schema); client cancellations aren't recorded as errors; failed exchanges with a server include the server's own
reason (redacted, bounded); forwarded tool calls send SEP-2243 `Mcp-Param-*` headers built from the approved
definition (GitHub's server needs them).

**Renamed to Open MCP Portal** (decision 46), formerly Open MCP Gateway, so it no longer clashes with Open Model
Gateway. Module `github.com/ncecere/open-mcp-portal`, binary `open-mcp-portal`, `OMP_*` environment variables, `omp_*`
metrics, `open-mcp-portal` Kubernetes names. Keys and tokens now start with `omp_`, `omp_sa_`, `ompat_`, `omprt_`,
`ompac_` and `ompcl_` (were `omcp_`, `omcp_sa_`, `omat_`, `omrt_`, `omac_`, `omcl_`), and exposed resources with
`omp://` (was `omcp://`): keys and tokens made before no longer authenticate; create new keys and sign MCP clients in
again. Payload capture still redacts the old prefixes. Migration `00013_open_mcp_portal`. The `MCP-Gateway-*` headers
MCP servers receive keep their names. A development database of the old Compose project moves with
`scripts/migrate-dev-db.sh`.

**Release** (v0.1.0). A `v*` tag runs `.github/workflows/image.yml`: it builds `ghcr.io/ncecere/open-mcp-portal` for
linux/amd64 and linux/arm64 on native runners with SBOM and provenance attestations, checks that the image reports the
tag's version and scans it, signs the multi-arch index with cosign (keyless) and tags it `vX.Y.Z` (and `latest` for a
final release). `scripts/github-release.sh` then creates the GitHub Release from `docs/releases/vX.Y.Z.md` with each
platform's SBOM, the digest and `checksums.txt`. `open-mcp-portal version` prints `open-mcp-portal 0.1.0 (<commit>)`. The
Kustomize base points at `ghcr.io/ncecere/open-mcp-portal:v0.1.0`.

[0.1.0]: https://github.com/ncecere/open-mcp-portal/releases/tag/v0.1.0
