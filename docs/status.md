# Status and handoff

Last updated: 2026-10-28. Open MCP Portal (formerly Open MCP Gateway, decision 46), version 0.3.3, **released on 2026-10-28**
(release notes: [releases/v0.3.3.md](releases/v0.3.3.md); earlier: [v0.3.2](releases/v0.3.2.md), [v0.3.1](releases/v0.3.1.md), [v0.3.0](releases/v0.3.0.md), [v0.2.2](releases/v0.2.2.md), [v0.2.1](releases/v0.2.1.md), [v0.2.0](releases/v0.2.0.md), the first release [v0.1.0](releases/v0.1.0.md)).

## v0.4.0 release candidate: MCP-only governance

Scopes (#29), curation (#30), shared service connections (#26), database-role separation (#44) and
external-platform retirement (#68) were integrated on `integration/credential-policy` for the main release candidate.
[Release/upgrade notes](releases/v0.4.0.md) cover migrations `00029`–`00034` and mixed-version policy limits.
The owner withdrew Pi Durable Platform/external-platform impersonation ([decision 81](decisions.md));
#62/#63 are closed as **not planned**, not completed remediation or verification. Retirement disables
issuers/marked accounts, revokes their keys and fences authority restoration while preserving marks/history.
Normal MCP clients, OAuth, keys, service accounts, personal connections and outbound identity remain.
Existing development services/data have not been changed; verification uses owned disposable fixtures.

Independent reviews and combined regressions corrected scope/OAuth serialization, curation numeric
persistence/retry records, UTC retention arithmetic, shared-connection transaction ordering and retired-account
preservation. A final narrow review approved the five shared transaction fixes and callback guidance without
confirmed findings. Local deletion/audit commits before upstream revocation HTTP; consent uses user
`KEY SHARE` → session → connection → state ordering, with final live authorization checks after waits.

**Final combined tree passed:** `make generate`, `make lint`, `go build ./...`, `make check-generated`,
required-PostgreSQL `make test` and full `go test -race -count=1 ./...` in **both** legacy and genuinely
authenticated split-role modes; web typecheck, **796 tests**, build, styling and size checks; Kubernetes
validation, actionlint, four smoke-helper lifecycle tests and clean diff checks. The full Go/deployment run
completed in 1,130 seconds after the final shared-transaction and callback corrections. Those transaction
regressions also passed three focused race repetitions per mode. Owner-only fixture DDL uses `OwnerPool`;
application writes still use authenticated runtime. Role changes were tested only in an owned disposable
PostgreSQL container, never against the development database.

**Browser/wire evidence:** literal-name scope entry preserves commas; fixed-argument `demo_echo` accepts
injected values and rejects conflicting values/old names. Shared consent through the fake OAuth server,
explicit service-account assignment and destination grants succeed. Actual legacy and modern MCP calls
receive the shared credential with verified portal identity and matching provider claim; a normal personal
caller still needs its own consent and has no personal connection. A 390px shared-connections screen has no
horizontal overflow and zero axe violations/incomplete checks. Browser checks found and corrected a shared
completion page that wrongly linked personal connections, and stale relay wording. Main CI, combined
kindnet/Calico deployment smoke and image/signature/publication gates remain pending.
Rebuilt mobile completion now shows shared guidance and a safe portal link, never personal-connection
instructions. Revoking the shared connection in the UI stops the same service key's next call (`-32010`);
all temporary wire-test keys were revoked. The completion screen has zero axe violations and one gradient
contrast item: manual conservative calculation gives **6.49:1**, above the 4.5:1 normal-text minimum.
These fake-server checks are not real-provider/IDE/pilot acceptance. The published release remains v0.3.3.

## v0.3.3 (2026-10-28)

The [implementation order](implementation-order.md) reconciled 36 open GitHub issues with the v0.3.2
checkout. Shipped and closed: **#28 owner-set tool classification** and independent **#37 browser sessions**.
The classification [design](tool-classification.md) records the trust boundary and migration `00027`;
[session management](phase4-client-auth.md#browser-sessions-37-decision-76) uses migration `00028`.
The combined implementation is committed as `9864b75`; the release is tagged at `8a10de3` and
[published on GitHub](https://github.com/ncecere/open-mcp-portal/releases/tag/v0.3.3). No production deployment
has been performed.

Subagent implementation and independent code reviews found and fixed three regressions before finishing:

- A capability refresh did not advance the server revision. Added/changed/gone capabilities now invalidate an
  old classification dialog; unchanged refreshes preserve its revision. Existing owner classes still
  intentionally survive changed definitions.
- Logout and session revocation deleted rows in opposite orders. Both now lock/delete the session before its
  connect states. A coordinated PostgreSQL regression fails against the old order with a deadlock and passes
  against the fix, including ten race-enabled repetitions.
- Session UI success handling could use a changed keep-current checkbox value rather than the submitted
  choice. The mutation now captures its inputs and sign-out effect; controls are disabled while pending.
  Delayed-response and credential/cache-clearing regressions cover it.

**Passed on the combined tree:** `make generate`, `make lint`, `go build ./...`, `OMP_TEST_REQUIRE_DB=1 make test`
(all Go tests with PostgreSQL required), focused session/classification tests with `-race`, `git diff --check`;
and web typecheck, **697 tests in 71 files**, production build, styling and source-size checks.

**Browser-checked on a scratch database and separate loopback ports:** classification bulk suggestions,
individual lowering and re-review, read-only admin classes; upgrade with an existing browser session intact;
Account Sessions listing/current marker, another-session revocation, keep-current sign-out, default sign-out
and admin self-revocation (the latter two returned to sign-in and `/v1/me` answered 401). Desktop screenshots
were inspected. Browser axe checks reported zero violations on the checked classification/session screens;
incomplete checks remain (the existing search-shortcut contrast and modal background focus checks), so this
is not a complete accessibility audit. Existing dev services and database were left untouched.

**Not run:** real-client/provider/pilot verification, a live Pi Durable Platform instance, a wall-clock idle
expiry soak, a full mobile/all-page browser pass or a fresh conformance-suite run. Docker and deployment
checks subsequently passed in release CI, as recorded below. Idle boundaries,
cleanup and activity throttling are covered with an injected clock. Very large session inventories have not
been load-tested; revoke-all currently deletes pending connect states per ended session.
At release preparation, the external agreement for #62 could not be verified (the linked upstream repository
returned 404). That work has since been withdrawn by the owner; see the unreleased scope change above.
The next implementation lanes were
**#29 scopes**, **#30 curation**, **#26 service connections** and **#44 database roles**, in isolated branches.

The first release-candidate CI passed the full Go race suite, Docker builds, generated-code and deployment
checks, and kindnet/Calico smoke tests, but failed dependency gates: Go 1.26.9's x509 advisory and Undici 8.12.1.
The toolchain/builder are updated to Go 1.26.10 and the web lockfile to Undici 8.12.3; patched application CI
passed. Calico smoke then exposed an orphaned port-forward into a draining pod after eviction: the wrapper
PID, not `kubectl`, had been stopped. The helper now launches/reaps the real process and waits for the evicted
pod to disappear. Four deterministic lifecycle tests reproduce the old failure and pass the fix.

Final [CI](https://github.com/ncecere/open-mcp-portal/actions/runs/40697899296), both
[kindnet/Calico smoke jobs](https://github.com/ncecere/open-mcp-portal/actions/runs/40697899038), and the
[native multi-architecture image/release workflow](https://github.com/ncecere/open-mcp-portal/actions/runs/40699155000)
passed at `8a10de3`. The published index contains linux/amd64 and linux/arm64, with SBOMs and checksums.
Cosign verification checked the tag-specific workflow identity, GitHub issuer, trusted certificate and
transparency-log inclusion. The arm64 image ran read-only with no network and reported
`open-mcp-portal 0.3.3 (8a10de3e34ec)`. The verified index digest is
`sha256:021672961ead3bc78de0e2383373e780ce1035b34b25d676e433199dcf8c5ed8`; the example overlay is pinned to it.
GitHub reported zero open Dependabot alerts after publication.

At v0.3.3 publication, #29/#30/#26/#44 remained staged rather than shipped. See the current release-candidate
section above for their combined verification and the subsequent MCP-only retirement. No production
deployment is implied by either publication or scratch-environment checks.

## v0.3.2 (2026-10-20)

Per-person secrets, machine OAuth, mTLS and a private CA (migrations `00024` to `00026`): see the [release notes](releases/v0.3.2.md). Verified by tests on each branch and the merged tree, and a browser check of the add-server form; **not** run against a real authorization server, a real server that wants a per-person key or a client certificate, or checked in a browser beyond the form.

## v0.3.1 (2026-10-20)

Provider access lists and narrowing, credential parts, tracing (migrations `00021` to `00023`): see the [release notes](releases/v0.3.1.md). Verified by tests and a browser check of two screens; **not** run against a real provider, a real collector or a real server that wants Basic or a query key.

## v0.3.0 (2026-10-20)

Agent-platform trust (migration `00020`): see the [release notes](releases/v0.3.0.md) and [agent-platforms.md](agent-platforms.md). Verified by tests, a contract check against tokens signed by Pi Durable Platform v0.4.0's real signer (19 tokens, 5 key sets) and an independent security review (0 Critical or High). **Not** verified: a live Pi Durable Platform instance end to end.

## v0.2.2 (2026-10-20)

Hardening (migrations `00018`, `00019`): see the [release notes](releases/v0.2.2.md). Verified by tests, including a full authorization-code and PKCE flow for Claude Code's metadata-document shape with a loopback redirect; **not** yet browser-checked or run with the real Claude Code client.

## v0.2.1 (2026-10-18)

What is planned next, and what is still unverified, is the [roadmap](roadmap.md): 49 issues in five [milestones](https://github.com/ncecere/open-mcp-portal/milestones), each with its implementation plan.

The cluster deployment (mcp.bitop.dev) runs v0.2.1, rolled out one replica at a time with no failed readiness probe.

Built, see [CHANGELOG.md](../CHANGELOG.md): a manual **Test connection** sends the editor's identity token and says when the server refuses it (decision 61; the limit is stated there: a server that refuses only at tool execution still passes), and `OAUTH_MAX_REGISTERED_CLIENTS` caps Dynamic Client Registration (threat model H-4, cap done). Verified by Go tests against PostgreSQL (the Test with a fake upstream that refuses `Authorization` at the HTTP level, with the token verified against the JWKS, and the cap with concurrent registrations) and the web tests. Not tried against DeepWiki itself or in a browser.

## v0.2.0 (2026-10-18)

Built: MCP 2026-07-28 toward clients and toward upstream servers ([mcp-protocol.md](mcp-protocol.md); migration `00016`), the admin
overview and team attention, notifications (inbox, email, signed and Slack webhooks), automation tokens (migrations `00014`, `00015`;
designs: [admin-overview.md](admin-overview.md), [notifications.md](notifications.md), [automation-tokens.md](automation-tokens.md)), and the
fixes F-1 to F-4 from the [threat model](threat-model.md), F-3 with migration `00017` (decisions 59 and 60).

Verified: Go tests with PostgreSQL (the route test and an authorization and token matrix over every operation), the web tests, the
`@modelcontextprotocol/conformance` suite, and a browser walkthrough of the new screens against a real stack (an SMTP sink, a webhook receiver,
the fake MCP and OAuth servers): the overview, a test email, a webhook test with its signature checked, a publish request raising a bell
entry, an email and a webhook, a review with the digest, the decision notification, a platform token against the API, and F-3 end to end
(consent naming the server, the grant ending when the server moves to another origin, allowing it again without a provider round trip).

Verified after the release (2026-10-18): Claude Code 2.1.280 was run against a gateway (API-key authentication): it spoke 2026-07-28 natively (`server/discover`, the lists, and `tools/call` with the required `Mcp-Method` and `Mcp-Name` headers), and it showed the person the consent link from the tool error (it declares form-mode elicitation only, so it takes the tool-error answer of decision 59). v0.2.0 was also deployed to a real Talos cluster (CloudNativePG, Traefik, Pangolin, Authentik sign-in; health, `doctor` and the OAuth endpoints checked from outside), with continuous WAL archiving and a daily base backup of its database to object storage. A restore was tested the same day: a scratch cluster recovered in about 70 seconds with identical data and a row written after the base backup (WAL replay). On that deployment Claude Code also signed in over OAuth (a metadata-document client, no registration or consent page) and called tools through a gateway; that run found that a public server refusing any `Authorization` header (DeepWiki) fails on its first call with the identity token on, which led to the v0.2.1 changes. A second restore, in the live namespace under its network policies, also recovered with identical data.

Verified on kind (2026-10-18, `make k8s-smoke`, [deploy.md](deploy.md#smoke-test)): the Kustomize base applied through `overlays/smoke` to a
three-node kind cluster (Kubernetes 1.37.0) with a throwaway PostgreSQL 17 and the in-cluster fake MCP server: the migrate init container and
`doctor`, two replicas on different nodes, the PodDisruptionBudget (one eviction allowed, a second refused), `/healthz`, `/readyz`, development
sign-in, and team, server, gateway and API key through the API, then `tools/list` and `tools/call` at `/mcp/{slug}` in the legacy and the
2026-07-28 era; a rolling update and a pod deletion with no failed request through the Service, and the SIGTERM drain (`/readyz` 503, 10 s, `shutdown complete`).
With `SMOKE_CNI=calico` the NetworkPolicies are enforced and tested (an outside pod cannot reach the portal; the portal reaches PostgreSQL and the
MCP server). Not covered: NetworkPolicy under the default CNI (kindnet does not enforce it), the `egress-https` rule, ingress and TLS, OIDC,
the internal-network allowlist (development sign-in allows private upstream addresses anyway), zones, upgrades between releases and
restores. `.github/workflows/k8s-smoke.yml` ran on GitHub on 2026-10-18 and passed on both CNIs (kindnet and Calico).

Not verified: a client that declares URL elicitation, VS Code and Cursor; a real SMTP provider over TLS and a real Slack webhook; the Kubernetes egress rows on a real cluster; a real Google or
Microsoft provider. Still open from the threat model: the hardening ideas in section 9 (notably H-5, scopes per call and a per-provider
server allow-list).

## Summary

- **Phases 1 to 7 are done** (backend and web UI): foundations, registry and catalog, gateways, client sign-in and
  service accounts, delegated credentials, operations, and per-person OAuth to upstream MCP servers. Details per phase
  below and in each design's "As built" section.
- **Verified with real clients and a real upstream server:**
  - Claude Code's real client signed in to a gateway over OAuth (CIMD, a trusted client, so no consent page) and
    called tools.
  - pi signed in over OAuth (dynamic client registration, through the consent page) and called tools.
  - GitHub's hosted MCP server (`https://api.githubcopilot.com/mcp/`) was set up as an `oauth`-mode server with a
    GitHub App as a manual client, each person signed in with their own GitHub account, and six tools worked from pi:
    `get_me`, `search_repositories`, `list_issues`, `list_branches`, `get_file_contents`, `search_code`.
  - The fixes this found are in git: `4f75508` (an empty token scope from a GitHub App is no scope information),
    `9ff238e` (drop non-object `outputSchema`s; client cancellations aren't errors), `f3272d9` (the server's own
    reason in failed-exchange errors), `6fe0995` (SEP-2243 `Mcp-Param-*` headers on forwarded calls), `0182c12`
    (drop non-object `structuredContent`).
- **Not verified yet:**
  - a real Google or Microsoft delegated-credentials provider (Phase 5 auth providers were only run against the fake,
    `make fake-oauth` with `make example-mail-fake`);
  - VS Code and Cursor (only their configuration snippets; Claude Code and pi were run);
  - a smoke test on kind: now `make k8s-smoke` (see "Verified on kind" above; `.github/workflows/k8s-smoke.yml` not run on GitHub yet);
  - the release workflow (`.github/workflows/image.yml`: native amd64 and arm64 builds, scan, cosign signing, GitHub
    Release) on GitHub's runners: it runs for the first time on the `v0.1.0` tag. `scripts/github-release.sh` was
    dry-run with a stand-in SBOM; `actionlint` and `shellcheck` pass.
- **Release v0.1.0 (2026-10-17), then v0.2.0 (2026-10-18).** `v*` tags run `image.yml`: multi-arch image `ghcr.io/ncecere/open-mcp-portal`
  (tags `vX.Y.Z`, `latest` for final releases) with SBOM and provenance, cosign keyless signature, and a GitHub Release
  from `docs/releases/vX.Y.Z.md`. The Kustomize base uses the `v0.1.0` tag; overlays pin the digest. `CONTRIBUTING.md`
  has the release steps. `compose.demo.yaml` still builds locally.

## Where things stand

- **Renamed to Open MCP Portal (decision 46).** Formerly Open MCP Gateway. Module
  `github.com/ncecere/open-mcp-portal`, binary and command `open-mcp-portal`, `OMP_*` environment variables (`OMP_CONFIG_FILE`,
  `OMP_TEST_DATABASE_URL`, `OMP_TEST_REQUIRE_DB`, `OMP_TEST_LOG`, `OMP_DEMO_PORT`, `OMP_IMAGE`, `OMP_FAKEMCP_IMAGE`),
  metrics `omp_*`, Kubernetes names `open-mcp-portal*`, dev Compose project `open-mcp-portal` (database and user
  `omp`). Prefixes: personal keys `omp_`, service account keys `omp_sa_`, access tokens `ompat_`, refresh tokens
  `omprt_`, codes `ompac_`, registered client IDs `ompcl_`, exposed resources `omp://`; keys and tokens made before
  no longer authenticate, and capture redaction still recognises the old prefixes. Migration `00013_open_mcp_portal`
  (the purge settings `omp.audit_purge`/`omp.calls_purge`, old names still accepted; key prefix checks accept both).
  The `MCP-Gateway-*` headers and the Gateways feature keep their names. An existing dev database moves with
  `scripts/migrate-dev-db.sh`; an existing `.env` needs `DATABASE_URL=postgres://omp:omp-dev-only@127.0.0.1:55442/omp?sslmode=disable`.
- Requirements interview: done. Decisions in [decisions.md](decisions.md); architecture, data model and phases in
  [../SPEC.md](../SPEC.md).
- **Phase 1 (foundations): done.** Browser QA found one blocking bug (`name@localhost` rejected) and polish items; fixed
  in the Phase 2 UI pass except: unnamed command-palette listbox (in `components/ui`), admin team tabs wrapping and
  breadcrumb collapse gap on mobile.
  - Go backend: config, store, migrations (`00001_identity`, `00002_teams`), OIDC + dev sign-in, sessions,
    users, teams, members, invites, platform admin, audit, all routes in `api/openapi.yaml`.
  - Tests: unit + integration (per-test databases), route/OpenAPI contract test, authz matrix over every operation.
  - Verified: `go build`, `go vet`, `gofmt`, `go test ./...`, integration tests with `-race`, `serve` smoke test.

- **Phase 2 (registry): done.** Browser QA run end to end; its findings are fixed (URL change now re-reads
  capabilities and blocks approval until read; form error clearing; rejected → private; wording/confirmations).
  Not re-checked in a browser after the fixes: the 390px layout tweaks. See [registry.md](registry.md).
  - UI routes: `/teams/$team/servers` (+ `?form=new`), `/teams/$team/servers/$serverId` (Overview, Capabilities,
    Health, Settings), `/catalog`, `/catalog/$serverId`, `/admin/servers`, `/admin/servers/$serverId`,
    `/admin/publishing`, publishing override in admin team › Settings. Shared record code in
    `web/src/components/servers/`. 171 Vitest tests.
  - Migration `00003_registry` adds `mcp_servers`, `mcp_capabilities`, `mcp_health_checks`, a one-row `platform_settings` table and `teams.publish_policy_override`.
  - New packages: `internal/registry`, `internal/upstream` (guarded client and SSRF guard), `internal/secrets`, plus `cmd/fakemcp` (`make fake-mcp`).
  - New config: `ENCRYPTION_KEY` (required by `serve`; the example key is refused off loopback), `ENCRYPTION_KEY_PREVIOUS` and `HEALTH_CHECK_INTERVAL` (default 5m). **An existing `.env` needs the `ENCRYPTION_KEY` line from `.env.example`.**
  - Every Phase 2 route in `api/openapi.yaml` is served, with no contract changes. The authz matrix covers every new operation. The tests cover discovery against a fake server, change detection, both publishing policies, catalog visibility and header-value non-disclosure.
  - Gaps: there is no bulk `rotate-keys` command. A URL change on a published server goes back to review under approval_required.

- **Phase 3 (gateways): backend and UI done; verified end to end with curl** (team server → gateway with 2 of 5
  tools → API key → `initialize`, `tools/list` shows only the 2, `whoami` reaches the fake with a JWT it verified
  against JWKS, an unselected tool is refused as unknown and logged `denied`). Browser QA done (no security or blocking bugs); its findings are fixed. 235 Vitest tests. See
  [phase3-gateways.md](phase3-gateways.md) "As built" and [upstream-identity.md](upstream-identity.md).
  - Migration `00004_gateways` adds `gateways`, `gateway_capabilities`, `gateway_grants`, `api_keys`, `signing_keys`,
    `mcp_calls` (append-only) and `users.groups`.
  - New packages: `internal/gateways`, `internal/mcpgw` (`/mcp/{slug}`), `internal/identity` (ES256 JWT, JWKS at
    `/.well-known/jwks.json`, rotation loop), `internal/apikeys`, `internal/calls`. `internal/upstream` gained
    `CallTool`/`GetPrompt` and an identity header; `cmd/fakemcp` gained `whoami`/`echo` and `-jwks`.
  - New config: `API_KEY_PEPPER` (required by `serve`; the example value is refused off loopback) and
    `OIDC_GROUPS_CLAIM` (default `groups`). **An existing `.env` needs the `API_KEY_PEPPER` line from `.env.example`.**
    Dev personas sign in with sample groups (engineering, support, …) for group grants.
  - Every Phase 3 route in `api/openapi.yaml` is served with no contract changes; the contract test skips `/mcp/` and
    `/.well-known/`. The authz matrix covers every new operation. Integration tests cover selection rules, grants by
    team/user/group, `/v1/me/gateways` reasons, an SDK-client end-to-end run (JWT verified against the JWKS, aud =
    server URL, never the API key), nine refusals between list and call that never reach the server, key rotation, and
    a sentinel check that arguments/results are absent from `mcp_calls`, audit and logs.
  - Gaps: resource subscriptions; no rate limit on `/mcp`; no SSE relay (calls are
    buffered within 1 MiB); `server/discover` (2026-07-28 stateless protocol) answered "method not found".
  - Follow-ups done (not yet browser-checked): archived teams stop serving (their team gateways answer 404, their
    servers leave the catalog, gateway-options and health loop, other gateways show `team_archived`; unarchive
    restores); signing keys are pre-published (`next` state, `SIGNING_KEY_PREPUBLISH`, default 24h; migration
    `00005_signing_key_next`); `/v1/me` returns `groups` (Account › Profile shows them; My gateways names the granting
    group via `MyGateway.groups`); `GET /v1/admin/mcp-servers/{serverId}/health-checks` (Admin's Health tab uses it);
    policy changes leave pending servers pending (documented in [registry.md](registry.md), tested).
    Contract changes: `GatewayUnavailableReason` + `team_archived`, `Me.groups` (required), `MyGateway.groups`
    (optional), the admin health-checks operation.
  - Follow-ups done (not yet browser-checked): gateway-options paged (`GatewayOptionPage`, `cursor`/`limit`
    100–500/`q`/`kind`/`server`; the picker searches on the server, filters by kind and server, loads more);
    resources and resource templates (exposed as `omp://{serverSlug}/{uri}`, RFC 6570 `{var}`/`{+var}` templates,
    `resources/list|templates/list|read`, JWT claim `resource`); API keys limited to gateways (`gatewayIds`,
    `ApiKey.gateways`, error class `key_scope`). Migration `00006_gateway_resources_key_scopes`. See
    [phase3-gateways.md](phase3-gateways.md) "As built".

- **Internal MCP servers (decision 20): done, not browser-checked.** Platform admins allow internal networks (CIDRs)
  and host names (exact or `*.suffix`, optionally with plain http) in **Admin › Internal networks**
  (`/admin/networks`: staged edits, Save with If-Match and confirmation, read-only deployment entries, a URL checker);
  `UPSTREAM_ALLOWED_NETWORKS` adds read-only deployment entries. Loopback, link-local/metadata, unspecified, multicast
  and broadcast stay blocked. Rules in [registry.md](registry.md#security), operations in
  [deploy.md](deploy.md#internal-mcp-servers).
  - Migration `00007_network_allowlist` adds a one-row `network_settings` table (entries JSON, own revision).
  - New package `internal/netpolicy` (classification, canonical entries, matching); `upstream.Client` gained
    `Networks` (the live policy) and `Dial` (a test seam); `registry.Networks` caches the admin entries (30s; the saving
    replica applies a change at once).
  - Contract changes: `GET`/`PUT /v1/admin/settings/network`, `POST /v1/admin/settings/network/check`; schemas
    `NetworkEntry`, `NetworkSettings`, `NetworkSettingsUpdate`, `NetworkCheckRequest`, `NetworkCheckResult`; new
    `url_not_allowed` reason `blocked_address` (loopback/link-local/metadata literals and `localhost`, previously
    `private_address`); `private_address` now says a platform admin can allow the network; audit
    `settings.network_update`. `Registry.Target` takes a context.
  - UI: the add-server and settings URL fields let plain http through to the server (it decides from the allowlist);
    a `private_address` refusal links platform admins to Internal networks and tells others to ask one.

- **Phase 4 (client sign-in and service accounts): backend and UI done; QA follow-ups done.** OAuth 2.1 authorization
  server for `/mcp/{slug}` (always on; CIMD and DCR clients, PKCE S256, resource = one gateway, consent per person +
  client + gateway, trusted clients, rotating refresh tokens) and team service accounts with `omp_sa_` keys. See
  [phase4-client-auth.md](phase4-client-auth.md) "As built", [connect-clients.md](connect-clients.md) and
  [upstream-identity.md](upstream-identity.md) (`principal_type`).
  - Migration `00008_client_auth` adds `oauth_settings` (trusted clients, seeded with Claude, Claude Code, VS Code),
    `oauth_clients`, `oauth_grants`, `oauth_codes`, `oauth_tokens`, `service_accounts`, `service_account_keys`,
    `service_account_key_gateways`; `mcp_calls` gains principal kinds `oauth`/`service_account` (nullable `user_id`)
    and snapshot columns.
  - New packages: `internal/oauth`, `internal/serviceaccounts`, `internal/ratelimit`. `upstream.Client.GuardedDial`
    lets metadata documents use the MCP servers' address guard and allowlist. `auth.SessionUser`/`LoginURL`; the
    post-login `next` limit grew to 8300 characters (an authorization request).
  - Protocol endpoints `/oauth/*` and `/.well-known/oauth-*` are outside the OpenAPI contract (the contract test skips
    `/oauth/`). Every `/v1` route already in `api/openapi.yaml` is served with **no contract changes**; the authz
    matrix covers all 16 new operations.
  - Verified: `make generate`, gofmt, vet, build, `go test ./...`, `make test-integration` (race), and a curl smoke
    test (fake MCP server, CIMD on a loopback http server under the development allowance, hand-made PKCE pair,
    consent, token, `tools/call whoami` showing `principal_type: user` and `client`, refresh rotation, then a service
    account key showing `principal_type: service_account`). Real clients: Claude Code (CIMD, trusted, no consent) and
    pi (DCR, consent page) signed in and called tools. VS Code and Cursor not tried.
  - Gaps (rate limits and pepper rotation: done in Phase 6): no rate limit on `/mcp` itself; rate counters per process; no previous-pepper support (rotating
    `API_KEY_PEPPER` signs clients out and invalidates keys); no CORS on OAuth endpoints; no private-use redirect
    schemes; DCR clean-up runs on registration; the previous release can't list call records of service accounts.
  - QA follow-ups done (not yet browser-checked): see [phase4-client-auth.md](phase4-client-auth.md) "As built: QA
    follow-ups". Contract changes: `GET /v1/teams/{team}/service-accounts/{serviceAccountId}/gateways`
    (`MyGateway` items), `GET /v1/admin/service-accounts` (`ServiceAccountPage`), team call lists also include the
    team's service accounts' calls through any gateway, `CallPrincipal.serviceAccountExists` and
    `oauthClientVerified`; identity JWT claim `client_verified`. Migration `00009_call_principals` (nullable
    `mcp_calls.oauth_client_kind`, an index). CIMD fetches logged at info level; the OAuth error page follows the
    color mode; UI fixes (rotation note, sign-in note for apps, combined notices, wording, focus).

- **Phase 5 (delegated credentials): done.** Auth providers (presets for GitHub, Google, Microsoft Entra ID,
  Atlassian, Slack, GitLab), server requirements and capability overrides (review when widened), consent links
  (JSON-RPC `-32042`), the connect flow (`POST /v1/me/connections/start`, `GET /connect/callback`), tokens sealed and
  refreshed under a row lock, revocation, and the runtime headers `MCP-Gateway-Provider`/`MCP-Gateway-Provider-Token` with
  the identity claim `provider`. See [phase5-delegated-credentials.md](phase5-delegated-credentials.md) "As built" and
  [upstream-identity.md](upstream-identity.md#provider-tokens).
  - Migration `00010_delegated_credentials` (`auth_providers`, `provider_connections`, `provider_connect_requests`,
    `provider_auth_states`; requirement columns on `mcp_servers`/`mcp_capabilities`; `mcp_calls.provider_slug` and the
    outcome `needs_authorization`).
  - New package `internal/providers`; `cmd/fakeoauth` (`make fake-oauth`, port 8092); the fake MCP server's
    `provider_token` tool. No new settings.
  - Contract: all 14 operations served. Additive changes made while building: `AuthProviderPreset.redirectUri`, `name`
    in `in_use` details' servers, provider slugs `done` and `callback` reserved (`422 invalid_slug`).
  - UI: Admin › Auth providers, Account › Connections, the connect pages (`/connect/{provider}`, `/connect/done`),
    "Needs" badges on servers and gateways.
  - Verified: `make generate`, gofmt, vet, build, `go test ./...`, `make test-integration` (race), `make k8s-validate`;
    end to end only with the fake provider (`make fake-oauth`, `make example-mail-fake`). Not verified against a real
    Google or Microsoft provider.
  - Gaps: no background refresh (the start rate limit is shared since Phase 6); see the design's "Not in this phase".

- **Phase 6 (operations): backend and UI done; browser QA done and its findings fixed.** Rate limits shared by replicas in PostgreSQL (per person, credential,
  service account and gateway; 429 + JSON-RPC `-32029`, recorded `rate_limited`), payload capture (opt-in per gateway or
  server, redacted, 16 KiB, sealed, audited views), retention loop, hourly usage rollups and reports, Prometheus metrics
  on `METRICS_ADDR`, `API_KEY_PEPPER_PREVIOUS`, `open-mcp-portal rotate-keys`, doctor key reports, and
  `.github/workflows/ci.yml`. See [phase6-operations.md](phase6-operations.md) "As built" and [deploy.md](deploy.md)
  (Metrics, Key rotation, Scaling).
  - Migration `00011_operations`. New packages `internal/limits`, `internal/capture`, `internal/retention`,
    `internal/usage`, `internal/observability`, `internal/keyrotation`; `internal/ratelimit` has a PostgreSQL store, and
    the OAuth, connect-start, sign-in and `/v1` limiters use it. Dependency `prometheus/client_golang` v1.25.0.
  - New config: `API_KEY_PEPPER_PREVIOUS`, `METRICS_ADDR`, `METRICS_MAX_OBJECTS`, `RETENTION_INTERVAL`,
    `RETENTION_BATCH_SIZE`. New targets `make test-ci`, `make actionlint`.
  - Contract: all 19 operations and the new fields served; **no contract changes**.
  - UI: Admin › Limits, Retention, Payload capture (patterns, tester), Usage; Admin › Teams › a team › Limits &
    retention; Team › Usage and Settings › Limits & retention; gateway rate limit and "Record call contents" switches
    on gateways and servers; call pages with "View contents"; capture badges (catalog, picker, My gateways).
  - QA fixes: catalog list badge; a server PATCH that changes nothing writes no audit entry and keeps the revision;
    usage times in UTC; call page (h1 size, 403 explained, platform staff pointed to Admin for recorded contents);
    chart colours; invalid team overrides not previewed; staged gateway limit shown; retention period in the capture
    confirmations; browser-side pattern check (RE2 rules still decide); named month/day/year selects for custom usage
    dates; "Nothing deleted" in Retention's last run. Not re-checked in a browser after the fixes.
  - Verified: `make generate`, gofmt, vet, build, `go test ./...`, `make test-integration` (race), `make k8s-validate`,
    actionlint; web typecheck, 421 Vitest tests, build, `check:styling`, `check:size`.
  - Gaps: CI never run on GitHub; the kind smoke test (`k8s-smoke`) came later (2026-10-18); provider-token redaction had unit tests only (the end-to-end
    test came in v0.2.2: `TestEchoedProviderTokenIsRedactedEverywhere`).
- **Deployment (Phase 6 slice): done, not on a cluster.** Distroless image (`make docker`; `--target fakemcp` for the
  demo), `compose.demo.yaml` (`make demo`: gateway + Postgres + fake MCP server, dev sign-in), Kustomize base and
  example overlay in `deploy/kubernetes` (one Deployment with a migrate init container, Service, PDB, NetworkPolicies,
  ServiceAccount), `make k8s-validate` (kustomize + kubeconform). Guide: [deploy.md](deploy.md). Verified: image
  `migrate` + `serve` in production mode (https APP_URL, OIDC, fresh keys) against a scratch database, `/healthz`,
  `/readyz`, `doctor`, SIGTERM drain; demo discovered the fake server's capabilities; `k8s-validate` passes.

- **Phase 7 (upstream OAuth): done; verified end to end against GitHub.** Servers in `oauth` mode
  (GitHub's hosted MCP server): detect (RFC 9728/8414/OIDC discovery through the guard), save with DCR, CIMD, a manual
  client or a linked platform provider, setup sign-in that reads capabilities, each person's own token as the bearer
  (identity in `MCP-Gateway-Identity`, or none with `sendIdentity: false`), 401 refresh-and-retry, 403 step-up, health
  "requires sign-in", review triggers. See [phase7-upstream-oauth.md](phase7-upstream-oauth.md) "As built".
  - Migration `00012_upstream_oauth`; new package `internal/upstream/oauthmeta`; `fakeoauth`/`fakemcp` protected modes.
  - Contract additions: `sendIdentity` (McpServer, create, update; decision 45), `McpServerOAuth.redirectUri`,
    `ConnectRequest.authorizationServerHost`.
  - Verified: `make generate`, gofmt, vet, build, `go test ./...`, `make test-integration`, `make k8s-validate`; a live
    detect against `https://api.githubcopilot.com/mcp/` (oauth, github.com/login/oauth, S256, manual, ten scopes);
    then GitHub end to end: a GitHub App as the manual client, setup sign-in, each person's own sign-in, and six tools
    called from pi (`get_me`, `search_repositories`, `list_issues`, `list_branches`, `get_file_contents`,
    `search_code`). Fixes from that run: `4f75508`, `9ff238e`, `f3272d9`, `6fe0995`, `0182c12`.
  - Gaps: upstream CIMD only tested as unavailable on loopback; DCR upstream only against the fake.

## Differences from Grounded (deliberate)

- OIDC login state lives in PostgreSQL (`login_states`), not Valkey.
- Rate limits are counted in PostgreSQL (UNLOGGED table), not Valkey.
- Listen address env var is `LISTEN_ADDR` (default `:8088`); config file env var is `OMP_CONFIG_FILE`.
- Malformed emails return `400 invalid_json` (generated Email type), same as Grounded.
- OAuth for MCP clients is always on (Grounded has a setting) and binds each connection to one gateway.
- Dropped for now: notifications/email, tracing. SSO groups are back
  (`users.groups`, for grants); API keys are our own implementation (`internal/apikeys`), personal only.

## Resume checklist

1. Read `AGENTS.md`, this release-candidate section and [implementation order](implementation-order.md).
   Check the branch, worktree changes, main CI and published tag before assuming a release is complete.
2. Preserve existing services and the real development database. Do not reseed/reset it, run migrations
   against it, overwrite a running `bin/` executable or start duplicate servers on development ports.
3. Use scratch binaries and owned disposable browser/database fixtures. Database role changes and genuine
   split-role tests require an owned PostgreSQL container, not the development cluster.
4. Run the [contribution gates](../CONTRIBUTING.md#tests) with `OMP_TEST_REQUIRE_DB=1`; exercise both
   `OMP_TEST_SPLIT_ROLES=0` and `1`. Regenerate contracts/SQL, inspect actual diffs, and record unrun checks.
5. Follow [release steps](../CONTRIBUTING.md#releasing): passing local tests is not publication. Wait for
   main CI, both deployment smoke jobs, image scans/signing and verification of the published digest.

For a **new** development instance, use [development setup](../CONTRIBUTING.md#development-setup), not a
blind restart/seed of an existing one. The historical dev-database migration helper remains
`scripts/migrate-dev-db.sh`; running it is an explicit operator task, not part of resuming feature work.

## Next steps

1. Finish v0.4.0 main CI/kindnet/Calico smoke;
   publish only after image scans/signing succeed, then verify digest/signature/SBOMs and update release status.
   Close #26/#29/#30/#44/#68 only with their actual acceptance evidence.
2. Implement #31 sensitive-call approvals on the combined scopes/curation path. The next reserved migration
   is **`00035`**, with proposed decision **82**; earlier plan numbers were superseded by retirement.
3. Continue #32/#33 and the ordered operations/lifecycle/audit lanes in
   [implementation order](implementation-order.md). #43 must prove upgrades, ingress, restore and load before
   Helm packaging; existing kindnet/Calico smoke does not establish those broader requirements.
4. Keep #13–#20's real review/client/provider/channel/pilot evidence separate. VS Code planning and fake OAuth
   browser checks do not close compatibility or real-provider issues. Use authorized throwaway accounts and
   dedicated client profiles; do not contact external recipients or use personal profiles implicitly.
5. Record remaining browser/accessibility/load and wall-clock expiry/refresh gaps honestly. Sampling, roots,
   logging and deprecated transports are not reintroduced; external-platform impersonation stays retired.

## Phase 1 UI

- Grounded's Vite/React app, Bitop UI library unchanged, templates, shell, team switcher, admin mode, command palette.
- Routes: `/`, `/settings/profile`, `/teams/$team`, `/teams/$team/settings?tab=members|audit|general`,
  `/admin` (→ users), `/admin/users`, `/admin/users/$userId`, `/admin/teams`, `/admin/teams/$team`, `/admin/audit`.
- Navigation lives in `web/src/components/layout/nav.tsx` as typed lists; a test checks links resolve. Adding MCP
  sections = a route plus one nav item.
- Verified: typecheck, 118 Vitest tests (with axe), build, styling/size checks; embedded build serves `/` and deep
  links; auditor can read team audit and admin users.
- `npm install` crashed in npm's resolver; the lock file was derived from Grounded's and pruned (256 packages, 0
  vulnerabilities). Re-check with a clean `npm ci`.

Known UI gaps:

- No team-scoped "update team" endpoint: team settings › General saves through `PATCH /v1/admin/teams/{team}`, so
  only platform admins can rename/archive (same as Grounded).
- No admin overview endpoint; `/admin` redirects to Users.
- `web/README.md` missing; `src/components/templates/README.md` and some comments still use Grounded wording.
- `errors.tsx` and `pager.tsx` copied but unused.
- Playwright e2e suite not set up.
