# Agent handoff: verified v0.10.0, governance and CLI shipped

**Latest execution instruction:** work directly in the main thread; start no subagents unless the owner explicitly asks again. Earlier delegation authorizations below are historical. The v0.10.0 evidence/pin follow-up `36210cf` passed all seven CI jobs41052812091 and all five Kubernetes jobs41052812085, and its preserved Release evidence footer/final confirmations are complete. A local v0.10.1 invite-acceptance deadlock candidate is now under validation, with no migration or SCIM implementation; see [status](status.md) and [candidate notes](releases/v0.10.1.md).

The original stop point was the verified v0.5.1 machine transfer. On 2026-10-29 the owner resumed ordered
backlog work, authorized releases when ready and delegated incidental decisions. **Do not cut v1.0.0 without
the owner's explicit decision.** #33's quota/concurrency/read-retry/breaker stage shipped and is verified
in v0.7.0; separate failover shipped in verified v0.8.0 and #33 is closed. #32 shipped in v0.6.0 and is closed. See
[upstream protection](upstream-protection.md) and [status](status.md) for scope and verification.
The original release tags remain immutable. No old environment, keys or data were transferred implicitly. Use owned fresh fixtures;
secure restoration of an existing encrypted database still requires its matching keys and operator control.

[Status](status.md) is the source of truth for release SHAs, image digests, CI evidence and remaining blockers.

The separate **v0.8.0 failover release is published and independently verified**: four complete mandatory-
PostgreSQL normal/race suites in both actual role modes (3,440s), all 853 web tests/deployment/advisories,
actual source/published browser/secondary-audience/quota checks and previous-v0.7.0/schema47 compatibility.
Main/tag CI, both CNI smokes, signed native images and independent signature/SPDX/provenance/checksum/
runtime verification passed at immutable source `c36ed3c6bbb8765004d243d1fc0bb37a8f80d106` and digest
`f73129a94cfdc8cc2badc6b2f1e21b74bd0bbc1fd6144afbb50f1986c592c960`. See [failover](upstream-failover.md),
[release notes](releases/v0.8.0.md) and [acceptance](https://github.com/ncecere/open-mcp-portal/issues/33#issuecomment-6499585660).
Keep published owner-mobile/health-mobile contrast and review-dialog aria-hidden-focus/contrast incompletes
explicit; they are not whole-product accessibility acceptance. The evidence/image-pin follow-up passed.

**Previous baseline (historical):** v0.9.0 is published at immutable source `f829b93bd90b2ea1536b9c997978a8f8affd737b`,
verified image `8a620e21c84786b9d8f6c326c19003a118456f17c322898174f008122f46f115`. #35's released
specification was confirmed before design and its conservative first stage shipped (decision86, migration48).
All four mandatory-PostgreSQL normal/race suites, 853 web tests, actual v0.8.0/schema48 compatibility,
source runtime/browser/restart and deployment/advisory checks passed. Exact-source main CI, both-CNI
smoke/ingress/restore, actual upgrade/rollback/canary and three-replica load checks passed, as did native
publication and independent signature/checksum/SPDX/SLSAv1/source/architecture verification. The actual
published read-only restricted runtime reopened a pre-publication authenticated task handle and passed
the full real-HTTP/browser smoke. Final tag CI/upgrade passed and
[#35 is closed](https://github.com/ncecere/open-mcp-portal/issues/35#issuecomment-6514201092). The example
image-pin/evidence follow-up `bcfb5e7` passed all seven CI jobs40998064377 and five Kubernetes jobs40998064220; [final confirmation](https://github.com/ncecere/open-mcp-portal/issues/35#issuecomment-6514713744). Both source and published editor-mobile contrast checks remain incomplete. See [status](status.md).
#43's Kubernetes gates and #52's scanning design are closed (decision87); scanner follow-ups #70–#73
are development work, not implemented scanning. **Current override: v0.10.0 is published and independently verified.** #40 governance and #46 CLI are closed with scoped acceptance at immutable source `875ef01caf94254882d5d08b23c6fb7924594043`, tag object `1b86ddd5d435502c9f9d18644d1eadc57a594c42`, index `b6060f98b8efc256f76ecae23a0174eaa95de5116c4ba41687f7d7b37785bf13`. Four complete normal/race PostgreSQL suites in actual role modes,896 web tests, all local/main/tag/deployment/upgrade/canary/load gates and actual prior-published-image compatibility passed. Independent image/source/OIDC/SPDX/SLSAv1 verification and all six genuine CLI signatures/checksums/byte-identical rebuilds passed. Actual published read-only restricted runtime reopened a pre-publication task and preserved old ciphertext/confirmation; the signed Linux CLI passed the clean-home token-only workflow. Fourteen source and fourteen published browser states had zero violations/overflow; two open confirmation dialogs retain aria-hidden-focus/contrast incompletes. Other-OS execution, real client/provider/pilot, natural-expiry soak and whole-product security/accessibility are not claimed. See [release notes](releases/v0.10.0.md) for the interrupted original pre-schema50 upstream-task gap and completed separate proofs. The evidence/example-pin follow-up is validated separately; do not move the tag. Migrations49/50 are immutable; future DDL is51+ only after inspecting integrated state. There are24 open issues:16 development/eight real-world. The #36 SCIM
preflight is a draft with unresolved parent-review objections, not accepted policy or implementation. Never move/reuse an existing tag.

## Start here

1. Fetch `origin/main` and tags; inspect `git status`, the latest main CI and the published release. Work from
   `main`, not an old approval/refresh/upstream-protection branch, for the released baseline. Inspect
   any active work before changing branches; do not discard an in-progress patch.
2. Read `AGENTS.md`, [CONTRIBUTING.md](../CONTRIBUTING.md), [status](status.md) and
   [implementation order](implementation-order.md). Preserve completed suite logs and owned
   compatibility/runtime fixtures with their matching keys. The v0.9.0 evidence/pin follow-up is complete
   and its tag is immutable. #33/#35/#40/#46 are closed; v0.10.0 is verified. Validate its evidence/pin
   follow-up CI, then correct/decide #36 SCIM's draft before implementation;
   do not restart shipped task implementation. Preserve approvals and access checks on every task operation.
   Do not restart old failover work or treat fixture results as real-client/provider/pilot evidence.
3. Git transfers source, migrations, generated contracts, tests and docs—not `.env`, encryption/signing keys,
   provider credentials or the existing development database. Use the documented fresh-instance setup or
   explicitly arrange a secure, consistent database-and-keys transfer. Never reset/reseed the old database,
   regenerate keys for its encrypted records, or run feature tests/migrations against database `omp`.
4. Use Go 1.26.10+, Node 22+, Docker, Python 3 and sqlc 1.31.1. Run `npm ci` in `web/`. Build scratch binaries
   outside `bin/`; an existing development instance may own ports 8088/8091/8092/8093.

## What is finished

- v0.3.3: classification #28 and browser sessions #37.
- v0.4.0: credential scopes #29, per-gateway curation #30, shared service connections #26, split database
  roles #44 and retirement of external-platform impersonation #68. #62/#63 were withdrawn, not verified.
- v0.5.0: sensitive-call approvals #31, decision 82, migrations `00035`–`00042`.
- v0.5.1: provider-refresh reliability under constrained pools, scoped endpoint dependency reads, complete
  exchange deadlines, and cancellation/drain before transaction SQL resumes. No new migration/API setting.
- v0.6.0: #32 opt-in gateway access requests, private human stewardship/notifications, atomic user/team
  grants and optional expiry, decision83/migrations43–45. Main/tag CI, both smoke CNIs, signed native images,
  SPDX/provenance/checksums and actual-published strict-runtime browser/MCP/forced-expiry checks passed.
  Browser modal/mobile-settings axe incompletes remain; this is not whole-product accessibility acceptance.
- v0.7.0: #33 shared server quotas, replica-local concurrency, bounded trusted-read retries and circuit breaking,
  decision84/migration46. Full local normal/race suites in both actual role modes, 848 web tests, main/tag CI,
  both smoke CNIs, independent signature/SPDX/provenance/checksum/runtime verification and actual-published
  strict-runtime browser/MCP quota checks passed. Owner-mobile contrast remains an axe incomplete. No failover,
  production deployment, broad soak or real-client/provider/pilot acceptance is implied; #33 remained open until v0.8.0.

- v0.8.0: #33 ordered endpoint failover with independent origin-bound sealed static credentials, actual-URL
  identity/definition parity, owner-only review/audit controls and endpoint-aware health/history/rotation;
  decision85/migration47. Full local/CI/native publication/independent artifacts and actual published strict-
  runtime smoke passed. Governed/NoReplay remains primary-only; all older serving/workers must drain before
  relying on endpoint policy. No source/published/browser/data fixture remains live; matching keys/config were
  removed only after destroying the owned database. Existing development state was untouched.

- v0.9.0: #35 bounded ungoverned modern task relay, migration48/decision86; #43 Kubernetes release gates
  and #52 content-scanning design-only/decision87. Full normal/race suites in both roles, 853 web tests,
  main/tag CI, both-CNI base/ingress/restore, upgrade/rollback/canary/load, native publication, independent
  artifact verification and actual-published restricted-runtime task/browser/pre-publication-handle checks
  passed. #35 is closed. Editor-mobile contrast remains incomplete; real Tasks-client/server interoperability
  and governed async lifecycle approval are not claimed. No scanner is implemented by #52.

- v0.10.0: #40 accountable ownership, human label confirmation, gateway ceilings, private review/lifecycle/transfer/attention/notifications and frozen transport cutoffs; #46 token-only CLI/public client/declarative policy-preserving plans, decisions88/89 and immutable migrations49/50. Full local/GitHub/native publication/independent image and six-binary verification plus actual published runtime/browser/signed-Linux-CLI checks passed. No CLI sign-in/keys/new scope, SCIM or whole-product accessibility claim.

See the release sections in [status](status.md) for actual publication/verification rather than interpreting
this list or a local version string as evidence. Release tags are immutable. Main may contain unreleased
backlog work as well as publication evidence and the verified example image digest; inspect current Git/CI.

## Safety boundaries to retain

- The product is MCP-only. Keep normal clients/authentication/provider connections and outbound identity;
  do not restore external issuer trust or person impersonation (decision 81).
- Approval binds effective merged arguments, requester, origin, definition, rule/context and credential
  deadlines. Spend once at actual tool transport after a confirmed commit; never automatically replay a
  consumed authorization. `used` is not proof of upstream success. See [tool approvals](tool-approvals.md).
- Release approval transaction locks before network I/O. Ordinary no-rule admission uses read-only snapshots.
  Keep the conservative governed fence and production autovacuum; contention must fail closed, not authorize.
- Provider refresh has a different lock boundary: it retains its connection row lock for the bounded token
  exchange and persists rotating refresh credentials before publishing cache entries. Dependency reads must
  use the scoped transaction capability, not recursively acquire a pool connection. Scope closure must cancel
  and drain before ordinary transaction SQL resumes; detached/late dials must not use a closed transaction or
  fall back to the pool. Checked policy failures must refuse public as well as private destinations.
- Access-request stewardship is not general admin or MCP access. Decisions recheck active requester/reviewer,
  current administered-team authority and gateway opt-in under transaction locks, never synthetic admin actors.
  Temporary-grant transport checks wrap approval consumption and recheck authoritative database time after
  commit; clock-read failure refuses dispatch. No pool connection/lock survives into network I/O. Keep
  spent-authorization/no-replay semantics even when a post-commit deadline check prevents the actual send.
- Preserve live linked-provider endpoint matching, requester/reviewer separation, private previews/notices,
  and least-privilege runtime grants. Historical schema compatibility does not imply old-image enforcement;
  drain pre-v0.5 images before enabling approval rules, and pre-v0.6 serving/background-worker replicas
  before enabling access requests or expiring grants. New server protection also requires draining older
  serving/background-worker replicas before relying on it; expanded-schema compatibility is not enforcement.
  Use the new rotation utility for new ciphertext fields. Failover permits only independently entered
  none/static credentials with no provider/TLS state: primary plus at most two ordered extras, three total
  iterations and fresh actual-URL identity/definition parity. Governed/NoReplay is primary-only even after
  failed negotiation; never restore/transfer a spent receipt. New-origin values must be entered again.
  Drain pre-v0.8 serving/workers before relying on endpoint policy, review, health or new-column rotation.

## Code and checks

- Approvals: `internal/approvals/`, `internal/mcpgw/approvals.go`, `internal/httpapi/approvals.go`,
  `web/src/pages/approvals/`; design: [tool-approvals.md](tool-approvals.md).
- Refresh patch: `internal/store/endpoint_reads.go`, `internal/providers/endpoint.go`, refresh callers in
  `runtime.go`, `narrow.go`, `service_runtime.go`; `internal/registry/networks.go` and upstream checked policy.
  `internal/httpapi/service_connections_pool_integration_test.go` proves one-connection/two-handler success
  and fail-closed negative controls. Scope-lifetime, SQL-error, linked-client and cache-isolation tests accompany it.
- Access requests/expiry: `internal/gateways/access_request*.go`, `grant_insert.go`, `grant_expiry.go`,
  `internal/mcpgw/grant_expiry.go`, `internal/httpapi/access_requests.go`, `internal/notify/access_requests.go`,
  `web/src/pages/access-requests/`. Keep the response-schema regression and duplicate-email identity test.
- Upstream protection: `internal/limits/server.go`, `internal/upstream/{protection,retry,forward}.go`,
  `internal/mcpgw/server_protection.go` and the server settings UI. Keep fresh per-attempt authority/quota,
  admission before spending/SSE, original timeout, NoReplay/continuation/progress exclusions, bounded state
  and before-dispatch/prior-attempt recording proofs. Read503 is not evidence of no remote effect.
- Follow all contribution gates. Use `GOFLAGS='-p=2'`, mandatory PostgreSQL (`OMP_TEST_REQUIRE_DB=1`) and
  actual legacy/split logins (`OMP_TEST_SPLIT_ROLES=0` and `1`) on an owned disposable PostgreSQL container.
  `make test-ci` keeps every test and the race detector with a bounded 20-minute per-package timeout.
  Generation, lint/build, web checks, Kubernetes validation and actionlint are required as applicable.
- The previous machine hit missing files in its shared Go compiler cache; an owned isolated `GOCACHE` was
  used for verification. Do not disable vet/race checks or clean another session's cache to work around that.

## What remains separate

There are 26 open issues after #32/#33/#35/#43/#52 and the four scanning follow-ups: 18 development and
eight real-world verification issues.
#13–#20 still require actual independent review/client/provider/channel/pilot evidence. Fake OAuth/MCP fixtures
and agent reviews do not close those. Broader load, restore/ingress/OIDC deployment validation, wall-clock
refresh/expiry and whole-product accessibility acceptance remain separate; no production deployment is implied.
