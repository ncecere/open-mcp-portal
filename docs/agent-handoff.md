# Agent handoff: resume after v0.5.1

The owner asked to finish the current release, merge/push everything to `main`, then **pause** for a machine
transfer. Do not start #32 until the owner resumes development. [Status](status.md) is the source of truth
for release SHAs, image digests, CI evidence and any remaining blocker.

## Start here

1. Fetch `origin/main` and tags; inspect `git status`, the latest main CI and the published release. Work from
   `main`, not an old approval or refresh-fix branch. No uncommitted patch is needed for the handoff.
2. Read `AGENTS.md`, [CONTRIBUTING.md](../CONTRIBUTING.md), [status](status.md) and
   [implementation order](implementation-order.md). The next feature is **#32 gateway access requests**;
   #33 upstream protection follows. Neither has been implemented in this batch.
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

See the release sections in [status](status.md) for actual publication/verification rather than interpreting
this list or a local version string as evidence. Release tags are immutable. Main may be ahead of the tag
only to record publication evidence, the verified example image digest and handoff documentation.

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
- Preserve live linked-provider endpoint matching, requester/reviewer separation, private previews/notices,
  and least-privilege runtime grants. Historical schema compatibility does not imply old-image enforcement;
  drain pre-v0.5 images before enabling approval rules. Use the new rotation utility for new ciphertext fields.

## Code and checks

- Approvals: `internal/approvals/`, `internal/mcpgw/approvals.go`, `internal/httpapi/approvals.go`,
  `web/src/pages/approvals/`; design: [tool-approvals.md](tool-approvals.md).
- Refresh patch: `internal/store/endpoint_reads.go`, `internal/providers/endpoint.go`, refresh callers in
  `runtime.go`, `narrow.go`, `service_runtime.go`; `internal/registry/networks.go` and upstream checked policy.
  `internal/httpapi/service_connections_pool_integration_test.go` proves one-connection/two-handler success
  and fail-closed negative controls. Scope-lifetime, SQL-error, linked-client and cache-isolation tests accompany it.
- Follow all contribution gates. Use `GOFLAGS='-p=2'`, mandatory PostgreSQL (`OMP_TEST_REQUIRE_DB=1`) and
  actual legacy/split logins (`OMP_TEST_SPLIT_ROLES=0` and `1`) on an owned disposable PostgreSQL container.
  `make test-ci` keeps every test and the race detector with a bounded 20-minute per-package timeout.
  Generation, lint/build, web checks, Kubernetes validation and actionlint are required as applicable.
- The previous machine hit missing files in its shared Go compiler cache; an owned isolated `GOCACHE` was
  used for verification. Do not disable vet/race checks or clean another session's cache to work around that.

## What remains separate

There are 27 open issues after #31: 19 feature/operations/design and eight real-world verification issues.
#13–#20 still require actual independent review/client/provider/channel/pilot evidence. Fake OAuth/MCP fixtures
and agent reviews do not close those. Broader load, restore/ingress/OIDC deployment validation, wall-clock
refresh/expiry and whole-product accessibility acceptance remain separate; no production deployment is implied.
