# Database roles (#44)

## Design and trust boundary

Open MCP Portal supports an optional migration owner and a separate runtime login.
`DATABASE_MIGRATE_URL` is a secret (environment, `_FILE`, or flat YAML); it falls
back to `DATABASE_URL`. `DB_RUNTIME_ROLE` defaults to empty (legacy single-owner
operation); `DB_REQUIRE_SPLIT_ROLES` defaults to false. No role or password is
created by the application. Role names are validated as existing PostgreSQL
identifiers, never SQL fragments.

`migrate`, and `serve` with `MIGRATE_ON_START`, open the migration pool first, run
goose and reconcile grants under the same advisory lock, then close that pool.
Only serving opens `DATABASE_URL`. Migration does not need runtime connectivity.
Doctor and key rotation use only `DATABASE_URL`, never the owner connection.
The hardened Kubernetes init container receives the owner Secret separately;
the serving container has no owner URL or shared secret volume and does not migrate.

Migration 00032 adds two static-SQL, owner-owned SECURITY DEFINER functions:
`public.omp_purge_audit_log(integer,integer)` and
`public.omp_purge_mcp_calls(timestamptz,integer,integer)`. Their search path is
`pg_catalog, pg_temp`; all application relations are explicitly public-qualified.
Migration 00033 additionally pins both functions' `TimeZone` to `UTC`, so caller
session settings (including POSIX zones with extreme DST shifts) cannot shorten
the elapsed 30-day audit or 1-day call floor. Both function-local settings restore
the caller's settings on return or error; the migration preserves owners and ACLs.
PUBLIC EXECUTE is revoked in the migration transaction. Functions and protected
tables must have the same owner: running a superuser migration over somebody
else's tables must fail rather than silently create a different definer owner.

Audit retention has a 30-day floor; call metadata has the existing **1-day**
floor, not 30 days. Effective call retention is the shortest of existing gateway
and server teams' effective periods (absent override inherits platform). With
neither team the platform period applies; a lone team's 365-day override is not
capped at the 90-day platform period. Clamp only after choosing that period.
NULL/invalid batch sizes are rejected; batches are bounded at 100000. Counts are
bigint and count call rows, not cascading payloads. Purge flags are restored on
success and error. Calls must be older than both retention and the smaller of
the caller watermark and persisted `rolled_up_to` truncated to its UTC hour,
minus one hour. Missing/uninitialized state deletes nothing.

Append-only triggers remain SECURITY INVOKER. UPDATE always fails. DELETE needs
an accepted `omp.*_purge` or legacy `omg.*_purge` flag **and** effective
`current_user` equal to the table owner found through `pg_class` and `TG_RELID`.
`current_user <> session_user` is not a safe test (SET ROLE bypasses it and the
single-owner definer has equal identities). Owners and superusers remain trusted.

The grants helper runs after goose even when no migration changed, in a
transaction inside the migration advisory lock. It removes stale direct grants
and grant options, then gives ordinary tables SELECT/INSERT/UPDATE/DELETE,
protected tables SELECT/INSERT, goose versions SELECT, sequences USAGE, schema
USAGE and the exact two function signatures EXECUTE. Never TRUNCATE, TRIGGER,
CREATE or ALL grants. PostgreSQL identifiers are quoted with pgx.Identifier.

A shared catalog inspector is used for migration preflight, doctor and required
split-role serving. It checks session and effective identities, role attributes
and memberships (including NOINHERIT/SET ROLE paths), ownership and effective
privileges including column privileges, PUBLIC and inherited grants and grant
options. It also requires operational reads/inserts, goose SELECT and function
EXECUTE. Unsafe PUBLIC/inherited privileges cannot be repaired by revoking a
direct grant: split-role migration rejects them. Legacy single-owner installs
warn; `DB_REQUIRE_SPLIT_ROLES=true` refuses unsafe serving.

This boundary protects recent audit and call history against SQL access using a
runtime credential, including setting purge flags. It is not tamper-proof
history: runtime can edit retention settings and rollup state, delete ordinary
tables and insert invented audit/call rows. The guaranteed boundary is the age
floor, not the integrity of rollup history or configurable longer retention.
Trusted owners/superusers can change the functions/triggers or remove records.
Use external immutable log storage for a stronger guarantee.

## Upgrade and rollback

Migrate as the existing schema owner first, then switch serving credentials.
The schema remains compatible with the previous owner-authenticated binary,
including its legacy flag-based retention. A previous binary's retention is
**not compatible with restricted runtime credentials**: restore owner credentials
for rollback or accept retention failures. New code fails closed if the purge
functions are missing; there is no direct-DELETE fallback.

See [deploy.md](deploy.md#database-roles) for PostgreSQL/CloudNativePG setup and
an existing-install runbook. Never grant runtime membership in an owner role,
even NOINHERIT membership: SET ROLE would cross the boundary.

## Verification

Use a new disposable PostgreSQL 17 container, bound to a random loopback port,
with isolated storage. The integration test split mode creates unique scratch
databases and owner/runtime logins and genuinely authenticates as runtime.
Privileged migration/schema fixtures explicitly request the owner pool. CI runs the
whole race-enabled Go suite in both legacy and authenticated split modes; test raw SQL denials,
flags, quoting, repeated/concurrent reconciliation, PUBLIC/inherited privileges,
search-path shadowing, age floors, team combinations, watermark and cascades.
Timezone regressions probe a bounded set of date-relative POSIX rules to prove
that the caller's zone actually shortens calendar subtraction before testing
purges. Under that hostile zone, 29.5-day audit rows and already-rolled-up
2-hour call rows survive while truly old rows purge; UTC function configuration
and caller timezone/purge-flag restoration are checked on success and error.
The SELECT-only probe also covers leap-day and year-wrap dates.
No live cluster or development database is needed or changed.

For a local run (replace the disposable password; do not reuse a development
container or server), start a uniquely named foreground container in a separate
terminal:

```sh
docker run --rm --name omp-roles-<unique> -e POSTGRES_PASSWORD=<disposable> \
  -p 127.0.0.1::5432 --tmpfs /var/lib/postgresql/data postgres:17
```

Read its assigned port with `docker port omp-roles-<unique> 5432`, then:

```sh
export OMP_TEST_DATABASE_URL='postgres://postgres:<disposable>@127.0.0.1:<port>/postgres?sslmode=disable'
export OMP_TEST_REQUIRE_DB=1
OMP_TEST_SPLIT_ROLES=0 go test -race -count=1 ./...
OMP_TEST_SPLIT_ROLES=1 go test -race -count=1 ./...
```

The bootstrap test login must be able to create/drop scratch databases and roles;
no existing role is altered by split fixtures. `testutil.OwnerPool` is explicit
fixture-only access for DDL/migration/instrumentation tests, never a replacement
for the authenticated runtime pool in service/API tests. `testutil.Regrant`
reconciles after a fixture recreates tables. Stop only that named disposable
container after testing; `--rm` and tmpfs remove its isolated storage.
