# Upstream protection (#33)

Status: **quota/concurrency/read-retry/breaker shipped/verified v0.7.0; separate failover shipped/verified v0.8.0 and #33 closed**. Decision84. This is the next ordered boundary after verified
v0.6.0/#32. The issue was drafted against v0.2.1: its migration29 and credential-mode assumptions are not
current instructions. Quotas, concurrency, read retries and circuit breaking ship before failover. **#33
stayed open until the separate failover acceptance criteria passed in v0.8.0; see [failover](upstream-failover.md).**

## Policy and defaults

- `server_per_minute` joins the existing platform defaults/ceilings and team overrides. It counts forwarded
  tool/prompt/resource attempts to one registered server across gateways, users, credentials and replicas,
  using the shared PostgreSQL rate store (`v:<server UUID>`). Each automatic retry counts again. Discovery,
  health and transport negotiation are not separately charged as forwarded operations. Existing person,
  credential, service-account and gateway quotas still count the inbound logical request once.
- A server's nullable `rateLimitPerMinute` overrides its team's setting, then the platform default; the
  platform ceiling always caps the effective value. The initial default/ceiling are unlimited, preserving
  existing installations until explicitly configured. Values are 1–1,000,000 or null (inherit). Lowering a
  ceiling caps existing values without rewriting them.
- Nullable `maxConcurrent` is 1–10,000 active forwarded operations **per server and replica**, otherwise
  unlimited. There is no queue. A lease covers negotiation, every retry, streamed/body processing and SDK
  cleanup; all exits release it. The fleet cap is approximately the configured value times replicas, not
  a cross-replica lease guarantee.
- The server team's owners/admins set these operational values using the existing revision-checked server
  mutation; ordinary editors/publisher tokens do not gain an operational-limits capability. Platform staff
  retain their existing read-only access to other teams' server settings. Limit changes are audited but do
  not widen credentials, alter definitions or require catalog re-review by themselves.
- Circuit breaking is per registered server and replica: five consecutive failed forwarded operations,
  30 seconds open, then one half-open operation. A recovered upstream answer closes it; local admission,
  policy/credential failures and caller cancellation do not manufacture upstream failures. State is bounded;
  active leases cannot be evicted or reset to bypass concurrency. Circuit metrics use bounded server labels.

Migration **`00046`** is expand-only: nullable columns on `mcp_servers`, no destructive rewrite, no endpoint
rows yet. The actual immutable v0.6.0 image passed schema46 doctor/readiness and a journaled metadata write
preserving the new settings under a genuinely authenticated restricted runtime. It cannot enforce new
quotas/caps or retry/breaker policy.
Drain all older serving/background-worker replicas before relying on enforcement. Schema compatibility is
not policy compatibility. No existing instance/database/key is implicitly migrated, reset or regenerated for development.

## Admission and authorization ordering

Resolve/authenticate the gateway, validate the current offer and merged arguments, credential scopes and
origin-bound target, and plan approval before forwarding. A pending/denied approval does not contact the
upstream or occupy a concurrency lease. All new local quota/concurrency/breaker admission occurs **before**
the tools/call hook can spend approval. No PostgreSQL connection, transaction or authority lock survives
into network I/O. A concurrency lease is an in-memory resource reservation, not an authority lock.

Each forwarding attempt checks the existing read-only authority epoch/deadline contract before networking;
errors or changed authority refuse the attempt rather than using a stale decision. The caller credential
and earliest matching temporary-grant deadlines cap this check. Existing transport-level gateway-expiry
checks remain outermost, including their authoritative database-clock check after approval consumption and
commit. Address/dial policy and origin matching run as before for every HTTP exchange. Quota/store failure
is a local refusal, never permission to bypass a configured limit.

Read retries do not turn a spent approval into reusable authority. `Target.NoReplay`, its atomic one-attempt
guard across SDK/era recovery, and committed-spend semantics remain unchanged. A later local failure never
restores a consumed authorization. The admission/error path must retain private approval error handling and
must not misclassify local denial as an upstream credential rejection or erase provider consent.

## Automatic read retries

Only `tools/call` with the owner's stored class **`read`**, `prompts/get` and `resources/read` can opt in.
Annotations are not authority. Write, destructive and unclassified tools never opt in. **Governed/NoReplay
calls never automatically retry**, including a governed read. Upstream elicitation continuations
(`inputResponses`/`requestState`) are single-attempt too; do not replay an interaction's state.

At most two retries fit inside the **original** server timeout and caller deadline; a retry cannot renew
either budget. Delays are cancellation-aware and jittered. A valid short `Retry-After` is honored up to two
seconds; a longer value stops automatic retry. Missing/malformed `Retry-After` does not authorize a 429
retry. Without such a header, eligible 502/503/504 or pre-request dial/TLS failures use bounded short backoff.

There is no retry after progress or a streamed response starts, partial/malformed/oversized results, local
policy/admission/authority failures, caller cancellation, 401/403, an ordinary RPC/tool business error or an
ambiguous transport failure after sending. The existing bounded OAuth refresh path remains separate.
A read-class 503 is **not proof that nothing executed**: repeatability relies on the trusted classification,
not on an exactly-once claim about the remote server. A misclassified read can still have side effects.

## Outcomes, privacy and observability

- Server quota and concurrency refusal: HTTP429 with `Retry-After`, existing era-appropriate rate-limit
  code, `rate_limited` outcome and class `server_per_minute` or `server_busy`. Do not expose other callers'
  counts or remaining server-wide capacity.
- Open circuit: existing `-32010` upstream failure with `data.reason: circuit_open`, `upstream_error`
  outcome and `circuit_open` class, without contacting the server.
- One call record/capture per logical inbound request; retries are not duplicate user calls. A later local
  admission/authority refusal must not erase earlier identity-dispatch metadata. Progress and cancellation
  retain their existing semantics. No raw arguments, tokens, sensitive headers, endpoint
  credentials or private request/approval content enter new labels, audit details or errors.
- `omp_server_circuit_state` is bounded like existing server metrics; no per-person/credential labels.
  State and series must retire safely when objects disappear. Rate-limit metrics retain bounded key names.

## Failover is a separate change

No multiple endpoints or failover was part of the v0.7.0 stage. The separate verified [v0.8.0
stage](upstream-failover.md) accounts for **all current modes**, not just the old issue's OAuth/static-header pair: multipart header/bearer/basic/query credentials,
each person's own secret, personal/shared/linked provider grants, upstream OAuth, client credentials and
mTLS/private CAs. Unsupported modes must refuse extra endpoints explicitly, never fall back to forwarding
an existing credential elsewhere. A newly trusted origin requires credential re-entry and review; the
identity audience is the actual URL, the era cache stays origin-aware and every endpoint passes address
checks. Preserve MCP-only authentication; no retired external issuer/person impersonation is restored.

## Required verification

- Distributed quota independence for two servers/gateways/handlers and correct effective overrides/ceilings;
  concurrent changes, out-of-range/role/token/foreign-team/stale-revision negative controls and audits.
- Fail-fast per-replica cap under races, lease release on cancellation, errors, streaming, closed deadline
  guards and all retries; no queue or recursive runtime-pool acquisition.
- Fake-clock breaker closed/open/half-open transitions, one probe, neutral local refusals, cancellation,
  bounded state and metrics retirement; no protected authority locks during network I/O.
- A read succeeds after eligible 503; writes, unclassified/annotation-only, governed reads and continuations
  do not retry. Stop at progress/partial results, long/malformed delay, elapsed budget, stale authority,
  missing policy/clock and revoked/narrowed credentials. Exercise modern and legacy protocol recovery.
- Preserve all existing approval/no-replay, grant-expiry, scoped provider-refresh, SSRF, origin/identity and
  role-split regressions. Authz matrices and generated API contracts cover the added fields.
- Complete mandatory PostgreSQL normal/race suites in actual legacy and authenticated split modes with
  `GOFLAGS='-p=2'`, all web/deployment/advisory gates, actual previous-image schema compatibility and
  published-artifact checks before release. Fake upstreams do not close real-client/provider/pilot issues.

Current publication/acceptance evidence belongs in [status](status.md). v1.0.0 remains the owner's decision.
