# Audit streaming: ordering, sealing, delivery and retention (#38, decision 93)

Status: **design, revised 2026-11-05 after an independent adversarial review (section 10). Nothing in this document
is built yet.** It turns the #38 proposal and the unwired [audit evidence foundation](audit-streaming-foundation.md)
into an ordered build plan, and settles the gate the foundation left open: *a proven ordering, gap and retention
design*. The owner delegated the defaults below when resuming development (2026-11-05) and may override any of them.

## 1. Goal, non-goals and trust scope

Goal (threat model BR-10, H-10): every committed `audit_log` row leaves the host, in a gapless numbered order, with
a hash chain a receiver can verify without trusting the database. Retention never purges a row that was not
sealed and, where a consumer is required, not acknowledged. Audit retention never falls below a floor the
operator sets at deployment, or below the retention of the call records it explains.

Not in scope: streaming `mcp_calls` continuously, payload export, per-team sinks, WORM storage, changing the
existing append-only triggers, and legal holds (#39 builds on this).

**Trust scope.** The database-level guarantees below (a forced `txid`, protected stream state, the retention floor)
hold in **split-role mode** (#44, `DB_RUNTIME_ROLE` set). In legacy single-owner mode the serving connection *is*
the owner and can alter its own protections; the stream still works, but those guarantees reduce to "the
application does not do this". Even in split-role mode, a compromised runtime can insert invented audit rows (they
are sealed like real ones) and, once checkpoints exist, sign false checkpoints *from then on*. The defence is that
off-host copies and earlier checkpoints pin history (section 7).

## 2. Ordering: the xid8 watermark (proven within one xid history)

`audit_log.id` is allocated at insert, not at commit, so a reader that tails by `id` skips a row whose transaction
commits after a later id became visible. The portal writes audit entries inside the audited transaction
(`internal/audit`), and those transactions commit in whatever order their locks and network waits allow. This is
the normal case, not an edge case.

**Rule.** Each row carries the top-level transaction id `txid xid8`. The fast path reads, in **one statement** (one
snapshot), only rows with `txid < pg_snapshot_xmin(pg_current_snapshot())`, in `(txid, id)` order, after its
cursor:

```sql
WITH wm AS (SELECT pg_snapshot_xmin(pg_current_snapshot()) AS x)
SELECT a.id FROM audit_log a
WHERE a.txid < (SELECT x FROM wm)
  AND (a.txid, a.id) > ($cursor_txid, $cursor_id)
ORDER BY a.txid, a.id
LIMIT $batch
```

**Why it is complete.** Every transaction with an xid below the snapshot's `xmin` has finished (committed or
aborted), and every xid assigned later is at or above the next xid, which is above `xmin`. So once the watermark
passes an xid, no new row with a smaller xid can appear, and everything between the previous and the new
watermark is final. `pg_current_snapshot()` is the active statement snapshot (checked in the PostgreSQL 17 source
and by experiment under READ COMMITTED and REPEATABLE READ). `pg_current_xact_id()` returns the top-level xid inside
savepoints; xid8 is epoch-extended and does not wrap.

**What it orders.** This gives a deterministic, stable **sealing order**, not commit order: two transactions can
take xids in one order and commit in the other. The watermark waits for both, so nothing is skipped, but the
chain does not claim to show which committed first. Receivers use `seq` order, which is the sealing order.

**Its precondition is one uninterrupted xid history.** A logical dump/restore into another cluster, or a
logical-replication cutover, breaks it (section 4.3). Within that precondition, the fast path never membership-tests
by `id`, so prefetched or caller-supplied ids and restored sequence state cannot strand a row.

**Evidence** ([proof program](proofs/audit-watermark/main.go), PostgreSQL 17, 2026-11-05: run three times by the
main thread and once more by the reviewer):

| Check | Result |
| --- | --- |
| Negative control: tail by `id` while an earlier id is uncommitted | The earlier row is **lost** |
| Same scenario under the watermark | Held back, then both rows sealed in `(txid, id)` order |
| Stress: 24 writers × 400 transactions, read-before-write (late xid), savepoint rollbacks, 10% aborts, random commit delays, sealer running throughout | Every run: 20,006 of 20,006 committed rows sealed; 0 missing, 0 phantom, 0 duplicates. Seal order differed from id order ~5,850 times per run |
| `ADD COLUMN txid xid8` on 200,000 rows | 1 ms, no table rewrite, old rows `NULL` |
| Partial index `(txid, id) WHERE txid IS NOT NULL`, built `CONCURRENTLY` | 47 ms; the id-only fast-path query is an index-only scan (fetching full rows is not) |
| Writing transaction open in **another database** on the same cluster | Holds the watermark (xids are cluster-wide) |
| Read-only transaction without an xid | Does not hold it |

This program is scratch evidence, not a test of product code. Slice 1 ports it as a retained integration test
against the real sealer, in both database-role modes, including the negative control.

**Lag, not loss.** A long writing transaction anywhere in the cluster (including another database or a prepared
transaction) delays sealing until it ends. It shows as `omp_audit_stream_lag_seconds` and an alert; it never skips
a row. (Prepared transactions were reasoned from source, not executed: the test server has
`max_prepared_transactions=0`.)

## 3. Schema (slice 1; migrations `00058` transactional, `00059` non-transactional)

Changes to `public` are limited to what the previous release tolerates. Its grant reconciler gives every
unfamiliar `public` table full DML to the runtime role, and its role inspector *requires* that DML. So protected
state cannot live in `public`. It cannot live in `omp_private` either, whose reconciler refuses unexpected
relations. New protected state goes in a **new schema `omp_audit`**, owned by the migration role, which the
previous release's reconciler and inspector do not touch.

In `public`:

1. `audit_log.txid xid8` (nullable, no default), a `BEFORE INSERT` trigger that **always** sets
   `NEW.txid := pg_current_xact_id()` (the trigger function lives in `omp_audit`), and
   `CHECK (txid IS NOT NULL) NOT VALID`, which applies to new rows only. A column default would let a caller supply
   `NULL` or a forged old xid and hide a row. The reviewer confirmed that ordinary `INSERT` and `COPY` are restamped,
   that an unprivileged role cannot set `session_replication_role`, and that privileged replica mode still fails
   the `NULL` check. The new role inspector also rejects runtime `SET` privileges on that parameter.
2. `omp_purge_audit_log(days, batch)` is replaced in place: same signature, owner, ACL, `SECURITY DEFINER`, fixed
   `search_path` **and `TimeZone = 'UTC'`** (`CREATE OR REPLACE` drops settings it does not restate; dropping
   migration 00033's setting would reopen the caller-timezone bypass). Section 6 gives the new body.

In `omp_audit` (runtime role: `USAGE` on the schema, `SELECT` on the tables, `EXECUTE` on the listed functions,
nothing else; managed by new reconciler and inspector code that the previous release ignores):

3. `state` (one row): `stream_id uuid` (random per install), `incarnation` (`system_identifier`, `timeline_id`),
   `epoch int`, `status` (`running`, `halted_incarnation`, `rebasing`), `cursor_txid xid8`, `cursor_id bigint`,
   `last_seq bigint`, `last_chain_hash bytea`, `sweep_at`.
4. `chain`: `seq bigint PRIMARY KEY`, `kind` (`entry`, `epoch_start`, `checkpoint`), `audit_id bigint UNIQUE`
   (null for non-entry kinds), `epoch`, `flags` (`late`), `occurred_at`, `summary_hash`, `entry_hash`, `chain_hash`,
   `sealed_at`. Append-only by trigger. No foreign key: retention removes the audit row first and keeps the chain
   row as the anchor.
5. `consumers`: `name`, `required bool`, `acked_seq`, `acked_at`, `created_by`. Pull consumers in slice 1; push
   sinks add their sealed configuration in slice 2.
6. `retention_floor` (one row, `min_days`). The migrate command writes `AUDIT_MIN_RETENTION_DAYS` from the
   operator's environment (default 30, today's hard minimum, so no behaviour change). Neither platform admins nor
   the runtime role can change it.
7. Definer functions, the only way the runtime changes stream state: `seal_batch(...)` (enforces
   `seq = last_seq + 1…`, that each `audit_id` exists and is not already chained, cursor monotonicity and the
   status), `ack(consumer, seq)` (monotonic, at most `last_seq`), `register_consumer`/`set_required` (audited).
   `rebase` is a migration-role command, not a runtime function.
8. `00059` (`NO TRANSACTION`): `CREATE INDEX CONCURRENTLY IF NOT EXISTS` on `(txid, id) WHERE txid IS NOT NULL`,
   dropping and recreating an invalid index left by an interrupted run (the safe-to-rerun pattern of `00020`).
   Acceptance runs the previous image between `00058` and `00059` as well as after both.

Pre-existing history is exactly the rows with `txid IS NULL`. The `NOT VALID` check stops new ones, so that set is
final once the migration commits.

## 4. Sealing

### 4.1 Normal operation

The leader (advisory lock `omp.auditstream`, `store.TryAdvisoryLockText`) runs batches. Each batch is one
transaction that calls `seal_batch` with records hashed in Go. `seal_batch` locks the state row, so two sealers can
never both extend the chain even if leader election fails. A `seq` comes from the state row, never from a
PostgreSQL sequence, so a rolled-back batch leaves no gap (the reviewer confirmed this by experiment). No network
I/O happens inside the transaction. Order within a batch:

1. **History backlog:** unsealed rows with `txid IS NULL`, in `id` order, until none remain.
2. **Fast path:** section 2's query.

### 4.2 Safety-net sweep

A sweep runs daily and after every rebase or epoch change. It is an anti-join of `audit_log` against `chain` over
rows that should already be sealed: `txid IS NULL`, or `(txid, id) <= cursor` with `txid` below the watermark.
It seals anything it finds with the `late` flag and increments `omp_audit_stream_late_total`, which should always
be zero; any hit alerts. Correctness does not rest on the sweep, but it bounds the damage of an unforeseen bypass
to "late and flagged" rather than "never".

### 4.3 Incarnation, epochs and rebase

The state records the cluster incarnation `(system_identifier, timeline_id)`, which any login role can read through
`pg_control_system()` and `pg_control_checkpoint()` (checked on the test server). Each batch compares it to the live
values.

- **`system_identifier` changed** (a logical dump/restore into a new cluster, or a logical-replication cutover,
  where the apply worker also bypasses the stamping trigger and keeps the publisher's xids). The sealer **halts**
  (`status = halted_incarnation`, metric and alert). It does not try to infer what happened from xids: the reviewer
  showed that `snapshot xmin < cursor_txid` misses a regression once unrelated activity moves xmin past the old
  cursor. The runbook requires `open-mcp-portal audit-stream rebase` (migration role) after a logical restore or
  cutover, *before serving writes*. Audit rows written while halted are not lost; rebase seals them.
- **`timeline_id` changed** (physical failover, PITR). xids continue, so the fast path stays correct, but the chain
  may have rewound: records sealed on the old timeline may be gone. The sealer starts a new epoch automatically and
  alerts. Receivers handle any overlap with the protocol in section 5.3.
- **`rebase`:** (a) take `LOCK audit_log IN SHARE MODE` in transaction A, which waits for in-flight writers;
  (b) open REPEATABLE READ transaction B and take its snapshot while A holds the lock, so B sees exactly the
  committed pre-rebase rows; (c) in A, record the new incarnation, `epoch + 1`, `status = rebasing`,
  `F = pg_current_xact_id()`, cursor `(F, 0)`, then commit, so writers resume after a lock held for milliseconds;
  (d) B seals every row in its snapshot not yet chained, in `id` order, whatever its (possibly foreign) `txid`;
  (e) set `status = running`; (f) once the watermark passes `F`, sweep rows with `txid < F` once, to catch writers
  that already held an xid below `F` and were blocked by the lock.

Every epoch begins with an `epoch_start` chain record (section 4.4) whose summary names the previous epoch, the last
`seq` the database still holds, the reason (`rebase`, `timeline`) and both incarnations.

### 4.4 Record version 2

The foundation's version-1 record (59 bytes: IDs and two enums only) cannot carry what a SIEM needs. Version 2 keeps
its discipline (fixed binary layout, domain separation, no JSON in the chain, explicit `seq`) and authenticates
**both** the summary a receiver acts on and the full row:

```
summary_hash = SHA256("OMP-AUDIT-SUMMARY\0V1\0" || canonical_summary_bytes)
entry_hash   = SHA256("OMP-AUDIT-ENTRY\0V1\0"   || canonical_entry_bytes)     -- zero for non-entry kinds
record_v2    = version u8 (=2) || kind u8 || flags u8 || stream_id 16 || epoch u32 || seq u64
               || audit_id u64 || occurred_at_unix_micros i64 || summary_hash 32 || entry_hash 32   -- 111 bytes
chain_hash   = SHA256("OMP-AUDIT-EVIDENCE\0CHAIN\0V2\0" || previous_chain_hash 32 || record_v2)
genesis predecessor = SHA256("OMP-AUDIT-EVIDENCE\0GENESIS\0V2\0" || stream_id)
```

A summary receiver can now recompute `summary_hash` from what it was given. The reviewer showed that without this,
a changed action or actor kept a valid linkage. A full receiver also recomputes `entry_hash`.

**Canonical encodings are a normative, versioned specification written with slice 1**, with golden vectors and
the Python reference verifier extended to version 2. The specification must list every field of each profile
(including `txid` and `actor_token_kind`, missing from the first draft) and define each encoding exactly:

- the presence byte for SQL `NULL` versus an empty string, and SQL `NULL` versus JSON `null`;
- duplicate jsonb keys (PostgreSQL keeps the last), object key order (sorted by UTF-8 bytes) and string escaping
  (one fixed escape set, no optional `\u` forms);
- numbers as PostgreSQL's numeric text tokens. These are **never** decoded through float64, which loses
  `9007199254740993`. Scale is preserved as stored (`1.0` and `1.00` are equal as jsonb but differ in text).

Adding a column to `audit_log` later means a new canonical version, never a silent change to version 1.

**Limits.** The foundation's 1,024-byte line cap and integer/hex-only CSV policy were made for the 59-byte record and
do not fit version 2: legitimate snapshots exceed 2 KiB, and an action such as `team.create` is not hex. Version 2
uses a 16 MiB per-line reader limit with a fixed-size buffer. A row whose full form exceeds it is still sealed and
delivered in summary form with an `oversized` flag, and its full form stays retrievable by id while retained.
Evidence is never truncated or dropped. CSV is an export view with spreadsheet-safe quoting (a leading `'` before
formula characters), never a verification input.

## 5. Delivery, consumers and recovery

### 5.1 Pull (slice 1)

`GET /v1/admin/audit/stream?after_seq=&limit=&profile=summary|full` streams sealed records in `seq` order as NDJSON,
joined to their audit rows. Platform admins and auditors with a browser session, or an automation token with
`platform:read` (which already grants full audit reads). A collector (Vector, Fluent Bit, a SIEM's HTTP input)
polls it. No outbound network, no sealed URLs, no SSRF surface. A request below the earliest seq whose audit row is
still retained gets `410 range_expired` with the earliest available `seq`; it never silently skips or downgrades
the profile. `POST /v1/admin/audit/stream/ack` records a registered consumer's acknowledged `seq`.
`GET /v1/admin/audit/verify?from=&to=` recomputes the chain over a range and reports the first bad `seq`.

### 5.2 Profiles

The **summary** profile (default) carries time, action, actor kind and ids, team, target type and id, request id
and automation-token id, all covered by `summary_hash`. The **full** profile adds `before_state`, `after_state`,
`metadata`, `client_ip`, token name and kind and `txid`, covered by `entry_hash`. Full is opt-in per consumer,
because snapshots can contain emails and other personal data. Snapshots are already secret-redacted at write
time. Summary is a smaller projection, not least privilege: its stable ids are still personal, linkable data.

### 5.3 Receiver protocol and tip

`GET /v1/admin/audit/stream/tip` returns `stream_id`, current epoch, `last_seq`, `last_chain_hash`, the earliest
available `seq`, and the epoch history (each epoch's first `seq`, predecessor hash and reason). From slice 2 the tip
is signed. A conforming receiver:

- keeps **stream-wide** state across epochs: `(stream_id, seq) → chain_hash`, not per-epoch deduplication;
- accepts an `epoch_start` record whose predecessor is the hash it holds for `seq - 1` (a clean continuation);
- treats any record at a `seq` it already holds with a different hash as a **fork**: it alerts and keeps both
  copies. An epoch change never legitimises an overlap; only an explicit operator acknowledgement at the receiver
  does;
- polls the tip as well as the stream. A database restored to seq 500 when the receiver holds 1,000 answers
  `after_seq=1000` with nothing; the tip's `last_seq < held seq` is the signal, and the receiver alerts.

`rebase --resume-after-seq=N` lets the operator restart numbering above the highest `seq` any receiver holds, so
that after a known rewind the new epoch does not reuse sequence numbers at all.

### 5.4 Push sinks and checkpoints (slices 2 and 3)

Webhook (reusing `notify`'s signature header and client), then syslog over TLS (RFC 5424, octet counting) and OTLP
logs over HTTP/JSON (hand-rolled; no new dependency). Sink URL and secret are sealed columns joined to
`keyrotation.Columns`, with a separate `AUDIT_STREAM_ALLOWED_NETWORKS` (public https only by default). One sender
per sink, at least once, strictly in `seq` order; its cursor advances only after acknowledgement. A stalled sink
never blocks audit writes; it shows as lag and a failure counter, and platform admins are notified after 3
consecutive failures.

Every 10,000 records or 15 minutes, the sealer writes a `checkpoint` chain record signed with a **dedicated**
Ed25519 audit-checkpoint key, never the identity key that signs upstream JWTs. The private key is sealed; public
keys are at `/.well-known/omp-audit-keys.json`.

## 6. Retention interlock

The replaced `omp_purge_audit_log(days, batch)` (section 3, item 2) deletes a row only when:

1. it is older than `greatest(days, retention_floor.min_days, D_calls)`, where `D_calls` is the longest effective
   call-metadata period: the platform setting or its built-in default, and every team override, read inside the
   function from `retention_settings` and `teams.retention_overrides`. This enforces H-10 in the database, so it
   also holds while previous-release binaries can still change settings;
2. it is sealed (its `id` is in `omp_audit.chain`); and
3. if any consumer is `required`, its `seq` is at or below the lowest required `acked_seq`.

The settings API additionally refuses an audit period below the floor or below `D_calls`, and refuses a call or team
override above the audit period. The database rule is the guarantee; the API rule is the explanation.
`omp_audit.chain` rows outlive their audit rows and are purged only behind a checkpoint, which becomes the trusted
start anchor. Acceptance covers hostile-timezone callers, missing floor or state rows (fail closed: delete nothing),
flag restoration on error, and owner/ACL/definer/`search_path` preservation.

**Before a consumer is registered**, rows are sealed but may be purged by age before anyone reads them. That is
today's behaviour plus sealing, and the tip's earliest-available `seq` says so honestly. Operators who need
delivery guarantees register a required consumer.

**Rollback hazard.** Once streaming is enabled, a rollback to a release without a sealer pauses audit purging
(nothing new is sealed). That fails safe for evidence, at a storage cost. The runbook gives the migration-role
command to disable the interlock deliberately. Mixed-version windows are fine: old binaries insert, the trigger
stamps, the new sealer seals.

## 7. What it detects, and what it does not

- A receiver detects a missing `seq`, a reordered or duplicated record, a changed summary (any profile) or full row
  (full profile), and a rewound or forked stream (a different hash at a held `seq`, or a tip below its own).
- `verify` detects in-database tampering of chained rows only relative to a trusted anchor. Without an off-host
  checkpoint, someone who controls the database can rewrite the whole chain consistently.
- Not detected: a row the application never wrote; a row invented by a compromised runtime; events during a period
  when an attacker held the checkpoint key; anything in legacy single-owner mode that the owner role can undo.

## 8. Build plan

| Slice | Contents | Migrations | Acceptance |
| --- | --- | --- | --- |
| **1. Seal and pull** | Section 3 schema and `omp_audit` reconciler/inspector support; sealer (backlog, fast path, sweep, incarnation halt, timeline epoch); `rebase` command; record v2 with its normative canonical specification, golden vectors and Python verifier; pull, ack, tip and verify APIs; consumers; purge interlock; metrics (`omp_audit_stream_lag_seconds`, `_sealed_total`, `_late_total`, `_state`); docs (deploy runbook for restore/cutover/rollback, threat model BR-10/H-10) | `00058`, `00059` | Ported watermark proof including the negative control; the trigger restamps forged or `NULL` `txid` and `COPY` under the runtime role; a late-prefetched or `OVERRIDING SYSTEM VALUE` id is sealed normally; a synthetic incarnation change halts and `rebase` seals pre-existing rows and lock-blocked writers without loss; a timeline change starts an epoch; sweep finds nothing in normal runs and seals a planted gap with `late`; purge never removes an unsealed or unacknowledged row, honours the floor and `D_calls` including team overrides, and keeps `TimeZone=UTC`; the runtime role cannot change `omp_audit` state except through the functions; the previous image starts in required split-role mode and migrates/reconciles without error between and after `00058`/`00059`; both role modes |
| **2. Push webhook + checkpoints** | Checkpoint key and signing, signed tip; webhook sink with sealed URL/secret; failure notification; Admin › Audit sinks UI | next free | At-least-once in order across restart and failover; a stalled required sink stops purge; sealed values never appear in any response, log or audit entry; checkpoints verify in the Python verifier |
| **3. Syslog TLS + OTLP** | Two more sink kinds, allowed-networks setting, fake TLS syslog and OTLP receivers | none expected | Same as slice 2 per kind; TLS failure recovery |
| **4. Bulk exports** | `adminExportAudit`, `adminExportCalls`, team calls export (NDJSON/CSV, streamed, filters as the list APIs, never payloads) | none | Streaming without loading the range; token scope; CSV safety |

#39 (holds, export and erasure) starts after slice 2: holds join the purge interlock, and erasure must not break
the chain. The plan is to keep the chain row and its hashes while personal fields are anonymised by a
migration-role function, with an erasure marker; the full profile then reports the row as erased rather than
failing verification. That is #39's design to settle.

## 9. Open questions for the owner

1. Is the default **summary** profile right, or should full rows leave the host by default?
2. The default `AUDIT_MIN_RETENTION_DAYS` of 30 keeps today's behaviour; the issue suggested 90. The database now
   also keeps audit at least as long as call metadata (H-10). That can retain audit longer on upgrade where call
   retention exceeds audit retention today.
3. Physical failover starts a new epoch automatically; a logical restore halts until `rebase`. Is that split right,
   or should every incarnation change wait for an operator?

## 10. Review record (2026-11-05)

An independent fresh-context review (Codex, read-only, with its own experiments on a disposable server) confirmed
watermark completeness within one xid history, snapshot alignment, savepoint stamping, trigger-and-`CHECK`
behaviour, state-row gapless allocation, retention lock safety, the first draft's record framing and the migration split. It
found no critical issue and eleven others, all addressed above:

| # | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | High | xmin-below-cursor misses a logical restore once xmin moves past; logical replication keeps publisher xids and bypasses the trigger | Incarnation binding with a halt and a mandatory rebase before serving writes (4.3); the sweep (4.2) as a backstop |
| 2 | High | The id-floor seam can strand prefetched/overridden ids and mis-restored sequences | Membership is by `txid` (and `txid IS NULL` for history), never by id magnitude; rebase uses a lock-bounded snapshot, not `max(id)` (3, 4.3) |
| 3 | High | Previous release's reconciler grants full DML on new `public` tables and its inspector requires it | Protected state in a new `omp_audit` schema behind definer functions; previous-image startup/migrate tests; trust scoped to split-role mode (1, 3) |
| 4 | High | Summary fields were not authenticated | `summary_hash` in record v2 (4.4) |
| 5 | High | Sealed-only retention can purge before delivery | Durable consumers and acks in slice 1; `410 range_expired`; honest pre-registration behaviour (5.1, 6) |
| 6 | High | No receiver recovery protocol for rewinds | Tip endpoint, stream-wide receiver state, fork rules, `--resume-after-seq` (5.3) |
| 7 | Medium | Full canonical form under-specified | Normative versioned specification with listed edge cases (4.4) |
| 8 | Medium | Inherited 1 KiB line and hex-only CSV limits | Version-2 limits and oversized handling; CSV as a view (4.4) |
| 9 | Medium | H-10 relation missed team overrides and old binaries | `D_calls` from platform and team settings, enforced in the purge function (6) |
| 10 | Medium | `CREATE OR REPLACE` drops `TimeZone=UTC` | Restate all settings; hostile-timezone and fail-closed tests (3, 6) |
| 11 | Low | "Commit order" overstated | Renamed to sealing order (2) |
