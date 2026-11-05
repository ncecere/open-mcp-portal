# Audit streaming: ordering, sealing, delivery and retention (#38, decision 93)

Status: **implementation in progress, feature disabled by default.** Slices 1a/1b implement schema, canonical records, sealing and recovery. Slice 1c adds migration 62, consumer boundaries, retention interlock and pull APIs; acceptance evidence remains required before enabling. The design was revised twice on 2026-11-05 after two independent adversarial reviews (section 10). It turns the #38 proposal and the unwired [audit evidence foundation](audit-streaming-foundation.md)
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
SELECT a.id, a.row_uid FROM audit_log a
WHERE a.txid < (SELECT x FROM wm)
  AND (a.txid, a.id) > ($cursor_txid, $cursor_id)
  AND NOT EXISTS (SELECT 1 FROM omp_audit.chain c WHERE c.row_uid = a.row_uid)
ORDER BY a.txid, a.id
LIMIT $batch
```

The anti-join matters only after a rebase (section 4.3), when rows sealed by the rebase can carry foreign xids
above the cursor. The cursor advances only to the last row actually sealed, never to a skipped one.

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
by `id`, and a row's identity in the chain is a trigger-stamped, never-reused `row_uid` (section 3). So prefetched,
caller-supplied or reused ids and restored sequence state cannot strand a row or make it look sealed.

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
unfamiliar `public` table full DML to the runtime role, and its role inspector *requires* that DML, so protected
state cannot live in `public`. It cannot live in `omp_private` either, whose reconciler refuses unexpected
relations. New protected state goes in a **new schema `omp_audit`**, owned by the migration role. The re-check
reviewer ran the previous release's actual inspector and reconciler against a migration-owned `omp_audit` with
runtime `USAGE`/`SELECT` at synthetic versions 58 and 59: both accepted it and the reconciler preserved the grants
(a catalog experiment; slice 1 adds the previous-image startup test).

In `public`:

1. `audit_log.txid xid8` and `audit_log.row_uid uuid` (both nullable, no defaults). A `BEFORE INSERT` trigger
   (function in `omp_audit`) **always** sets `NEW.txid := pg_current_xact_id()` and
   `NEW.row_uid := gen_random_uuid()`, whatever the caller supplied. `CHECK (txid IS NOT NULL AND row_uid IS NOT
   NULL) NOT VALID` applies to new rows only. A column default would let a caller supply `NULL` or a forged value.
   `row_uid` exists because `id` is reusable: after retention deletes a row, a caller with `INSERT` can write a new
   row with the same id (`OVERRIDING SYSTEM VALUE`, or a mis-restored sequence). Keyed by `id`, that new row would
   look already sealed. Checked on PostgreSQL 17: the trigger overrides a caller-supplied `row_uid` and `txid`, even
   with `OVERRIDING SYSTEM VALUE`. Both reviews confirmed restamping on `INSERT` and `COPY`, that an unprivileged
   role cannot set `session_replication_role`, and that privileged replica mode still fails the `NULL` check. The
   new role inspector also rejects runtime `SET` privileges on that parameter.
2. `omp_purge_audit_log(days, batch)` is replaced in place: same signature, owner, ACL, `SECURITY DEFINER`, fixed
   `search_path` **and `TimeZone = 'UTC'`** (`CREATE OR REPLACE` drops settings it does not restate; dropping
   migration 00033's setting would reopen the caller-timezone bypass). Section 6 gives the new algorithm.

In `omp_audit` (runtime role: `USAGE` on the schema, `SELECT` on the tables, `EXECUTE` on the listed functions,
nothing else; managed by new reconciler and inspector code that the previous release ignores):

3. `state` (one row): `stream_id uuid` (random per install), `system_identifier`, `timeline`, `epoch int`, `status`
   (`running`, `halted_incarnation`, `rebasing`), `cursor_txid xid8`, `cursor_id bigint`, `last_seq bigint`,
   `last_chain_hash bytea`, `sweep_at`.
4. `chain`: `seq bigint PRIMARY KEY`, `kind` (`entry`, `epoch_start`, `checkpoint`), `row_uid uuid UNIQUE` (new rows),
   `legacy_id bigint UNIQUE` (history rows with `txid IS NULL`, whose ids can no longer be reused because new rows
   are never `NULL`-stamped), exactly one of the two for `entry` and neither otherwise; `audit_id` (informational),
   `epoch`, `flags` (`late`, `oversized`), `occurred_at`, `summary_hash`, `entry_hash`, `chain_hash`, `sealed_at`.
   Append-only by trigger. No foreign key: retention removes the audit row first and keeps the chain row as the
   anchor.
5. `consumers`: `name`, `profile`, `required bool`, `acked_seq`, `acked_at`, `created_by`; `oversized_fetches`
   (consumer, seq) for section 4.4.
6. `retention_floor` (one row, `min_days`). The migrate command writes `AUDIT_MIN_RETENTION_DAYS` from the operator's
   environment (default 30, today's hard minimum, so no behaviour change). Neither platform admins nor the runtime
   role can change it.
7. The definer functions in section 4.5, the only way the runtime changes stream state.
8. `00059` (`NO TRANSACTION`): `CREATE INDEX CONCURRENTLY IF NOT EXISTS` on `audit_log (txid, id) INCLUDE (row_uid)
   WHERE txid IS NOT NULL`, dropping and recreating an invalid index left by an interrupted run (the safe-to-rerun
   pattern of `00020`). Acceptance runs the previous image between `00058` and `00059` as well as after both.

Pre-existing history is exactly the rows with `txid IS NULL`. The `NOT VALID` check stops new ones, so that set is
final once the migration commits.

## 4. Sealing

### 4.1 Normal operation

The leader (advisory lock `omp.auditstream`, `store.TryAdvisoryLockText`) runs batches. Each batch is one READ
COMMITTED transaction that calls `seal_batch` (section 4.5). `seal_batch` locks the state row, so two sealers can
never both extend the chain even if leader election fails. A `seq` comes from the state row, never from a PostgreSQL
sequence, so a rolled-back batch leaves no gap (confirmed by experiment). No network I/O happens inside the
transaction. Order within a batch:

1. **History backlog:** rows with `txid IS NULL` not in `chain.legacy_id`, in `id` order, until none remain.
2. **Fast path:** section 2's query.

If `seal_batch` reports a stale candidate (already chained, or the status changed), the sealer discards the batch
and re-reads; it never retries the same candidates in a loop.

### 4.2 Safety-net sweep

A sweep runs daily and after every rebase or epoch change. It is an anti-join on `row_uid` (and `legacy_id`) over
rows that should already be sealed: `txid IS NULL`, or `(txid, id) <= cursor` with `txid` below the watermark. It
seals anything it finds with the `late` flag and increments `omp_audit_stream_late_total`, which should always be
zero; any hit alerts. Correctness does not rest on the sweep, but it bounds the damage of an unforeseen bypass to
"late and flagged" rather than "never".
As built (slice 1b), a pass checks at most 5,000 ids after its persisted scan position and seals at most 500. A
cycle completes on a pass that finds no newer audit rows; on a busy install it keeps making passes over only the
rows written since the last one, which costs a few index probes per new row. The re-check confirmed it catches a REPEATABLE READ writer that held an xid
below a rebase's `F` and was blocked by its lock (`fast_hits=0, sweep_hits=1`), without sealing it before commit.

### 4.3 Incarnation, epochs, rebind and rebase

The state records the incarnation: `system_identifier` from `pg_control_system()`, and the **WAL insertion
timeline** from `pg_walfile_name(pg_current_wal_lsn())`. That is not `pg_control_checkpoint().timeline_id`, which
stays on the old timeline after a promotion until the end-of-recovery checkpoint completes, while the new primary
already accepts writes. Any login role can read both (checked). Each batch compares them to the live values:

- **Timeline changed, same `system_identifier`** (physical failover or switchover, including CloudNativePG, and
  PITR). xids continue, so the fast path stays correct, but the chain may have rewound. The sealer starts a new
  epoch automatically with an `epoch_start` record (section 5.3) and alerts.
- **`system_identifier` changed.** Either a logical restore or replication cutover (xids from another history;
  the apply worker also bypasses the stamping trigger) or a `pg_upgrade` (a new cluster with xids preserved). The
  sealer **halts** (`status = halted_incarnation`, metric, alert). It does not guess which from xids: the first
  review showed that `snapshot xmin < cursor_txid` misses a regression once unrelated activity moves xmin past the
  old cursor. Audit rows written while halted are kept and sealed later. The operator runs one of two migration-role
  commands:
  - `open-mcp-portal audit-stream rebind` after `pg_upgrade` (the deploy runbook's major-upgrade step): records the
    new identifier and keeps epoch and cursor. It refuses if the snapshot xmin is below `cursor_txid`, as a sanity
    check, not as proof of continuity; the operator asserts that.
  - `open-mcp-portal audit-stream rebase` after a logical restore or cutover, **before serving writes**.
- **Rebase** keeps every snapshot read-only and every state change in fresh transactions:
  1. Transaction A takes `LOCK audit_log IN SHARE MODE`, which waits for in-flight writers. While A holds it,
     read-only REPEATABLE READ transaction B takes its snapshot. B now sees exactly the committed pre-rebase rows.
  2. A sets `status = rebasing`, the new incarnation, `epoch + 1`, `F = pg_current_xact_id()` and cursor `(F, 0)`,
     writes no chain record and commits. Writers resume; the lock was held for milliseconds.
  3. B streams the identities of its unsealed rows, in `id` order, to the sealer. The sealer seals them in normal
     READ COMMITTED transactions through `seal_batch(mode => 'rebase')`, preceded by one `epoch_start` record.
     B never locks or writes anything (the re-check showed B cannot lock the state row A changed: SQLSTATE 40001).
     While `status = rebasing`, `seal_batch` accepts only rebase batches, so the fast path is fenced.
  4. The sealer sets `status = running`. Once the watermark passes `F`, it sweeps rows with `txid < F` once, to catch
     writers that held an xid below `F` and were blocked by the lock.
  5. **Crash recovery.** A crash leaves `status = rebasing`. Rerunning `rebase` resumes: it takes a fresh
     lock-bounded snapshot and seals every visible unsealed row. That superset includes rows written since, which is
     safe: each identity is sealed at most once (`UNIQUE row_uid`), and the fast path skips chained rows. It keeps
     the same epoch and does not repeat `epoch_start`.

  Rows sealed by a rebase can carry foreign xids above `F`. The fast path's anti-join skips them when the
  watermark reaches them, and its cursor never jumps to a foreign xid, which would skip later local writes.

### 4.4 Record version 2

The foundation's version-1 record (59 bytes: IDs and two enums only) cannot carry what a SIEM needs. Version 2 keeps
its discipline (fixed binary layout, domain separation, no JSON in the chain, explicit `seq`) and authenticates
**both** the summary a receiver acts on and the full row:

```
summary_hash = SHA256("OMP-AUDIT-SUMMARY\0V1\0" || canonical_summary_bytes)
entry_hash   = SHA256("OMP-AUDIT-ENTRY\0V1\0"   || canonical_entry_bytes)       -- zero for non-entry kinds
record_v2    = version u8 (=2) || kind u8 || flags u8 || stream_id 16 || epoch u32 || seq u64
               || row_identity 16 || occurred_at_unix_micros i64 || summary_hash 32 || entry_hash 32  -- 119 bytes
chain_hash   = SHA256("OMP-AUDIT-EVIDENCE\0CHAIN\0V2\0" || previous_chain_hash 32 || record_v2)
genesis predecessor = SHA256("OMP-AUDIT-EVIDENCE\0GENESIS\0V2\0" || stream_id)
```

`row_identity` is the `row_uid`, or for history rows eight `0xFF` bytes followed by the big-endian `legacy_id`
(which `gen_random_uuid()` cannot produce, because its version nibble is 4). For `epoch_start` and `checkpoint`
records it is zero, and `summary_hash` commits to the record's own fields (section 5.3).

**Canonical encodings are a normative, versioned specification written with slice 1**, with golden vectors shared by
Go, SQL and the Python reference verifier. Rules:

- The **summary** encoding uses only scalar columns (text, uuid, timestamps, the actor kind), each as a presence byte,
  then a big-endian length and the UTF-8 bytes, or the fixed-width value, in a fixed field order. It is deliberately
  computable in SQL with built-ins (`sha256`, `int4send`, `int8send`, `uuid_send`, `convert_to`, checked) so the
  database can validate it (section 4.5).
- The **full** encoding adds `before_state`, `after_state`, `metadata`, `client_ip`, the token name and kind and
  `txid`. It must define SQL `NULL` versus an empty string versus JSON `null`, duplicate jsonb keys (PostgreSQL keeps
  the last), object key order (sorted by UTF-8 bytes) and one fixed string escaping with no optional `\u` forms.
  Numbers are PostgreSQL's numeric text tokens, **never** decoded through float64, which loses `9007199254740993`.
  Scale is preserved as stored (`1.0` and `1.00` are equal as jsonb but differ in text).
- Adding a column to `audit_log` later means a new canonical version, never a silent change to version 1.

**Limits and oversized rows.** The foundation's 1,024-byte line cap and integer/hex-only CSV policy were made for the
59-byte record and do not fit version 2: legitimate snapshots exceed 2 KiB, and `team.create` is not hex. Version 2
uses a 16 MiB per-line reader limit with a fixed-size buffer. A full-profile line above it is never downgraded. It
is replaced by an **`oversized` envelope** that carries the summary fields, `entry_hash`, the full length and a
reference. The consumer fetches the full row in bounded chunks from `GET /v1/admin/audit/entries/{seq}/full` and
verifies `entry_hash` itself. The server records each fetch (`oversized_fetches`). A full-profile consumer's ack is
refused (`409 oversized_pending`, listing the seqs) past any oversized seq it has not fetched, so retention cannot
release full evidence it never collected. CSV is an export view with spreadsheet-safe quoting (a leading `'` before
formula characters), never a verification input.

### 4.5 The privileged boundary

All functions are `SECURITY DEFINER`, owned by the migration role, `SET search_path = pg_catalog, pg_temp` and
`TimeZone = 'UTC'`, with every relation schema-qualified, `EXECUTE` revoked from `PUBLIC` and granted to the runtime
role only. Arguments are bounded: batch length 1 to 1,000, digests exactly 32 bytes, known kinds and flags only.

- `seal_batch(mode, records[])` locks the state row, requires `status = running` (or `rebasing` for
  `mode => 'rebase'`), and for each record checks that `seq` is `last_seq + 1…`, that the referenced audit row exists
  with that `row_uid` or `legacy_id` and is not already chained, and that the fast-path cursor only moves forward.
  It **recomputes `summary_hash` from the audit row and `chain_hash` from the fields and the previous hash in SQL**,
  and rejects any mismatch. It also refuses to **skip** rows: a history record must be the next `txid IS NULL` row
  after the history cursor (`history_id`), and a fast-path record must be the next unchained row after the
  watermark cursor, both checked with index probes (`audit_log_history_idx`, `audit_log_stream_idx`, the chain's
  unique `row_uid`), so a buggy or compromised caller cannot strand a row behind the cursor. Only `entry_hash`, which needs the jsonb canonicaliser, is caller-supplied; a wrong one
  is detected by `verify` and by full-profile receivers. So a compromised runtime can make the stream unverifiable
  (a denial of evidence), but cannot make it state something about a row's summary that the row does not say.
- `ack(consumer, seq)`: monotonic, at most `last_seq`, subject to the oversized rule.
- `register_consumer`, `set_required`, `remove_consumer`: audited. Authorisation (platform admins with a browser
  session for registration and `required`; the consumer's own token for `ack`) is enforced by the API, not the
  database. A compromised runtime can therefore forge an ack and release the purge interlock for that consumer. The
  consumer sees the result as `410` for what it never received, never as silent loss.

## 5. Delivery, consumers and recovery

### 5.1 Pull (slice 1)

`GET /v1/admin/audit/stream?after_seq=N&limit=&profile=summary|full` returns sealed records with `seq > N`
(exclusive) in `seq` order as NDJSON, joined to their audit rows. It is open to platform admins and auditors with a
browser session, or an automation token with `platform:read` (which already grants full audit reads). A collector
(Vector, Fluent Bit, a SIEM's HTTP input) polls it. No outbound network, no sealed URLs, no SSRF surface.

The response is **contiguous or an error**. Retention removes only a `seq` prefix (section 6), so a range is either
fully available or starts below the earliest retained `seq`. In that case the API returns `410 range_expired` with
the earliest available `seq`. Any `entry` record in the range whose audit row is missing anyway is an integrity
failure (`500 audit_row_missing`, metric, alert), never a silent omission or a downgraded profile.
`POST /v1/admin/audit/stream/ack` records a registered consumer's acknowledged `seq`.
`GET /v1/admin/audit/verify?from=&to=` recomputes the chain over a range and reports the first bad `seq`.

### 5.2 Profiles

The **summary** profile (default) carries time, action, actor kind and ids, team, target type and id, request id and
automation-token id, all covered by `summary_hash`. The **full** profile adds the fields listed in section 4.4,
covered by `entry_hash`. Full is opt-in per consumer, because snapshots can contain emails and other personal data.
Snapshots are already secret-redacted at write time. Summary is a smaller projection, not least privilege: its
stable ids are still personal, linkable data.

### 5.3 Receiver protocol

A conforming receiver **pins `stream_id`** at enrollment. A record with another `stream_id` is never treated as a
fresh stream without local operator approval, and the old anchor and history are kept. The receiver keeps
stream-wide state across epochs, `(stream_id, seq) → chain_hash`, and:

- accepts records whose predecessor is the hash it holds for `seq - 1`;
- accepts an `epoch_start` record as a **clean continuation** only when its declared predecessor is `seq - 1` and
  matches the hash it holds. A receiver that lagged behind a rewind point receives the restored history first and
  reaches the continuation normally;
- treats every other `epoch_start` as a **discontinuity**. That covers a predecessor that does not match the
  receiver's hash, a declared gap (`--resume-after-seq`), and a receiver that holds records beyond the predecessor.
  The receiver does not accept it until local approval. On approval it records the `epoch_start` as a new trusted
  anchor and keeps the old anchor and any records beyond the predecessor as orphaned fork evidence;
- treats a different hash at a held `seq` as a fork: it alerts and keeps both copies.

An `epoch_start` record's `summary_hash` commits to the previous epoch, the predecessor `seq` and hash the database
still holds, the reason (`timeline`, `rebase`), both incarnations and any declared gap. `rebase
--resume-after-seq=N` makes the new epoch start at `N + 1` and declares `predecessor_seq + 1 … N` as a gap. It
exists so numbering after a known rewind does not collide with seqs receivers already hold; it is always a
discontinuity, never a clean continuation.

`GET /v1/admin/audit/stream/tip` returns `stream_id`, epoch, `last_seq`, `last_chain_hash`, the earliest available
`seq` and the epoch history. It is **advisory**. An unsigned tip (slice 1) cannot make a pinned receiver accept
altered history: the chain and digests prevent that. But it can lie to suppress a rewind signal (a tip below what
the receiver holds), and a signed tip (slice 2) only adds the portal's own assertion. Receivers never replace
trusted local state from the tip.

### 5.4 Push sinks and checkpoints (slices 2 and 3)

Webhook (reusing `notify`'s signature header and client), then syslog over TLS (RFC 5424, octet counting) and OTLP
logs over HTTP/JSON (hand-rolled; no new dependency). Sink URL and secret are sealed columns joined to
`keyrotation.Columns`, with a separate `AUDIT_STREAM_ALLOWED_NETWORKS` (public https only by default). One sender
per sink, at least once, strictly in `seq` order; its cursor advances only after acknowledgement. A stalled sink never
blocks audit writes; it shows as lag and a failure counter, and platform admins are notified after 3 consecutive
failures.

Every 10,000 records or 15 minutes, the sealer writes a `checkpoint` chain record signed with a **dedicated** Ed25519
audit-checkpoint key, never the identity key that signs upstream JWTs. The private key is sealed; public keys are at
`/.well-known/omp-audit-keys.json`.

## 6. Retention interlock

The replaced `omp_purge_audit_log(days, batch)` (section 3, item 2) runs this algorithm, failing closed:

1. Read the singleton rows `public.retention_settings`, `omp_audit.state` and `omp_audit.retention_floor`. If any is
   missing, raise (and delete nothing; the existing flag restoration on error is kept).
2. Compute `D_calls` once per call: the platform `call_metadata` period, then the maximum with every
   `teams.retention_overrides` `call_metadata` value. An absent key means the built-in 90 days for the platform,
   and no override for a team. A JSON `null`, a non-integer or a value outside 1–3650 raises. Deleted teams no longer
   count, which matches the call purge (confirmed by the re-check). A performance test uses 10,000 teams.
3. `cutoff = now() - greatest(days, floor.min_days, D_calls)` days, all three non-null by step 1–2 (`greatest`
   ignores `NULL`s, so this must be checked, not assumed).
4. Find the largest `S` such that every `entry` record with `seq <= S` has `occurred_at < cutoff`, is at or below
   every required consumer's `acked_seq`, and is not past an unfetched oversized seq of a required full-profile
   consumer. Delete only audit rows whose chain record has `seq <= S`, joined on `row_uid` or `legacy_id`, in batches
   with `FOR UPDATE SKIP LOCKED`. Unsealed rows are never candidates.

Retention therefore removes a **`seq` prefix**, so the stream never has interior holes. A late-sealed old row waits
until the prefix reaches it, which retains it slightly longer than its age alone would. The settings API also refuses
an audit period below the floor or below `D_calls`, and a call or team override above the audit period. The database
rule is the guarantee; the API rule is the explanation.

The Go settings decoder currently ignores JSON errors, so a `null` period decodes as 0 days and a malformed value can
fall back to the built-in default. Slice 1 makes Go strict with the same rules as step 2 and pins them with a Go/SQL
parity test. Such values are reachable only by writing to the database directly; the API validates them.

`omp_audit.chain` rows outlive their audit rows and are purged only behind a checkpoint, which becomes the trusted
start anchor. Acceptance covers hostile-timezone callers, each missing-row and malformed-value case, flag restoration,
and owner/ACL/definer/`search_path`/`TimeZone` preservation.

**Before the stream has sealed anything and before any consumer exists** (every install that has not enabled
`AUDIT_STREAM_ENABLED`), the purge deletes by age exactly as before, still never below the floor or the longest
call-metadata period: there is nothing to protect, and requiring sealed rows would silently stop audit retention.
The first-ever seal takes the retention-floor row lock (state, then floor), as the purge does, so a row the purge is
deleting cannot be sealed and a sealed row cannot be age-purged. From then on the interlock above applies for good.
This was caught at integration review of slice 1c (`TestRetentionBeforeStreamingPurgesByAge`,
`TestFirstSealSerializesWithAgePurge`).

**Before a consumer is registered**, rows are sealed but may be purged by age before anyone reads them. That is
today's behaviour plus sealing, and the tip's earliest available `seq` says so honestly. Operators who need delivery
guarantees register a required consumer.

**Rollback hazard.** Once streaming is enabled, a rollback to a release without a sealer pauses audit purging (nothing
new is sealed). That fails safe for evidence, at a storage cost. The runbook gives the migration-role command to
disable the interlock deliberately. Mixed-version windows are fine: old binaries insert, the trigger stamps, the new
sealer seals.

## 7. What it detects, and what it does not

- A receiver detects a missing `seq`, a reordered or duplicated record, a changed summary (any profile) or full row
  (full profile), and a rewound or forked stream (a different hash at a held `seq`, a discontinuity, or a changed
  `stream_id`). An unsigned tip can hide a rewind signal but not altered history.
- The database refuses seals whose summary or chain hash does not match the row; `verify` and full receivers detect a
  wrong `entry_hash`.
- `verify` detects in-database tampering of chained rows only relative to a trusted anchor. Without an off-host
  checkpoint, someone who controls the database as owner can rewrite the whole chain consistently.
- Not detected: a row the application never wrote; a row invented by a compromised runtime; a forged ack (it shows as
  `410`, not silence); events during a period when an attacker held the checkpoint key; anything in legacy
  single-owner mode that the owner role can undo.

## 8. Build plan

| Slice | Contents | Migrations | Acceptance |
| --- | --- | --- | --- |
| **1. Seal and pull** | Section 3 schema and `omp_audit` reconciler/inspector support; sealer (backlog, fast path, sweep, incarnation halt, timeline epoch); `rebind` and `rebase` commands; record v2 with its normative canonical specification and Go/SQL/Python golden vectors; the section 4.5 functions; pull, ack, oversized fetch, tip and verify APIs; consumers; purge algorithm; strict Go retention decoding; metrics (`omp_audit_stream_lag_seconds`, `_sealed_total`, `_late_total`, `_state`); docs (deploy runbook for restore, cutover, major upgrade and rollback; threat model BR-10/H-10) | `00058`, `00059` | Ported watermark proof including the negative control; the trigger restamps forged or `NULL` `txid`/`row_uid` and `COPY` under the runtime role; a reused, prefetched or `OVERRIDING SYSTEM VALUE` id after a purge is sealed as a new row; a synthetic incarnation change halts, `rebind` and `rebase` recover, `rebase` seals pre-existing rows, foreign-xid rows (never twice) and lock-blocked writers, and a crashed rebase resumes; a promotion fixture changes the insertion timeline and starts an epoch; sweep finds nothing normally and seals a planted gap with `late`; `seal_batch` rejects a wrong summary or chain hash, a reused identity, a gap and a fast-path batch during `rebasing`; purge removes only a sealed, acknowledged `seq` prefix, honours the floor and `D_calls` with team overrides, fails closed on each missing row and malformed value, and keeps `TimeZone=UTC`; the stream API returns contiguous ranges or `410`; an unfetched oversized seq blocks a full-profile ack; the previous image starts in required split-role mode and migrates/reconciles between and after `00058`/`00059`; both role modes |
| **2. Push webhook + checkpoints** | Checkpoint key and signing, signed tip; webhook sink with sealed URL/secret; failure notification; Admin › Audit sinks UI | next free | At-least-once in order across restart and failover; a stalled required sink stops purge; sealed values never appear in any response, log or audit entry; checkpoints verify in the Python verifier |
| **3. Syslog TLS + OTLP** | Two more sink kinds, allowed-networks setting, fake TLS syslog and OTLP receivers | none expected | Same as slice 2 per kind; TLS failure recovery |
| **4. Bulk exports** | `adminExportAudit`, `adminExportCalls`, team calls export (NDJSON/CSV, streamed, filters as the list APIs, never payloads) | none | Streaming without loading the range; token scope; CSV safety |

Slice 1 is large. It may be built as consecutive pull requests behind one feature setting that stays off until all
of its acceptance passes: schema, trigger and functions; sealer and recovery; APIs and purge. It ships only whole.

#39 (holds, export and erasure) starts after slice 2: holds join the purge interlock, and erasure must not break the
chain. The plan is to keep the chain row and its hashes while personal fields are anonymised by a migration-role
function, with an erasure marker; the full profile then reports the row as erased rather than failing verification.
That is #39's design to settle.

## 9. Open questions for the owner

1. Is the default **summary** profile right, or should full rows leave the host by default?
2. The default `AUDIT_MIN_RETENTION_DAYS` of 30 keeps today's behaviour; the issue suggested 90. The database now also
   keeps audit at least as long as call metadata (H-10). That can retain audit longer on upgrade where call
   retention exceeds audit retention today.
3. A timeline change (failover, PITR) starts a new epoch automatically; a new `system_identifier` (logical restore,
   cutover, major upgrade) halts until `rebind` or `rebase`. Is that split right?

## 10. Review record (2026-11-05)

Two independent fresh-context reviews (Codex, read-only, each running its own experiments on a disposable
PostgreSQL 17 server) preceded this version.

**First review**: no critical finding, six high. It confirmed watermark completeness within one xid history, snapshot
alignment, savepoint stamping, trigger-and-`CHECK` behaviour, state-row gapless allocation, retention lock safety and
the migration split.

| # | Severity | Finding | Resolution | Re-check verdict |
| --- | --- | --- | --- | --- |
| 1 | High | xmin-below-cursor misses a logical restore; logical replication keeps publisher xids and bypasses the trigger | Incarnation binding with a halt and `rebase`/`rebind` (4.3); sweep (4.2) | Partially (rebase failures, now R1–R3, R5) |
| 2 | High | The id-floor seam strands prefetched/overridden ids and mis-restored sequences | Membership by `txid`; identity by `row_uid` (3, 4) | Partially (id reuse, now R2) |
| 3 | High | Previous release's reconciler grants full DML on new `public` tables and its inspector requires it | `omp_audit` schema behind definer functions; split-role trust scope (1, 3) | Closed |
| 4 | High | Summary fields not authenticated | `summary_hash` in record v2 (4.4) | Closed |
| 5 | High | Sealed-only retention can purge before delivery | Durable consumers and acks; `410` (5.1, 6) | Partially (interior holes, now R7) |
| 6 | High | No receiver recovery protocol | Tip, stream-wide state, fork rules (5.3) | Partially (now R6) |
| 7 | Medium | Full canonical form under-specified | Normative specification with listed cases (4.4) | Partially (still deferred to slice 1 by design) |
| 8 | Medium | Inherited 1 KiB line and hex-only CSV limits | Version-2 limits (4.4) | Partially (oversized conflict, now R9) |
| 9 | Medium | H-10 missed team overrides and old binaries | `D_calls` in the purge function (6) | Partially (failure semantics, now R8) |
| 10 | Medium | `CREATE OR REPLACE` drops `TimeZone=UTC` | Restate all settings; tests (3, 6) | Closed |
| 11 | Low | "Commit order" overstated | Sealing order (2) | Closed |

**Re-check of the revision**: no critical finding, three high. It ran the previous release's real inspector and
reconciler against `omp_audit` (accepted) and confirmed the sweep covers lock-blocked older-snapshot writers, that
deleted teams correctly fall back, and that pinned receivers cannot be made to accept rewritten history.

| # | Severity | Finding | Resolution in this version |
| --- | --- | --- | --- |
| R1 | High | Rebase transaction B cannot lock the state row A changed (SQLSTATE 40001) | B is read-only and only supplies candidates; sealing happens in fresh transactions, fenced by `status = rebasing`; crash recovery specified (4.3) |
| R2 | High | A purged id reused by a new row matches the old chain entry | Trigger-stamped, never-reused `row_uid` as the chain identity; `legacy_id` only for `NULL`-`txid` history (3, 4.4) |
| R3 | High | Foreign-xid rows sealed by rebase are selected again by the fast path, stalling it | Fast-path anti-join on `row_uid`; cursor never jumps to foreign xids; stale batches re-read (2, 4.1, 4.3) |
| R4 | Medium | Definer functions accept caller hashes; hardening unspecified | Summary and chain hashes recomputed in SQL; exact hardening contract; honest scope of `ack`/`set_required` (4.5) |
| R5 | Medium | Checkpoint timeline stale after promotion; `pg_upgrade` changes the identifier | WAL insertion timeline; explicit `rebind` for major upgrades (4.3) |
| R6 | Medium | `--resume-after-seq` cannot be a clean continuation; `stream_id` not pinned | Clean continuation versus approved discontinuity; mandatory `stream_id` pinning; advisory tip (5.3) |
| R7 | Medium | Earliest-available seq misses interior retention holes | Retention removes only a `seq` prefix; contiguous-or-error API; exclusive `after_seq` (5.1, 6) |
| R8 | Medium | Malformed settings and missing rows unspecified; `greatest` ignores `NULL` | Explicit fail-closed algorithm; strict Go decoding with a parity test (6) |
| R9 | Medium | Oversized handling contradicted "never downgrade" | Authenticated `oversized` envelope, chunked fetch and ack gating (4.4) |

## Slice 1c implementation notes

Migration 62 persists `purged_seq` in the owner-protected retention singleton.
Expiry is determined from this prefix anchor; a missing audit row above it is
an integrity error. Batch deletion stops at the first locked row rather than
skipping over it, preserving the no-interior-hole guarantee. Consumer configuration
shares that singleton lock with purging. Platform/team retention settings changes
serialize on the platform settings row.

Full JSON uses `sql_null_json` to disambiguate SQL NULL from JSON null. The oversized
flag reserves 64 KiB of envelope space below the 16 MiB wire limit. Consumer lag
metrics aggregate maxima with four bounded profile/required label combinations.
No consumer-name labels are emitted. Checkpoints, signing, push delivery and UI
remain future slices. The Vector example requires a durable cursor-aware adapter.

New consumers enroll at the protected `purged_seq` boundary. Starting them at zero
would permanently block a full consumer on a previously purged oversized row that
can no longer be fetched. This enrollment boundary does not claim delivery of
unavailable history; receiver approval of an initial anchor remains explicit.
