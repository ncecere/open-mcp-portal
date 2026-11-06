# Audit streaming slice 2: signed checkpoints and webhook sinks (#38, decision 94)

Status: **slice 2a implemented locally for review (2026-11-06); slice 2b remains design.** Migration 63 supplies the protected extension and keys; the leader, CLI, key publication, pull verification and checkpoint alerts are wired. Acceptance evidence and outstanding coverage are recorded in the implementation handoff. It
builds on slice 1, which shipped in v0.14.0: [audit-streaming.md](audit-streaming.md) (decision 93) and
[audit-record-v2.md](audit-record-v2.md). The owner delegated the defaults in section 8.

Slice 2 ships as two consecutive parts, each a reviewable unit:

- **2a. A protected extension schema and signed checkpoints** (migration `00063`).
- **2b. Webhook sinks and the Admin › Audit stream page** (migration `00064`).

Slice 3 adds syslog over TLS and OTLP to the sink model of 2b; slice 4 adds bulk exports.

## 1. Goal and non-goals

The portal pushes the audit stream to a receiver itself, and periodically signs where the chain stands, so a receiver
can anchor history without trusting the database. That closes H-10: an off-host copy that a platform admin cannot
quietly rewrite.

Not in this slice:
- syslog and OTLP (slice 3), per-team sinks, custom CAs or mTLS for sinks;
- purging `omp_audit.chain` rows behind a checkpoint;
- WORM storage.

## 2. Compatibility boundary: `omp_audit_ext` (2a)

### 2.1 Why a new schema

The actual v0.14.0 inspector (`internal/store/audit_boundary.go` at the tag) treats `omp_audit` as closed:
- it requires exactly 2 or 5 tables;
- it allows only six named functions;
- its reconciler revokes every other grant in the schema, including column-level grants.

So a new protected table or function in `omp_audit` would make a v0.14.0 replica refuse to start in required
split-role mode, or would have its grants stripped by a v0.14.0 `migrate`. The reviewer confirmed this against the
real predicates. v0.14.0 does not look at schemas it does not know, so all new protected objects go into a new
migration-owned schema, `omp_audit_ext`.

### 2.2 A manifest-driven boundary, for good

Hard-coding the protected object set is what made this necessary, so `omp_audit_ext` fixes it going forward:

- **The manifest.** `omp_audit_ext.manifest` lists every object in the schema and the exact **set** of privileges the
  runtime gets on it. Its columns:
  - `kind`: `table` or `function`;
  - `identity`: the schema-qualified table name, or the full function signature as `regprocedure` text;
  - `privileges`: a sorted, de-duplicated text array whose elements are `select`, `execute` or `update(<column>)`, one
    element per column.

  A table may combine `select` and column updates. For example, `checkpoint_keys` is `{select, update(private_key_cipher)}`,
  because key rotation selects ids and ciphertext before rewrapping them. A function may have only `execute`.
  `(kind, identity)` is unique.

  Owner, `PUBLIC`, inherited-privilege and grant-option checks stay independent of the manifest. It describes allowed
  runtime operations, never trust.
- **Inspector and reconciler from 2a on.** They read the manifest instead of a hard-coded list. They reject any object
  not in the manifest, and any runtime privilege beyond it. They grant exactly what it lists.
- **Writes.** Only migrations, which run as the migration role, write the manifest. The runtime has `SELECT` on it.
- **Effect.** Later slices add objects and manifest rows in one migration, and every release from 2a on accepts
  them without a code change. v0.14.0 applies its all-schema `CREATE` and schema-ownership checks to this schema, and the proposed grants pass
  them. Its table, function and grant-option checks are limited to schemas it knows, so it ignores everything else
  here; the re-check confirmed this with the real v0.14.0 inspector and reconciler. `omp_audit` itself stays exactly as
  v0.14.0 expects:
  five tables, the same functions, and the same grants.

Changes to `omp_audit` are limited to what v0.14.0 tolerates:
- new nullable columns on `state` and `chain`, without column-level grants;
- replacing function bodies under the same signatures, restating every setting, using the restate-and-assert pattern
  from migration 00062.

### 2.3 Compatibility acceptance (2a and 2b)

Each test uses the actual v0.14.0 executable:
- start in required split-role mode at the new schema;
- run `migrate` (reconcile) **after** the new release's reconcile, then restart the new release and confirm its grants
  are intact;
- run the new release's reconcile after v0.14.0's;
- restart v0.14.0 after the new release has written checkpoints, with checkpoints still disabled (section 3.4);
- roll back from the new release to v0.14.0 **before** checkpoints are enabled, and confirm the retention loop,
  sealer and pull API;
- after checkpoints are enabled, refuse v0.14.0 (section 3.4);
- run the actual v0.14.0 key-rotation utility against schema 63/64. It does not know the extension ciphertext, so the
  runbook forbids retiring a previous `ENCRYPTION_KEY` with an older utility whenever extension ciphertext exists, and
  a test pins that the new utility covers it.

## 3. Checkpoints (2a)

### 3.1 Key

- **Dedicated key.** An install-local Ed25519 key, never the ES256 identity key.
- **Storage.** It lives in `omp_audit_ext.checkpoint_keys`: `kid bytea(16)`, `public_key bytea(32)`, `state`
  (`active` or `retired`), `private_key_cipher`, `created_at`, and `active_from_seq` and `retired_at_seq` (bigint,
  nullable).
- **`kid`.** The first 16 bytes of `SHA-256(public_key)`, raw in the statement, and unpadded base64url in JSON.
- **At most one active key.** A partial unique index enforces it.
- **Sealing.** The private key is sealed with `ENCRYPTION_KEY`, AAD `audit_checkpoint_key:<kid base64url>`, and
  the column joins `keyrotation.Columns`. The manifest grants the runtime `update:private_key_cipher` and nothing else
  on the table, so a key-rotation run can rewrap it.

**First key.** `omp_audit_ext.ensure_checkpoint_key(kid, public_key, cipher)` takes the `omp_audit.state` row lock
first. It inserts the key only if no active key exists, and returns the active key either way. A replica that loses
the race discards its generated key and loads the winner's.

**Rotation is atomic, and it completes even on a busy stream.** `open-mcp-portal audit-stream rotate-checkpoint-key`
uses the runtime URL, because it seals with `ENCRYPTION_KEY`. It:
1. generates and seals the new key;
2. opens one transaction and locks `omp_audit.state` `FOR UPDATE`, so sealing waits for milliseconds;
3. reads the tip from that locked row;
4. builds the handover statement (3.2), listing the old then the new `kid`;
5. signs it locally with **both** keys;
6. calls `omp_audit_ext.rotate_checkpoint_key(new_kid, new_public, new_cipher, statement, signatures)` **in the same
   transaction**.

A concurrent rotation waits on the lock, then fails its tip check and retries from step 2. An incarnation change or a
non-`running` status aborts the rotation with a clear error. Rotation, like every checkpoint append, requires
`checkpoints_enabled` (3.4).

The function, under the state-row lock and in one transaction:
- checks that the statement covers the current tip;
- appends the handover checkpoint record;
- activates the new key with `active_from_seq` set to the handover's `seq`;
- retires the old key with `retired_at_seq` set to the same `seq`, and clears its `private_key_cipher`.

There is no pending state, so a crash leaves either the old key active with nothing appended, or the full handover
committed. Concurrent rotations serialize on the state lock, and the loser fails because the tip moved. Rotation is
audited, is manual, and is recommended yearly.

**Publication.** `/.well-known/omp-audit-keys.json` is anonymous. It is a JWK set (`kty: OKP`, `crv: Ed25519`), and each
key carries `kid`, `active_from_seq` and `retired_at_seq`. Retired keys stay listed, but only for verifying
checkpoints in their own range.

### 3.2 Statement and record (normative in `audit-record-v2.md`)

```
statement = "OMP-AUDIT-CHECKPOINT\0V1\0" || stream_id 16 || epoch u32 || seq u64 || covered_seq u64
            || covered_chain_hash 32 || issued_at_unix_micros i64 || kid_count u8 (1 or 2) || kid_1 16 [|| kid_2 16]
signature_i = Ed25519(private_key_i, statement)        -- 64 bytes each, in kid order
```

**Rules:**
- `seq` is the checkpoint record's own sequence number, and `covered_seq = seq - 1`.
- `covered_chain_hash` is the chain hash at `covered_seq`.
- `issued_at` is stored as the record's `occurred_at` and is the only timestamp.
- `kid_count` is 1, or exactly 2 for a handover, with two distinct kids: old, then new.

**The record.** It is the chain record at `seq`, with `kind = checkpoint`, row identity and entry hash zero, and
`flags = 0`. Its `summary_hash` is `SHA256("OMP-AUDIT-CHECKPOINT-SUMMARY\0V1\0" || statement || signatures)`, so the
chain commits to the signatures. The statement and signatures are stored in new nullable `omp_audit.chain` columns:
`checkpoint_statement bytea` and `checkpoint_signatures bytea`, the latter 64 or 128 bytes. A `CHECK` requires them
exactly when `kind = 'checkpoint'`.

**Database checks.** `seal_batch(mode => 'checkpoint')` is the existing function with a new mode, restated with every
existing check and setting. In one locked transaction it requires:
- `checkpoints_enabled`, `status = running`, no pending epoch, and the live incarnation unchanged. These are the same
  fences as data sealing plus the enable flag, and they apply to **every** checkpoint append path, rotation included.
  Stale submissions are rejected with SQLSTATE `40001`.
- `seq = last_seq + 1`, `covered_seq = last_seq` and `covered_chain_hash = last_chain_hash`.
- The stream id and epoch from state.
- `kid_count = 1` and `kid` equal to the active key, outside rotation. The handover goes only through
  `rotate_checkpoint_key`.
- Signature byte lengths, and summary and chain hashes that match when it recomputes them.

**It cannot verify Ed25519.** Core PostgreSQL has none. Go verifies its own signature before submitting, and
`verify` and receivers verify every signature. A forged signature is detectable denial of evidence, never accepted
authentication.

### 3.3 Cadence

`omp_audit.state` gains `entries_since_checkpoint`, `last_checkpoint_seq` and `last_checkpoint_at`.
- **Counter.** Only `entry` records increment the counter. `epoch_start` and `checkpoint` records and declared
  sequence gaps do not.
- **When to write.** The sealer leader writes a checkpoint when `entries_since_checkpoint >= 10000`, or when
  `entries_since_checkpoint >= 1` and 15 minutes have passed since `last_checkpoint_at`. A checkpoint resets the counter.
- **Baseline.** When checkpoints are first enabled (3.4), the baseline is set to the time of enabling.
- **Idle streams.** An idle stream writes none, and a checkpoint never counts toward the next one.
- **Stale state.** On `40001` or any changed state, the leader re-reads the tip, rebuilds and re-signs. It never
  resubmits an old statement.

### 3.4 Enabling checkpoints only after the rollout

v0.14.0's pull and verify code treats every non-entry record as an `epoch_start` record. The reviewer showed that it
then returns a **partial or empty `200`** when a checkpoint is in the range, not a clean error. So checkpoints are
off until an operator runs `open-mcp-portal audit-stream enable-checkpoints` with the migration role, after every
serving replica runs 2a or later. It sets `state.checkpoints_enabled`.

The status page and `audit-stream status` show this state, and the command refuses if the stream is not `running`.

**Enabling is a minimum-reader-version transition, a one-way door.** Once a checkpoint record exists, v0.14.0 must
not serve again, because disabling future checkpoints cannot remove existing ones. The command says so and requires
`--min-reader-version-ack`. It records `state.min_reader_version` (the 2a version), and the runbook makes "rollback
only to a release at or above it" explicit. Fencing a returning v0.14.0 from inside the database is not possible
for every role mode, so it is not claimed. Acceptance tests cover pre-enable rollback (allowed) and post-enable
behaviour separately.

### 3.5 Receiver rules, added to the slice-1 protocol

A receiver must:
- **Enroll** by pinning the stream id and the **currently active** key from `omp-audit-keys.json`, fetched over TLS and
  confirmed out of band. It never treats every listed key as a signing authority.
- **Verify each checkpoint:** the statement's stream id, epoch and `seq` equal the record's, `covered_seq = seq - 1`,
  `covered_chain_hash` equals the hash it holds for `covered_seq`, `issued_at` equals the record time, and every
  signature is valid. A statement moved into another record fails these equalities.
- **Track authority.** Pinned keys carry an authority range. A key may sign only checkpoints with `seq` inside its range.
  A verified handover, signed by the current key and the new one, closes the old key's range at the handover `seq`
  and opens the new key's. After that, the old key can authorize nothing, neither a later checkpoint nor another
  handover.
- **Treat anything else as a discontinuity** needing local operator approval: an unknown `kid`, a key outside its range,
  or a suspected key compromise. Automatic handover is not compromise recovery.
- **Enrollment is forward-only by default.** It starts from an approved anchor: a checkpoint at or after the active
  key's `active_from_seq`, signed by the pinned key. To verify older history, a receiver walks back through
  authenticated handovers. Each handover is signed by both keys, so a pinned K2 vouches for K1 within K1's range, and
  so on. An explicit historical-key approval is the alternative. During a handover, the new key's signature on that
  record is the only signature it may make outside its own range, at its first `seq`.
- **Restores and rebases.** Approving a chain discontinuity (slice 1, 5.3) **never** restores a retired key's authority.
  Authority after an approved discontinuity comes only from the keys the receiver already holds as current, or from a
  new explicit key approval.
- **Duplicates and conflicts.** A receiver discards only **identical** duplicates. A record at a `seq` it holds with a
  different hash is a fork, preserved and alerted, even when it arrives late or belongs to an archived branch.

The checkpoint's JSON envelope is normative in `audit-record-v2.md`. Next to the common fields, it carries:
- `checkpoint.statement`: the base64url of the exact bytes;
- `checkpoint.kids`: unpadded base64url, in order;
- `checkpoint.signatures`: base64url, in kid order;
- the decoded `stream_id`, `epoch`, `seq`, `covered_seq`, `covered_chain_hash` and `issued_at`, which receivers must
  check equal the statement's.

The Python reference verifier implements these rules. It stays standard-library only, with a small pure-Python
RFC 8032 Ed25519 verify tested against the RFC's vectors. It is slow, which is acceptable for a reference verifier.

### 3.6 What checkpoints add, and what they don't

A receiver holding the pinned key can verify that records up to a checkpoint are exactly what the portal sealed and
signed at that time.

Checkpoints don't detect an attacker who holds the active private key (the runtime holds it, sealed by
`ENCRYPTION_KEY`), nor rows the application never wrote. Off-host copies and earlier off-host checkpoints bound how far
back a compromise can reach.

## 4. Webhook sinks (2b)

### 4.1 Model: sinks are not consumers

Sinks get their own protected state. They are **not** slice-1 consumers, because the shipped `auditAck` lets
auditors and `platform:read` tokens acknowledge any consumer name. A sink's cursor must move only when the sender
confirmed a delivery. The table is `omp_audit_ext.sinks`, with all writes through definer functions.

**Columns:**
- **Identity and settings:** `id`, `name` (unique, 1–100 characters), `kind` (`webhook`), `profile` (`summary` or
  `full`), `required`, `enabled`, `batch_max_records` (1–1,000, default 100), `revision`.
- **Sealed:** `url_cipher` and `url_hint` (host only), `secret_cipher`, `secret_previous_cipher` and
  `secret_previous_until`. The AADs are `audit_sink:<id>:url`, `:secret` and `:secret_previous`. The manifest grants
  the runtime `update:` on the three cipher columns only, for keyrotation.
- **Delivery:** `cursor_seq`; `inflight_first`, `inflight_last` and `inflight_token` (a uuid), plus
  `inflight_revision`; `next_attempt_at`, `consecutive_failures`, `last_error_class`, `last_ok_at`, `state`
  (`active`, `range_expired` or `paused`); `streak_id` (a uuid, nullable) and `streak_notified`.
- **Pending gap:** `gap_first` and `gap_last`, nullable.

**Functions** (hardening contract as slice 1: owner-bound, fixed `search_path`, `TimeZone = 'UTC'`, `PUBLIC` revoked,
bounded arguments):
- `create_sink`, `update_sink(id, expected_revision, …)` and `delete_sink`. These are the only way to change settings;
  each bumps `revision` and **clears any in-flight attempt**.
- `begin_attempt(id, expected_revision, expected_cursor, kind, first, last)`, where `kind` is `data` or `gap`. Under
  the sink-row lock it requires that:
  - the revision and cursor equal the snapshot's, so a read taken under an older configuration cannot start an attempt;
  - `first = cursor_seq + 1` for data, or the persisted gap endpoints for a gap;
  - the in-flight slot is empty, or holds the same kind, range and revision.

  It **always issues a new token**, which replaces any previous one, so a previous leader's late result is rejected.
  The token is bound to the revision, kind and range.
- `finish_attempt(id, token, ok, error_class, notify_intent)`. It succeeds only for the current token. On a successful
  data attempt it advances `cursor_seq` to `inflight_last`, never backwards. A successful gap attempt sets
  `cursor_seq = gap_last` and clears the gap. The streak transition and its notification intent are written in the
  same transaction (4.3).
- `resume_sink(id)` and `acknowledge_oversized(id, seq)`, both audited by the API layer.

**Retention.** The purge function (`public.omp_purge_audit_log`, replaced with every setting restated) caps the
deletable prefix at the minimum `cursor_seq` of **every required sink, whatever its `enabled` or `state`**, alongside
required consumers. A required sink can never be `range_expired`:
- expiry applies only to sinks that are not required;
- making a sink required is refused while it is `range_expired`, so it must be resumed first;
- every retention-affecting transition (create, `required` on or off, enable or disable, delete, expire, resume) and
  the purge itself serialize on the `omp_audit.retention_floor` row lock;
- an expiry decided from a stale read re-checks `required` under that lock.

The purge's age-only path before streaming starts now also requires that no sink exists. Unrequiring or deleting a
sink is the explicit way to release retention, and both are audited.

**Threat limit.** These functions protect against mistakes, auditors, tokens, stale leaders and previous releases.
They do **not** protect against a compromised runtime. It can call the runtime-executable functions, including
`finish_attempt(ok=true)` and the management functions, so it can release a sink's retention hold or claim deliveries
that never happened. Receiver-side completeness checks (gapless `seq`, checkpoints) and receiver alerting on silence
are what detect that.

### 4.2 Delivery

The leader holds a session advisory lock, `omp.auditsinks`, on a dedicated connection for as long as it leads. **No
transaction and no row lock** is held during network I/O. The leadership lock is a session lock by design, and
fencing (below) makes losing it harmless.

For each due sink:

1. **Read** in one read-only REPEATABLE READ transaction, using `auditstream`'s contiguity check and row reads on that
   same snapshot. If there is an in-flight range, re-read exactly that range. Otherwise read records after the cursor,
   up to `batch_max_records` or a 4 MiB **target**. A single envelope larger than the target, up to the pull API's
   16 MiB line cap, is sent alone in its own request, so the cap never stalls delivery. The 4–16 MiB interval has a
   test. An expired range reports `range_expired` (step 6). A missing row reports
   `integrity`, and nothing is sent.
2. **Begin.** `begin_attempt` records the range before any byte is sent.
3. **POST** the NDJSON lines of the pull API for that profile, envelopes included. Headers:
   - `Content-Type: application/x-ndjson`
   - `X-OMP-Event: audit.batch`
   - `X-OMP-Audit-Stream`
   - `X-OMP-Audit-First-Seq` and `X-OMP-Audit-Last-Seq`
   - `X-OMP-Delivery` and `Idempotency-Key`, both `<sink id>:<first>-<last>:<revision>`, stable across retries of
     the same in-flight range
   - `X-OMP-Attempt`, `X-OMP-Timestamp` and `X-OMP-Signature`. The signature is the same HMAC as notification
     webhooks, with two `v1=` values while a previous secret is valid.
4. **Finish** with `finish_attempt`. A 2xx advances the cursor. Anything else gets a fixed error class: `dns`, `connect`,
   `tls`, `timeout`, `http_3xx` (redirects are never followed), `http_4xx`, `http_5xx`, `too_large`, `policy_denied`
   or `integrity`. Failures back off from 1 s, doubling, capped at 5 minutes, with 20% jitter.
5. **Ordering.** The portal guarantees that a sink's cursor only advances over a range the destination acknowledged, in
   `seq` order, and that it sends every sealed record at least once. It does **not** guarantee arrival order. A stale
   leader's delayed request can arrive after newer ranges. Receivers apply records by `seq`, discard only identical duplicates, and
   preserve a conflicting hash at a held `seq` as fork evidence, as slice 1 requires. Tests cover lock-session loss while an HTTP
   request is still running.
6. **Expired range** (optional sinks only, since required ones hold retention). The sink is set to `range_expired`,
   an alert fires, and delivery **stops**. An admin calls `POST …/{id}/resume`, which is audited. Under the floor lock it
   records `gap_first = cursor_seq + 1` and `gap_last = earliest_available - 1`. The sender then delivers the gap as a
   fenced `gap` attempt:
   - one signed request with `X-OMP-Event: audit.gap`, whose **HMAC-covered body** carries the stream id and the exact
     endpoints;
   - resent with the same delivery id until a 2xx;
   - on success, `cursor_seq = gap_last`.

   Normal delivery then resumes and re-checks availability. If retention advanced meanwhile, the sink expires again
   and a second, explicit resume covers the new hole. A gap is never stretched silently. The gap request is
   **advisory**. Under 3.5 the receiver needs local approval of a new trusted predecessor, or the next checkpoint, to
   continue verifying, and it keeps its old evidence. A portal resume never implies receiver trust.
7. **Oversized full-profile rows** (above the 16 MiB line cap). These are sent as the **same oversized envelope as the
   pull API** (`entry_hash`, length, reference).
   - A sink that is not required passes the envelope and continues.
   - A **required** full-profile sink **stops at that `seq`**: its cursor does not pass the envelope, so the cursor
     itself holds retention, and no separate bookkeeping is needed. An admin resolves it with
     `POST …/{id}/oversized/{seq}/acknowledge`, which is audited. It calls `acknowledge_oversized(id, revision, seq)`,
     which lets the sink pass that one `seq` after the admin has retrieved the row through the entries API.

   Another party's fetch never releases a sink. There is no special wire format and no large request.

### 4.3 Failure notifications

- **Streaks.** `finish_attempt` opens a streak, with a new `streak_id`, on the first failure after a success, and
  closes it on success.
- **Failing notice.** When `finish_attempt` records the third consecutive failure, the **same transaction** writes the
  notification event `audit.sink_failing` (dedup key `audit-sink:<id>:<streak_id>:failing`) through the notification
  service's transactional insert, and sets `streak_notified`. They commit together or not at all.
- **Recovery notice.** A success that closes a notified streak writes `audit.sink_recovered` (`…:recovered`) in the
  same transaction. It keeps the closed streak's id on the event, so a crash cannot lose it.
- **Duplicates versus failures.** The event insert distinguishes "already exists", which is success for an idempotent
  retry, from failure. It does not use `notify.Emit`'s single boolean.
- **Plumbing.** These are new platform-admin event types, wired through validation, recipients, preferences,
  composition and routing. Tests cover flapping, repeated streaks and crash boundaries.
- **Not a substitute for receiver monitoring.** A compromised runtime can simply stop sending, so receivers should
  alert on silence.

### 4.4 Destination policy

- **A dedicated validator** (a parameterized `notify.CheckURL`):
  - `https`, or `http` only for an allowlist entry with `AllowHTTP`;
  - no user info or fragment;
  - at most 2,048 characters.
- **Save-time resolution.** The host is resolved at save time, and every answer must be allowed. That is a check, not a
  guarantee.
- **Dial time.** The address is enforced again at every dial by the guarded dialer, which checks every resolved
  address and connects to the approved IP, so DNS rebinding cannot reach a blocked address.
- **Transport.** It reuses the notification transport pattern, not the MCP exchange client, with proxies ignored and
  responses discarded after 64 KiB.
- **Allowlist.** `AUDIT_STREAM_ALLOWED_NETWORKS` is separate and empty by default, so destinations are public only.
- **TLS.** Verification is always on.
- **Secrets.** URL-bearing errors are reduced to fixed classes. The URL never appears in logs, errors, audit or
  responses.

### 4.5 Management API and page

Platform-admin browser sessions only. Tokens get `403 token_not_allowed`, and auditors may read.

- **Endpoints.** `…/admin/settings/audit-sinks` CRUD, with `If-Match` on `revision`. The URL is write-only and
  returns only the host hint. The secret is portal-generated, 32 bytes, and shown once at creation and rotation.
- **Actions.** `rotate-secret` (the previous secret stays valid for 24 hours), `test` (a signed `audit.test` that
  never moves the cursor), `resume`, and `oversized/{seq}/acknowledge`.
- **Status.** `GET /v1/admin/audit/stream/status` is open to platform admins, auditors, or `platform:read`. It returns
  the tip, the checkpoint state (enabled, last, keys), sinks and consumers with lag, state and retention effect.
- **Ack.** `auditAck` now refuses consumer names beginning `sink.` and `sink-`, with tests. Since sinks are not
  consumers, it cannot reach them anyway; this is defence in depth.
- **The page.** Admin › Audit stream shows:
  - stream status, including a prominent notice when the sealer or checkpoints are off;
  - checkpoint keys and their fingerprints;
  - a sinks table with each sink's **effect on retention** (holding, not holding, holding while disabled);
  - sink dialogs, test, rotate, resume, oversized acknowledgements;
  - the pull consumers;
  - "how to verify" links.

  Auditors see it read-only. The wording says "tamper-evident with pinned keys and stream id" and never claims
  tamper-proofing.

## 5. Migrations

- **`00063` (2a):**
  - schema `omp_audit_ext`, `manifest`, `checkpoint_keys`, `ensure_checkpoint_key` and `rotate_checkpoint_key`;
  - new nullable columns on `omp_audit.state` and `omp_audit.chain`;
  - `seal_batch` restated with `checkpoint` mode;
  - inspector and reconciler move to the manifest for `omp_audit_ext`, while `omp_audit` keeps its exact v0.14.0
    shape.
- **`00064` (2b):** `sinks` and its functions plus their manifest rows, and the purge function restated with the
  sink cap.

## 6. Metrics and alerts

Labels are bounded, with no names or ids:
- `omp_audit_stream_sink_lag_records{kind,required}`;
- `omp_audit_stream_sink_deliveries_total{kind,result}`;
- `omp_audit_stream_checkpoints_total`;
- `omp_audit_stream_last_checkpoint_timestamp_seconds`;
- `omp_audit_stream_checkpoints_enabled`.

Alert rules:
- a sink failing for 15 minutes;
- no checkpoint for 1 hour with entries pending while checkpoints are enabled;
- sink lag over 100,000 records.

## 7. Acceptance tests

**2a:**
1. Manifest-driven inspection rejects unlisted objects and excess privileges. The reconciler grants exactly the
   manifest.
2. The section 2.3 compatibility suite passes with the real v0.14.0 executable.
3. First-key creation is race-safe across concurrent replicas.
4. Rotation is atomic. A crash before commit leaves the old key, and concurrent rotations serialize.
5. `seal_batch(checkpoint)` rejects:
   - a wrong `seq` or `covered_seq`, or a wrong hash;
   - another stream or epoch;
   - an inactive `kid`, or a handover outside rotation;
   - bad signature lengths;
   - a stale incarnation, a pending epoch, or a `rebasing` state;
   - summary or chain mismatches.
6. Go, SQL and Python vectors cover statements, summaries, records and malformed inputs.
7. Cadence follows 3.3:
   - entry-only counting;
   - nothing written when idle;
   - a baseline at enabling;
   - re-signing on a stale state;
   - correct behaviour across a promotion, a declared gap and a rebase.
8. Checkpoints are disabled until `enable-checkpoints`.
9. `verify` checks signatures and authority ranges.
10. The Python verifier:
    - accepts a clean chain with a handover;
    - rejects a transplanted statement;
    - rejects a retired key signing after its range;
    - rejects an unknown `kid`.

**2b:**
1. Fenced attempts: stale leader results are rejected, and losing the lock session while a request is in flight is
   handled.
2. A crash between the 2xx and `finish_attempt` resends the identical range with the same delivery id. Arrival order is
   tolerated.
3. REPEATABLE READ snapshots hold under a concurrent purge.
4. Range expiry stops the sink. Resume and the gap request work, and the gap request is resent until accepted.
5. Oversized rows: the envelope is delivered, and a required full sink holds retention until fetch or acknowledgement.
6. The required, disabled and expired states have the correct retention effect.
7. Configuration changes clear in-flight attempts. A late 2xx for an old URL or profile is rejected.
8. The notification streak works across crash, flapping and failed emission.
9. Destination policy: save-time resolution, mixed DNS answers, rebinding, mapped IPv6, redirects, proxies, secret
   redaction, and `AllowHTTP`.
10. A sentinel test shows URLs and secrets never leak.
11. Authorization and token matrices, including the refusal of `sink.` names in `auditAck`.
12. The UI passes Vitest, axe, and a real-browser check at desktop and phone sizes.
13. The section 2.3 compatibility suite passes again at schema 64.

## 8. Defaults the owner may override

- A checkpoint every 10,000 entries, or every 15 minutes with activity.
- Manual key rotation, recommended yearly.
- Checkpoints enabled by an explicit operator command after rollout.
- Sinks not required and in the summary profile by default.
- Admins notified at the third consecutive failure.
- A separate, empty `AUDIT_STREAM_ALLOWED_NETWORKS`.
- A 4 MiB and 1,000-record batch cap.

## 9. Review record (2026-11-06)

An independent read-only review of the first draft, running experiments on a disposable PostgreSQL 17, found no
critical finding, six high and eight medium. All are addressed above.

| # | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| 1 | High | New objects in `omp_audit` break v0.14.0's closed inspector and reconciler | New `omp_audit_ext` schema with a manifest-driven boundary; `omp_audit` keeps its v0.14.0 shape; real-executable compatibility suite (2) |
| 2 | High | Auditors and `platform:read` tokens can ACK a sink consumer and skip evidence | Sinks are not consumers; fenced protected cursor; `auditAck` refuses sink names (4.1, 4.5) |
| 3 | High | Rotation can lose the old key before the handover; creation races | Atomic pre-signed handover in one locked transaction; unique active key; locked first-key creation (3.1) |
| 4 | High | Receivers keep signing authority for retired keys | Authority ranges per key; a handover closes the old range; enrollment pins the current key only (3.1, 3.5) |
| 5 | High | Oversized delivery and resume conflict with the shipped `ack` | Sink-specific functions; oversized rows use the pull envelope, with retention held for required full sinks until fetch or audited acknowledgement (4.1, 4.2) |
| 6 | High | Advisory leadership cannot guarantee arrival order | Cursor-order and at-least-once guarantee only; receivers apply by `seq`; fenced attempts; leadership lock distinguished from transaction locks (4.2) |
| 7 | Medium | v0.14.0 pull returns a partial `200` on checkpoint records | Checkpoints off until `enable-checkpoints` after rollout (3.4) |
| 8 | Medium | READ COMMITTED breaks the snapshot contract | One REPEATABLE READ snapshot per read (4.2) |
| 9 | Medium | The gap line is not a recovery protocol | Separate advisory signed request, durable until accepted; receiver approval required (4.2) |
| 10 | Medium | Statement and envelope under-specified | Exact layout, kid encoding, single timestamp, envelope-binding equalities, vectors (3.2, 3.5) |
| 11 | Medium | Cadence initialization and race rules missing | Entry-only counter, baseline at enabling, existing fences, re-sign on a stale state (3.3) |
| 12 | Medium | Sink configuration and cursor can diverge | All sink state protected; configuration changes clear in-flight attempts and bump the revision; effect on retention shown (4.1, 4.5) |
| 13 | Medium | URL validation does not resolve and has the wrong bounds | Dedicated validator, save-time resolution, `AllowHTTP`, notification transport (4.4) |
| 14 | Medium | Notification streaks lack durable identity | Persisted streak id, outbox dedup keys, retried emission, full event plumbing (4.3) |

**Re-check of the revision:** no critical finding, five high and seven medium. It closed findings 1, 2, 3, 6, 8, 11
and 13, and partly closed 4, 5, 7, 9, 10, 12 and 14. Using the real v0.14.0 inspector and reconciler it confirmed:
- the extension schema and its grant set pass, and survive a v0.14.0 reconcile;
- runtime cannot tamper with the manifest (SQLSTATE `42501`);
- reconciliation converges in either order;
- the statement binding prevents transplantation;
- first-key creation has no lock inversion.

| # | Severity | Finding | Resolution |
| --- | --- | --- | --- |
| R1 | High | A read under an old configuration can begin an attempt under a newer revision | `begin_attempt` takes the expected revision and cursor, checks the range, and always issues a fresh token bound to revision, kind and range (4.1) |
| R2 | High | No safe rollback after enabling checkpoints; rotation bypasses the gate | Every append path requires `checkpoints_enabled`; enabling is an acknowledged minimum-reader-version transition; separate pre- and post-enable tests (2.3, 3.2, 3.4) |
| R3 | High | No sink-specific bookkeeping for oversized rows | A required full sink's cursor stops at the envelope (the cursor is the hold) until an audited, sink- and revision-bound acknowledgement; others' fetches never release it (4.2) |
| R4 | High | Envelopes of 4–16 MiB have no delivery path | 4 MiB is a target; one envelope up to the 16 MiB cap is sent alone; tested (4.2) |
| R5 | High | `required` plus `range_expired` fails open; transitions race the purge | Required sinks never expire; requiring an expired sink is refused; all retention transitions serialize on the floor lock; the age-only path checks sinks; compromised-runtime threat limit stated (4.1) |
| R6 | Medium | A durable gap can become obsolete while waiting | Fenced gap attempts with HMAC-covered endpoints; the cursor moves to `gap_last`; a new hole needs a new explicit resume (4.2) |
| R7 | Medium | Notification transitions not crash-safe | The streak transition and event insert commit in one transaction; "exists" is distinguished from failure (4.1, 4.3) |
| R8 | Medium | Rotation may never succeed on a busy stream | Lock the state row, read the tip, sign locally and rotate in one transaction; retry rules (3.1) |
| R9 | Medium | Receiver bootstrap and checkpoint JSON incomplete | Forward-only enrollment from an approved anchor, historical verification through handovers, no authority restored by discontinuity approval, normative JSON (3.5) |
| R10 | Medium | Manifest cannot express SELECT plus column UPDATE | Privilege sets per object, signature identity, independent owner/`PUBLIC`/grant-option checks (2.2) |
| R11 | Medium | The old key-rotation utility ignores extension ciphertext | Runbook restriction and an actual-old-utility regression test (2.3) |
| R12 | Medium | "Discard at or below held" hides forks | Discard identical duplicates only; preserve conflicts (3.5, 4.2) |
