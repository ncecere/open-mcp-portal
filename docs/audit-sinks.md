# Audit streaming slice 2: signed checkpoints and webhook sinks (#38, decision 94)

Status: **design, 2026-11-06. Nothing in this document is built yet.** It builds on slice 1, which shipped in v0.14.0:
[audit-streaming.md](audit-streaming.md) (decision 93) and [audit-record-v2.md](audit-record-v2.md). The owner
delegated the defaults below and may override any of them. Slice 3 adds syslog over TLS and OTLP to the sink model
defined here, and slice 4 adds bulk exports.

## 1. Goal and non-goals

**Goal.** The portal pushes the audit stream to a receiver itself, so an install no longer needs a collector polling
the pull API. It also periodically signs where the chain stands, so a receiver can anchor history without trusting the
database. Together these close threat-model item H-10: an off-host copy that a platform admin cannot quietly rewrite.

**Not in this slice:**
- syslog and OTLP sinks (slice 3);
- per-team sinks;
- custom CA bundles or mTLS for sinks;
- purging `omp_audit.chain` rows behind a checkpoint, which stays future work because chain rows are about 200 bytes;
- WORM storage;
- changing slice 1's pull API, except that the tip gains the latest checkpoint.

## 2. Checkpoints

### 2.1 Key

- **Dedicated key.** Each install has its own Ed25519 audit-checkpoint key. It is never the ES256 identity key that signs
  upstream JWTs, because sharing a key would let one protocol's signatures stand in for the other's.
- **Storage.** A new protected table, `omp_audit.checkpoint_keys`, holds `kid`, `public_key` (32 bytes), `state`
  (`active`, `retired`), `private_key_cipher`, `created_at` and `retired_at`. The `kid` is the base64url SHA-256 of
  the public key, truncated to 16 bytes.
- **Sealing.** The private key is sealed with `ENCRYPTION_KEY` (`secrets.Box`) with AAD
  `audit_checkpoint_key:<kid>`, and the column joins `keyrotation.Columns`. A key-rotation run must be able to rewrap
  it, so the runtime role gets column-level `UPDATE (private_key_cipher)` and nothing else on the table. That is the
  same pattern as `omp_private.approval_binding_keys`, and the inspector checks it the same way.
- **Creation.** The runtime creates the first key the first time it needs to sign. It calls the definer function
  `omp_audit.add_checkpoint_key(kid, public_key, private_key_cipher)`, which refuses if an active key already exists.
- **Rotation.** `open-mcp-portal audit-stream rotate-checkpoint-key` uses the runtime URL, because it must seal with
  `ENCRYPTION_KEY`. It calls `omp_audit.rotate_checkpoint_key(new_kid, new_public, new_cipher)`, which
  1. retires the old key and clears its `private_key_cipher`, keeping its public key forever, and
  2. requires that the next checkpoint be a **handover**: one signed by both the old and the new key.

  Rotation is manual; the recommendation is yearly or after a suspected key exposure. It is audited.
- **Publication.** Public keys are published at `/.well-known/omp-audit-keys.json`, anonymously readable, as a JWK set
  (`kty: OKP`, `crv: Ed25519`) with `created_at` and `retired_at`. Retired keys stay listed so old checkpoints remain
  verifiable.

### 2.2 Checkpoint record

The sealer leader writes a `checkpoint` chain record when either condition holds:
- 10,000 entry records have been sealed since the last checkpoint, or
- 15 minutes have passed since it **and** at least one record has been sealed since.

An idle stream produces no checkpoints, but the tip still shows the latest one.

The signed statement is a fixed binary layout, made normative in `audit-record-v2.md`:

```
statement = "OMP-AUDIT-CHECKPOINT\0V1\0" || stream_id 16 || epoch u32 || covered_seq u64
            || covered_chain_hash 32 || issued_at_unix_micros i64 || kid_count u8 || kid_1 16 [|| kid_2 16]
signature_i = Ed25519(private_key_i, statement)
```

- **Coverage.** `covered_seq` and `covered_chain_hash` are the chain state immediately before the checkpoint record,
  so a checkpoint covers everything up to and including `covered_seq`.
- **The record.** The checkpoint becomes chain record `covered_seq + 1`, with `kind = checkpoint` and a zero row
  identity and entry hash. Its `summary_hash` is `SHA256("OMP-AUDIT-CHECKPOINT-SUMMARY\0V1\0" || statement ||
  signature_1 [|| signature_2])`. The chain therefore commits to the signatures, and a receiver that holds the record
  can verify them.
- **Database checks.** `seal_batch(mode => 'checkpoint')` is a new mode with one record. Under the state-row lock it
  checks that:
  - `covered_seq` equals `state.last_seq` and `covered_chain_hash` equals `state.last_chain_hash`;
  - the epoch and stream id match;
  - every `kid` is the active key, or the retiring key plus the new active key during a handover;
  - a handover carries exactly two signatures;
  - the summary and chain hashes match when it recomputes them.

  It **cannot verify the Ed25519 signatures**, because core PostgreSQL has no Ed25519. Go verifies its own signatures
  before submitting, and `GET /v1/admin/audit/verify` and receivers verify them too. A compromised runtime can
  therefore store a checkpoint with a bogus signature. Receivers reject it, and `verify` reports it. This is the same
  trust scope as slice 1's `entry_hash`.
- **Tip.** `GET /v1/admin/audit/stream/tip` adds `checkpoint: {seq, covered_seq, kids, issued_at}`, which is advisory.
  The record itself, in the stream, is what a receiver verifies.

### 2.3 What checkpoints add, and what they don't

A receiver that pins the stream id and the checkpoint public keys can verify, without trusting the database, that a
range of records up to a checkpoint is exactly what the portal sealed and signed at that time. That is useful even for
a receiver that only stores checkpoints.

It does not detect an attacker who holds the private key, so signing is only as strong as the runtime's protection of
`ENCRYPTION_KEY`. It also doesn't detect rows the application never wrote. The defence for both remains copies held off
the host, and earlier checkpoints held off the host bound how far back a key compromise can reach.

### 2.4 Receiver rules, added to the slice-1 protocol

- Pin the checkpoint public keys at enrollment, or take them from the first verified fetch of
  `omp-audit-keys.json` over TLS, and record them like the stream id.
- Accept a new `kid` only through a handover checkpoint signed by a key already pinned, or by local operator approval.
  Otherwise treat it as a discontinuity.
- Verify every checkpoint's signatures and its `covered_chain_hash` against the hash held for `covered_seq`. A mismatch
  is a fork.

The Python reference verifier implements these rules. It stays standard-library only, so Ed25519 verification is a
small pure-Python RFC 8032 implementation tested against the RFC's vectors. It is slow, which is acceptable for a
reference verifier.

## 3. Webhook sinks

### 3.1 Model

`public.audit_sinks` is an ordinary table, so the previous release's grant reconciler gives it normal DML and its
inspector accepts it. Its columns:
- `id`, `name` (unique, 1–100 characters), `kind` (`webhook`; slice 3 adds `syslog` and `otlp`), `profile`
  (`summary` or `full`) and `enabled`;
- `url_cipher` and `url_hint` (the host only);
- `secret_cipher`, `secret_previous_cipher` and `secret_previous_until`;
- `batch_max_records` (1–1,000, default 100);
- delivery state: `last_ok_at`, `last_attempt_at`, `consecutive_failures`, `next_attempt_at`, `last_error_class` and
  `state` (`active`, `range_expired` or `paused`);
- `revision`, `created_by`, `created_at` and `updated_at`.

The three ciphers join `keyrotation.Columns`, with AADs `audit_sink:<id>:url`, `:secret` and `:secret_previous`.

**Each sink is a consumer.** Creating a sink also registers the slice-1 consumer `sink.<id>` through
`omp_audit.register_consumer`, using the sink's profile and its `required` flag, in the same transaction. The sink's
cursor is that consumer's `acked_seq`. It is advanced only through `omp_audit.ack`, so the protected, monotonic,
oversized-aware acknowledgement and the purge interlock from slice 1 apply unchanged. Deleting a sink calls
`remove_consumer`. The `required` flag lives only on the consumer, so `set_required` is the one switch.

The configuration (URL, secret, enabled) sits in `public`, where a compromised runtime could change it. That costs
nothing new, because such a runtime can already read the audit log directly. The state that protects evidence, the
acknowledged cursor that gates purging, stays in `omp_audit`.

### 3.2 Delivery

One sender loop runs on the leader, under the advisory lock `omp.auditsinks`, separate from the sealer's lock. It
serves every sink whose `next_attempt_at` has passed. Each sink delivers strictly in order, at least once.

1. **Read.** A short READ COMMITTED transaction reads the sink, decrypts the URL and secrets, and reads sealed records
   after its cursor. It stops at `batch_max_records` or at 4 MiB of body. It uses the projection, contiguity check
   (`410`-equivalent) and integrity checks of the slice-1 pull API (`auditstream.Delivery`). It then commits, so
   **no network I/O happens inside a transaction or while a lock is held.**
2. **POST.** The body is NDJSON, exactly the pull API's lines for that profile, including `epoch_start`, `checkpoint`
   and `oversized` envelopes. Headers:
   - `Content-Type: application/x-ndjson`
   - `X-OMP-Event: audit.batch`
   - `X-OMP-Audit-Stream: <stream_id>`
   - `X-OMP-Audit-First-Seq` and `X-OMP-Audit-Last-Seq`
   - `X-OMP-Delivery` and `Idempotency-Key`, both `<sink id>:<first>-<last>`, so retries of the same range carry the
     same value
   - `X-OMP-Attempt`, `X-OMP-Timestamp` and `X-OMP-Signature`. The signature is `notify.SignatureHeader`, HMAC-SHA256
     over `timestamp.body`, with two `v1=` values while a rotated previous secret is still valid.
3. **Advance on any 2xx.** The sender calls `omp_audit.ack('sink.<id>', last_seq)` in a fresh transaction and records
   success with `last_ok_at` and `consecutive_failures = 0`. A crash between the 2xx and the ack resends the same
   range. Receivers deduplicate by `(stream_id, seq)`, as slice 1 already requires.
4. **Failure.** Any other result gets a fixed error class, recorded with exponential backoff (1 s, doubling, capped at
   5 minutes, with 20% jitter):
   - `dns`, `connect`, `tls` and `timeout`;
   - `http_3xx` (redirects are **never followed**);
   - `http_4xx`, `http_5xx` and `too_large` (a 413);
   - `policy_denied`, when the address is refused at dial time;
   - `integrity`, when the slice-1 checks fail locally, in which case nothing is sent.

   At **3 consecutive failures**, platform admins get one `audit.sink_failing` notification per failure streak,
   through the existing notification fan-out, and the next success sends `audit.sink_recovered`.
5. **Expired range.** An optional sink can fall behind retention, because only required sinks hold back purging. The
   sender then sets `state = range_expired`, notifies admins and **stops**. It never skips ahead silently. An admin
   resumes it explicitly with **Resume from earliest available**. That action is audited, and it sends one
   `audit.gap` line (`{"gap": {"from": a, "to": b}}`, unsigned by the chain and labelled as such) before the next
   records, so the receiver sees the hole.
6. **Oversized rows** (full profile only). A row whose full form exceeds the 16 MiB line limit is sent **alone** in
   its own request, in full, so the push receiver gets complete evidence. If the receiver refuses it with a 413 or
   another 4xx, the sink stalls with `too_large` and alerts. An admin can switch the sink to the summary profile, or
   fix the receiver. The record is never acknowledged as delivered in full when it wasn't.

Defaults: a 10-second connect timeout, a 30-second total timeout per POST, and a 4 MiB body cap. Responses are read
up to 64 KiB, then discarded.

### 3.3 Destination policy

URLs are checked as notification webhooks are (`notify.CheckURL` logic):
- `https` only, except plain `http` for a host in the allowlist;
- no user info or fragment;
- at most 2,048 characters;
- an address the allowlist permits, checked again at every dial by the guarded `upstream.Client`.

The allowlist is a **separate** `AUDIT_STREAM_ALLOWED_NETWORKS` setting, which defaults to empty, meaning public
addresses only (threat-model 10.1). Reusing `NOTIFY_WEBHOOK_ALLOWED_NETWORKS` would let anyone who may point a team
notification at an internal host also receive audit data there. TLS verification is always on, against the system CAs.

### 3.4 Management

These operations are open to **platform-admin browser sessions only**; automation tokens get `403 token_not_allowed`.
Every change is audited with before and after settings and no secret. `If-Match` conflicts answer `409`.

- `GET` and `POST /v1/admin/settings/audit-sinks`, and `GET`, `PUT` and `DELETE …/{id}`. The URL is write-only; only
  the host hint is ever returned. The **signing secret is generated by the portal** (32 random bytes) and shown
  **once**, at creation and rotation, the same as notification destinations.
- `POST …/{id}/rotate-secret`: the previous secret also signs for 24 hours.
- `POST …/{id}/test`: sends one signed `X-OMP-Event: audit.test` POST with the body `{"test": true, "stream_id": …}`.
  It contains no audit content, never moves the cursor, and returns the result class.
- `POST …/{id}/resume`: the `range_expired` recovery in 3.2 step 5.
- `GET /v1/admin/audit/stream/status`: platform admins and auditors, or a `platform:read` token. It reports the tip,
  the last checkpoint, every consumer and sink with its lag and state, and the public-key fingerprints. It is the read
  model behind the new page.

### 3.5 UI

There is a new **Admin › Audit stream** page:
- **Status card:** stream id, epoch, last sequence, last checkpoint and its age, state. When the sealer is off
  (`AUDIT_STREAM_ENABLED=false`), it says so prominently and explains that nothing is sealed or delivered.
- **Sinks table:** name, kind, profile, required, host, state, lag in records, last success, last error class, and
  consecutive failures.
- **Sink actions:** create and edit dialogs, with the secret shown once; test; rotate secret; resume; delete with
  confirmation.
- **Pull consumers:** list, register, toggle required, and remove. Slice 1 has the API but no UI.
- **Links:** the public-key set, and a short "how to verify" section pointing at the runbook.

Auditors see the page read-only. The wording never claims tamper-proofing; it says "tamper-evident with the pinned
keys and stream id". All new states have Vitest tests, axe checks and a real-browser check.

## 4. Schema: migration `00063` (expand-only)

- `omp_audit.checkpoint_keys`, plus the definer functions `add_checkpoint_key` and `rotate_checkpoint_key`. Both meet
  the slice-1 hardening contract: owner-bound, `search_path = pg_catalog, pg_temp`, `TimeZone = 'UTC'`, `PUBLIC`
  revoked and bounded arguments.
- `omp_audit.chain` gains nullable `checkpoint_kids text[]` and `checkpoint_signatures bytea[]`. A `CHECK` requires
  them exactly when `kind = 'checkpoint'`.
- `omp_audit.state` gains `last_checkpoint_seq`, `last_checkpoint_at` and `handover_pending`.
- `seal_batch` is replaced with the new `checkpoint` mode. Every existing check and setting is preserved, by the same
  restate-and-assert pattern migration 00062 used, plus the catalog tests.
- `public.audit_sinks` as in 3.1.
- Reconciler and inspector updates: runtime `EXECUTE` on the two new functions, column `UPDATE (private_key_cipher)`
  on `checkpoint_keys`, nothing else.
- The previous v0.14.0 executable must migrate, reconcile and serve at schema 63. Its retention loop and sealer ignore
  sinks and checkpoints. A v0.14.0 sealer that meets a checkpoint record in the chain only advances past it, because
  sealing reads the state row, not the chain. The previous-image test asserts this.
- **Mixed-version window.** v0.14.0's pull and verify code treats every non-entry record as an `epoch_start` record and
  parses its declaration. On a `checkpoint` record it therefore returns an error instead of a line. That fails closed:
  no wrong or partial data is served, and a collector retries. Upgrade guidance is to drain v0.14.0 serving replicas
  before relying on pull delivery across checkpoints. Checkpoints are written only by a new sealer, so a fleet still
  running only v0.14.0 never sees one. The previous-image test asserts the error is a clean failure, not a partial
  response.

## 5. Metrics

All labels are bounded, with no sink names or ids:
- `omp_audit_stream_sink_lag_records{kind,required}` (the maximum per label set);
- `omp_audit_stream_sink_deliveries_total{kind,result}`, where `result` is `ok` or one of the error classes;
- `omp_audit_stream_checkpoints_total`;
- `omp_audit_stream_last_checkpoint_timestamp_seconds`.

New alert rules in `deploy/prometheus`:
- a sink failing for 15 minutes;
- no checkpoint for 1 hour while records were sealed;
- sink lag over 100,000 records.

## 6. Acceptance tests

1. **Key boundary.** The runtime cannot insert or update `checkpoint_keys` except through the functions and the cipher
   column. Rotation seals with the right AAD, clears the old private key and keeps the old public key published.
   `keyrotation` rewraps the cipher.
2. **Checkpoint checks.** `seal_batch(checkpoint)` rejects a wrong `covered_seq` or hash, an unknown or retired `kid`,
   a handover with one signature, and a summary or chain mismatch. The summary hash commits to the signatures. Go,
   SQL and Python golden vectors cover the statement, the summary and the chain record.
3. **Cadence and verification.** A checkpoint is written after 10,000 records and after 15 minutes with activity, and
   none is written when idle. `verify` checks signatures and reports a planted bad signature. The Python verifier
   accepts a clean chain with a handover and rejects a new `kid` without one.
4. **In-order, at-least-once delivery** against a fake receiver that verifies the HMAC signature. It survives a sender
   restart and a crash injected between the 2xx and the ack (the range is resent with the same delivery id), and a
   leader change. No record arrives out of order, and none is skipped.
5. **Failure handling.** Backoff progresses, error classes are fixed, and the notification fires at the third failure
   and recovery fires once. A redirect is not followed. A private address is refused at save and at dial. A required
   sink that is failing stops audit purging; an optional one doesn't.
6. **Range expiry.** An expired range stops the sink with an alert. Resume is audited and sends the gap line.
7. **Oversized rows.** An oversized full-profile row is sent alone, and a 413 stalls the sink without acknowledging.
8. **Secret handling.** The URL and secrets never appear in any API response, log, metric, audit entry or error. A
   sentinel test covers this, as slice 1's did. The secret is shown once.
9. **Authorization.** Tokens and non-admins are refused on sink management. Auditors can read the status and the page.
   The token-scope and authz matrices are updated deliberately.
10. **Previous-image compatibility** at schema 63, in both role modes.
11. **UI.** Vitest and axe for every state, plus a Playwright real-browser check at desktop and phone sizes.

## 7. Defaults the owner may override

- 10,000 records or 15 minutes per checkpoint.
- Manual key rotation, recommended yearly.
- Sinks are **not required** by default, so a broken sink cannot fill the database. Admins mark a SIEM sink required
  deliberately, and the UI explains the trade-off.
- Sinks use the **summary** profile by default.
- An admin is notified after 3 consecutive failures.
- A separate, empty `AUDIT_STREAM_ALLOWED_NETWORKS`.
- A 4 MiB body and 1,000-record batch cap.
