# Audit record v2 (NORMATIVE)

This specification fixes canonical summary/entry version 1 and chain record version 2.
Implementations MUST hash bytes, never a JSON serialization of the record envelope.
The v1 experiment in `internal/auditevidence` remains a separate protocol.

All integers are big-endian. Every canonical field is encoded as `00` for SQL NULL,
or `01 || length u32 || value` for variable-length fields. Fixed-width values
use `01 || value` without a length.
Lengths count bytes. Text is UTF-8 without normalization; UUID is its 16 raw bytes;
time is signed i64 microseconds since Unix epoch in UTC. PostgreSQL timestamps must
be finite and representable in signed Unix microseconds. Empty text is `01 00000000`.
A zero UUID is present, and differs from SQL NULL.

Summary fields, in exact order: occurred_at (time), action (text), actor_kind (text),
actor_user_id (UUID), team_id (UUID), target_type (text), target_id (text), request_id
(text), actor_token_id (UUID). All fields use the presence framing above, with lengths only for text.

Full entry bytes start with those summary bytes and append, in order: before_state,
after_state, metadata (canonical JSON text), client_ip (text), actor_token_name
(text), actor_token_kind (text), txid (unsigned decimal text without leading zeros).
SQL NULL JSON uses `00`; JSON null uses the present UTF-8 token `null`. Neither is
an empty string (the JSON token `""`) nor empty SQL text. Audit ID and row UID are
record identity, not full entry fields; sealed_at is not an audit-row field.

JSON is the stored jsonb value: duplicate keys retain the last value. Object keys
sort lexicographically by UTF-8 bytes, recursively. Arrays retain order. No spaces
are emitted. Strings use literal UTF-8 except quote and backslash (escaped with a
backslash), and U+0000 through U+001F (lowercase `\u00xx`, including newline and tab).
No optional ASCII, slash or Unicode escapes occur. PostgreSQL jsonb rejects NUL and
invalid Unicode. Numbers use PostgreSQL numeric text tokens from jsonb text, without
conversion through binary floating point: 1.0 and 1.00 retain different scale;
9007199254740993 stays exact. Exponent input is normalized by PostgreSQL before
canonicalization. Negative zero is normalized by PostgreSQL. Raw JSON fixtures must
use stored numeric spelling; duplicate-key fixtures exercise last-key-wins ingestion.

`summary_hash = SHA256(ASCII("OMP-AUDIT-SUMMARY\0V1\0") || summary_bytes)`.
`entry_hash = SHA256(ASCII("OMP-AUDIT-ENTRY\0V1\0") || entry_bytes)`.

Record bytes have no presence/length framing and are exactly 119 bytes:
version u8=2, kind u8 (entry=1, epoch_start=2, checkpoint=3), flags u8 (late=1,
oversized=2, bitwise OR), stream UUID 16, epoch u32, seq u64, row_identity 16,
occurred_at signed i64 Unix microseconds, summary_hash 32, entry_hash 32.
Unknown kinds/flag bits are invalid. Epoch and sequence are positive.
For entries, row_identity is row_uid, or eight FF bytes followed by legacy_id as
signed i64 big-endian for historical NULL-txid rows. A v4 row UUID cannot collide
with that prefix. Non-entry kinds use a zero identity and zero entry hash. Their
summary is kind-specific: epoch starts and checkpoints are specified below.
Checkpoint append requires the explicit minimum-reader-version transition in
[audit-sinks.md](audit-sinks.md#34-enabling-checkpoints-only-after-the-rollout).

`chain_hash = SHA256(ASCII("OMP-AUDIT-EVIDENCE\0CHAIN\0V2\0") || previous_hash_32 || record_bytes_119)`.
The predecessor before seq 1 is
`SHA256(ASCII("OMP-AUDIT-EVIDENCE\0GENESIS\0V2\0") || stream_uuid_16)`.
A receiver MUST pin stream UUID and trusted predecessor/end anchors. Sequence
continuity and digest continuity alone do not authenticate an untrusted anchor.

The shared vectors in `internal/auditstream/testdata/vectors.json` include canonical
JSON, summary, full entry, record, genesis and chain hashes. Go and the Python
reference verifier check them; SQL integration checks the summary and actual seal.

The SQL input is a JSONB array of entry records containing `audit_id` (the source
row's primary-key locator), `seq`, `kind`, `flags`, `row_uid`, `legacy_id`,
`summary_hash`, `entry_hash`, `chain_hash`. Digests are hex. Exactly one identity
is present. For UUID identities SQL looks up by audit_id AND row_uid, so the
primary key avoids per-record full-table scans while identity remains the UUID.
The source audit_id is not itself a chain identity and is not hashed separately.

## Epoch starts (slice 1b)

An `epoch_start` has kind 2, flags zero, zero identity and entry hash. Its
`epoch_summary` declaration MUST contain these fields. Its summary hash is SHA256
of `OMP-AUDIT-EPOCH\0V1\0` followed by, in order:

- `previous_epoch` u32; `predecessor_seq` i64; `predecessor_hash` raw 32 bytes.
- `reason` text (`timeline` or `rebase`), using the variable-length presence framing.
- `old_system_identifier` text, `old_timeline` i64.
- `new_system_identifier` text, `new_timeline` i64.
- `gap_from`, `gap_to`: nullable i64, using fixed-width presence framing.

In this kind-specific summary, mandatory fixed-width fields are raw and
unframed; only text and nullable gap endpoints use presence framing.
All fields except the gap endpoints MUST be present. Identifiers are unsigned
PostgreSQL decimal text. Both gap endpoints MUST be NULL together, or describe
`predecessor_seq + 1 … resume_after_seq`, inclusive. An absent gap starts the
marker at `predecessor_seq + 1`; a present gap starts it at `gap_to + 1`.
The marker's epoch MUST be `previous_epoch + 1`. The marker chain uses the declared
predecessor hash even when a gap is declared; missing records are never fabricated.
The timestamp in the fixed record is the transition preparation time in UTC.
The shared `epoch_vectors.json` includes clean and declared-gap cases.

Receivers MUST pin stream UUID and retain stream-wide hashes across epochs. A
clean continuation requires the declared predecessor at `seq - 1` with the held
hash, no declared gap, and no held records beyond that predecessor. All other
epoch starts require local approval, which installs the marker as a new trusted
anchor while retaining the previous anchors and orphaned records as fork evidence.
Archived orphaned records MUST NOT block verified continuation from the approved
anchor; conflicting records remain fork evidence. A different hash at an already
held sequence MUST alert and preserve both hashes.
An unsigned tip MUST NOT replace trusted local state. The Python `Receiver`
harness implements these rules; it does not define a delivery API.

SQL derives epoch declarations from locked state, stores them in `epoch_pending`,
and recomputes both summary and chain hashes itself. `seal_batch('epoch', …)`
requires a pending rebase marker and a matching summary hash. Runtime cannot
prepare an epoch or choose an incarnation, predecessor, gap, timestamp or epoch.
Automatic timeline transitions use the same internal encoding and append primitive.

## Pull JSON envelope (slice 1c)

NDJSON envelopes expose `stream_id`, `epoch`, `seq`, `kind`, `flags`, identities,
`occurred_at`, and hex `summary_hash`, `entry_hash`, `chain_hash`. `summary_fields`
contains the normative scalar summary fields. Full profile adds `full`, containing
the original audit row plus `sql_null_json`, an array naming SQL-NULL JSON columns.
These names restore presence framing when the wire JSON has a null value; a null
column not listed is a present JSON null. Full fetch uses the same convention.
`epoch_summary` contains the normative epoch declaration. IDs and digests are not
inferred from JSON property order; canonical bytes remain defined above.

An oversized envelope omits `full`, sets `oversized`, and provides `full_length`
and a relative `reference`. The authenticated flags contain bit 2; the server
reserves 64 KiB for envelope overhead below the 16 MiB line cap. Receivers fetch
and verify the full entry instead of treating the smaller envelope as full evidence.


## Signed checkpoints (slice 2a)

These protocol requirements extend v2 without changing the 119-byte record. They
specify the target protocol; checkpoint codec availability alone does not enable
the database writer or the rollout command.

A checkpoint statement is exactly the concatenation below. All integers are big
endian; timestamps are signed Unix microseconds, with no presence framing:

```
ASCII("OMP-AUDIT-CHECKPOINT\0V1\0")
stream_id          16 raw UUID bytes
epoch               4 bytes, positive u32
seq                 8 bytes, positive u64 limited to PostgreSQL bigint
covered_seq         8 bytes, u64, exactly seq - 1
covered_chain_hash 32 bytes
issued_at           8 bytes, signed i64 Unix microseconds
kid_count           1 byte, exactly 1 or 2
kids               16 bytes per kid, in signature order
```

There are no trailing bytes. `kid` is the first 16 bytes of SHA-256 of the raw
32-byte Ed25519 public key. A normal checkpoint has one kid, the current key. A
handover has two distinct kids, old first and new second. Each signature is the
64-byte RFC 8032 Ed25519 signature of the entire exact statement, without an
additional prehash or context. Concatenated signatures follow kid order.

`summary_hash = SHA256(ASCII("OMP-AUDIT-CHECKPOINT-SUMMARY\0V1\0") || statement || signatures)`.

The checkpoint record has kind 3, flags zero, zero row identity, zero entry hash,
and the statement's stream, epoch, seq and issued_at. The statement covers the
held chain hash at `seq - 1`. The ordinary v2 chain hash commits to this record
and therefore to both the statement and its signatures. No additional timestamp
is authenticated. Signature byte lengths MUST equal `kid_count * 64`.

The SQL boundary MUST validate the enabled flag, running status, absent pending
epoch and live incarnation under the state-row lock for every checkpoint append,
including handover. It MUST recompute summary and chain hashes and bind all
statement fields to locked state. Ordinary `seal_batch` MUST reject two-kid
statements; only atomic key rotation may append a handover. PostgreSQL does not
verify Ed25519. The writer MUST verify its own signatures before submitting;
verifiers and receivers MUST verify every signature independently. A valid chain
digest with a bad signature is invalid evidence.

### Checkpoint JSON envelope

The common envelope fields are unchanged, with `kind: "checkpoint"`. There is
no `summary_fields`, `full` or `epoch_summary`. A `checkpoint` object contains:

- `statement`: exact statement bytes as unpadded base64url.
- `kids`: unpadded base64url 16-byte kids in statement order.
- `signatures`: unpadded base64url 64-byte signatures in that order.
- `stream_id`, `epoch`, `seq`, `covered_seq`, `covered_chain_hash`, `issued_at`:
  decoded projections of the statement. UUID, lower-case hex hash and RFC 3339
  timestamp use the common envelope conventions.

Receivers MUST reject padding, noncanonical base64url, wrong counts, duplicate
kids and extra or missing binary bytes. They MUST check every decoded projection
against the signed statement, then check the statement stream, epoch, seq and
issued_at against the enclosing record. `covered_seq` MUST be `seq - 1`, and
`covered_chain_hash` MUST equal the locally held predecessor. JSON numbers MUST
be decoded losslessly; booleans are not numbers. A statement transplanted into
another record is invalid even when its Ed25519 signature is valid.

### Receiver enrollment and key authority

A receiver MUST pin stream id and explicitly approve the currently active key
from the TLS-authenticated `/.well-known/omp-audit-keys.json` response, confirmed
out of band. The response is a JWK set; each key has `kty: "OKP"`, `crv:
"Ed25519"`, raw-public-key `x`, the derived `kid`, `active_from_seq` and
`retired_at_seq`. Publishing a key does not confer authority. Retired keys remain
published solely for verifying their historical range.

Enrollment is forward-only by default. Its approved anchor MUST be a checkpoint
at or after the pinned key's `active_from_seq`, signed by that key. A receiver
MUST track each key's inclusive authority interval. A normal checkpoint outside
that interval is invalid. A verified handover requires both signatures, closes
the old key's interval at the handover seq and opens the new key's interval at
that same seq. The new key's signature at its initial handover is permitted;
there is no authority to sign any earlier record. The old key cannot authorize
any subsequent checkpoint or handover.

To verify older history, a receiver MAY walk backwards through authenticated,
dual-signed handovers: an already pinned new key authenticates the old key for
its historical interval, recursively. Historical-key approval by a local operator
is an alternative. Merely downloading all published keys MUST NOT enroll them.
Unknown kids, out-of-range signatures or suspected compromise require explicit
local key approval; automatic handover is not compromise recovery.

Approving a chain discontinuity, including restore or rebase, MUST NOT restore a
retired key's authority. The current approved keys remain authoritative, unless a
new explicit key approval changes that. Chain approval and key approval are
separate decisions, and old anchors and fork evidence MUST be retained.

Receivers MUST discard only identical duplicates. A different hash at any held
seq is a fork, including late deliveries and conflicts with an archived branch.
They MUST preserve and alert on both hashes; `seq <= tip` is never sufficient to
silently discard a record.

`internal/auditstream/testdata/checkpoint_vectors.json` contains ordinary and
handover statement, signature, summary, fixed-record, chain and JSON vectors.
The Go codec and stdlib-only Python checkpoint harness consume the same vectors.
The Python Ed25519 verifier also checks RFC 8032 section 7.1 test cases 1–3.
