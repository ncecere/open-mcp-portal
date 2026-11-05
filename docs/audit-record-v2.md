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
summary is kind-specific: epoch starts are specified below; checkpoints remain
reserved and are not accepted by the sealing boundary.

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
A different hash at an already held sequence MUST alert and preserve both hashes.
An unsigned tip MUST NOT replace trusted local state. The Python `Receiver`
harness implements these rules; it does not define a delivery API.

SQL derives epoch declarations from locked state, stores them in `epoch_pending`,
and recomputes both summary and chain hashes itself. `seal_batch('epoch', …)`
requires a pending rebase marker and a matching summary hash. Runtime cannot
prepare an epoch or choose an incarnation, predecessor, gap, timestamp or epoch.
Automatic timeline transitions use the same internal encoding and append primitive.
