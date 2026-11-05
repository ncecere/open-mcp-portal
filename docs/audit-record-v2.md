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
summary is kind-specific and will be specified with recovery/checkpoint support;
slice 1a accepts only entries, rather than pretending to validate those summaries.

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
