# Audit evidence foundation (#38, unwired experiment)

`internal/auditevidence` has no runtime callers, database mapping or product
protocol commitment. Parent review is required before choosing this format.
It does not implement #38 acceptance, delivery, export authorization or retention.
Existing audit writers, identity signing and purge behavior are unchanged.

## Closed projection and privacy

Version 1 includes only version, nonzero uint64 sequence, event/actor/correlation
IDs (each exactly 16 bytes encoded as 32 lowercase hex characters), and two
one-byte enumerations: actor kind (user/API key/system/automation token) and
coarse event class (authentication/configuration/authorization/lifecycle).
Zero IDs represent absence. Event identity uniqueness is a future producer
obligation, not checked across a range here. Sequence is a protocol number,
**not audit_log.id**, a transaction ID or an assertion about commit order.
No timestamps or arbitrary strings are accepted. Categories have no automatic
mapping from existing actions; unsupported actions must not be silently dropped.
The identifiers must be reviewed opaque IDs, not hex-encoded secrets/payloads.
The type prevents arbitrary fields, not malicious semantic misuse of IDs.

There is deliberately no audit.Entry adapter: metadata/maps, snapshots,
captured payloads, email/private contacts, token names/kinds, credentials,
ciphers/hints, client IP, request claims and free-form error messages cannot
be projected implicitly. Opaque actor and correlation IDs are still personal /
pseudonymous data, NOT anonymization. Future integration requires export
permission/filter/tenant isolation review, data minimization, retention and
privacy review (including linkability and destination access/deletion policy).
Package errors are fixed codes; arbitrary iterator/I/O/parser errors are not
wrapped or echoed. Context errors are standard cancellation/deadline errors.

## Experimental version-1 bytes

Canonical record bytes are exactly 59 bytes: version u8, sequence u64 big-endian,
raw event ID (16), raw actor ID (16), raw correlation ID (16), kind u8, class u8.
This is a custom binary encoding, **not RFC8785**, and not a claim that arbitrary
encoding/json is canonical. No floats, optional fields, maps or concatenation
ambiguity. The envelope's predecessor and digest are 32-byte lowercase hex.

```
hash = SHA256(ASCII("OMP-AUDIT-EVIDENCE\0CHAIN\0V1\0")
              || raw_previous_32_bytes || canonical_record_59_bytes)
```

The version and explicit sequence are hashed; the predecessor binds the prefix.
A new stream starts at sequence 1 with a zero predecessor. Distinct stream
identity/domain allocation is a parent design gate: there is no tenant/stream
namespace, signer, off-host checkpoint or authentication in this experiment.
A caller may verify a suffix using its trusted predecessor sequence/digest and
trusted expected final sequence/digest. All duplicate deliveries, including
identical ones, are errors. Failed acceptance does not advance state. A changed
event at an already-seen sequence is never silently accepted. Finish is mandatory
and compares both final sequence and digest: without a trusted expected end,
truncation cannot be detected. Without trusted anchors, an attacker can rewrite
all history. Even trusted anchors do not prove truthful events or completeness
relative to database commits, or prevent a producer from inventing events.

## Streaming and wire policy

Export pulls an iterator and writes one envelope at a time. Both explicit record
limits and anchors are capped at 1,000,000 records per invocation (split larger
ranges with separately trusted anchors). Memory does not grow with range size.
Canonical NDJSON is exactly encoding/json's serialization of the closed envelope
struct, followed by LF. Reader accepts only that spelling/key order, rejecting
unknown/duplicate fields, alternate integers, whitespace, invalid UTF-8 and
unknown versions. Lines are limited to 1024 bytes with a fixed-size buffer;
missing final LF is rejected, including a partial last record. On reader error,
discard the reader rather than trying to resynchronize. CSV is an export view,
not the hashed format or a supported verification input. Header order matches
version, sequence, event_id, actor_id, correlation_id, kind, class, previous, hash.

Spreadsheet-safe policy: every data cell is an unsigned decimal integer or
lowercase hex; formula prefixes (=,+,-,@), tabs, Unicode controls, embedded
newlines, commas and quotes are rejected, not escaped into a new identity.
encoding/csv handles the fixed header/row framing. This prevents formula
interpretation under ordinary CSV import, but spreadsheet numeric coercion may
lose precision or change hex-looking IDs: do not round-trip evidence through a
spreadsheet. Verify the original NDJSON, not spreadsheet output.

Source and I/O failures can leave a partial output; discard it. The exporter
checks individual record integrity but does NOT certify order/completeness;
use Verify with trusted anchors. Cancellation is checked between pull/write/read
operations, not preemption of arbitrary blocking Go I/O. The caller must provide
deadline-aware readers/writers/iterators and close its resources. No locks or
network connections are acquired here.

## Harness and evidence limits

Go `Verify` is the incremental NDJSON library harness. An independent Python
stdlib implementation is in `internal/auditevidence/testdata/reference_verify.py`;
pass START_SEQ START_HASH END_SEQ END_HASH and pipe NDJSON on stdin. Both require
externally trusted anchors. Golden canonical/hash/wire vectors use synthetic IDs;
fixtures and matching implementations are regression checks, not genuine
independent security evidence or a security audit.

Remaining #38 gates include a proven commit-order/gap/retention design, producer
mapping and stream identity, transactional sequencing/crash recovery, sink
backpressure/retry/deduplication, authenticated/off-host checkpoints and key
separation, authorization/PII review, retention interlock, sealed configuration,
real TLS syslog/OTLP/webhook failure recovery, API/UI/metrics and deployment tests.
Neither ID tailing nor txid/xmin correctness is assumed. No authority locks over
network I/O, cursor advancement, background loops, DDL, routes or runtime hooks
are introduced here.
