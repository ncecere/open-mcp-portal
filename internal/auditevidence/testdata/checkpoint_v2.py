"""Checkpoint binary/envelope verifier. Authority is explicitly supplied locally.

Publication alone never grants authority. Callers must enroll from an approved
anchor and authenticate historical ranges through handovers or local approval.
"""
import base64
import hashlib
import re
import struct
import uuid
from datetime import datetime, timezone, timedelta
from ed25519_verify import verify

DOMAIN = b'OMP-AUDIT-CHECKPOINT\0V1\0'
SUMMARY = b'OMP-AUDIT-CHECKPOINT-SUMMARY\0V1\0'
CHAIN = b'OMP-AUDIT-EVIDENCE\0CHAIN\0V2\0'


def unbase64(value):
    assert isinstance(value, str) and '=' not in value
    raw = base64.b64decode(value + '='*((-len(value)) % 4), altchars=b'-_', validate=True)
    assert base64.urlsafe_b64encode(raw).decode().rstrip('=') == value
    return raw


def statement(raw):
    fixed = len(DOMAIN) + 16 + 4 + 8 + 8 + 32 + 8 + 1
    assert len(raw) in (fixed + 16, fixed + 32) and raw.startswith(DOMAIN)
    p = len(DOMAIN)
    stream = raw[p:p+16]
    epoch, seq, covered = struct.unpack('>Iqq', raw[p+16:p+36])
    previous = raw[p+36:p+68]
    micros, count = struct.unpack('>qB', raw[p+68:p+77])
    assert epoch > 0 and seq > 0 and covered == seq - 1
    assert count in (1, 2) and len(raw) == fixed + count*16
    kids = [raw[fixed+i*16:fixed+(i+1)*16] for i in range(count)]
    assert len(set(kids)) == count
    return stream, epoch, seq, covered, previous, micros, kids


def verify_checkpoint(record, checkpoint, previous, authorities):
    """authorities: kid -> (public bytes, inclusive first seq, last seq or None).

    Handover ranges must already have been authenticated by a receiver's walk
    through the dual-signed handover. This helper never approves unknown keys.
    """
    raw = unbase64(checkpoint['statement'])
    stream, epoch, seq, covered, prev, micros, kids = statement(raw)
    assert len(record) == 119 and record[:3] == b'\2\3\0'
    assert record[3:19] == stream and record[19:31] == struct.pack('>Iq', epoch, seq)
    assert record[31:47] == bytes(16) and record[47:55] == struct.pack('>q', micros)
    assert record[87:] == bytes(32) and prev == previous
    assert uuid.UUID(checkpoint['stream_id']).bytes == stream
    assert type(checkpoint['epoch']) is int and checkpoint['epoch'] == epoch
    assert type(checkpoint['seq']) is int and checkpoint['seq'] == seq
    assert type(checkpoint['covered_seq']) is int and checkpoint['covered_seq'] == covered
    assert checkpoint['covered_chain_hash'] == prev.hex()
    # datetime silently truncates sub-microsecond fractions. Reject any lost
    # precision instead of accepting a projection different from signed time.
    issued = checkpoint['issued_at']
    assert isinstance(issued, str)
    match = re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.(\d{1,9}))?(?:Z|[+-]\d{2}:\d{2})', issued)
    assert match is not None
    fraction = match.group(1) or ''
    assert not fraction[6:] or set(fraction[6:]) == {'0'}
    timestamp = datetime.fromisoformat(issued.replace('Z', '+00:00'))
    assert timestamp.tzinfo is not None
    assert timestamp == datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=micros)
    assert len(checkpoint['kids']) == len(checkpoint['signatures']) == len(kids)
    signatures = b''
    for i, kid in enumerate(kids):
        assert unbase64(checkpoint['kids'][i]) == kid
        signature = unbase64(checkpoint['signatures'][i])
        public, first, last = authorities[kid]
        assert hashlib.sha256(public).digest()[:16] == kid
        assert type(first) is int and 1 <= first <= seq
        assert last is None or (type(last) is int and seq <= last < 2**63)
        if len(kids) == 2:
            assert (last == seq) if i == 0 else (first == seq)
        assert verify(public, raw, signature)
        signatures += signature
    assert record[55:87] == hashlib.sha256(SUMMARY + raw + signatures).digest()
    return hashlib.sha256(CHAIN + previous + record).digest()
