#!/usr/bin/env python3
"""Record-v2 reference verifier; does not replace the v1 wire verifier.
Run with the shared vector file. Anchors in fixtures are regression evidence only.
"""
import hashlib
import json
import struct
import sys
import uuid

class Number(str):
    pass

def canonical(v):
    if isinstance(v, Number):
        return str(v)
    if v is None:
        return 'null'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, str):
        return '"' + ''.join('\\' + c if c in '"\\' else '\\u%04x' % ord(c) if ord(c) < 32 else c for c in v) + '"'
    if isinstance(v, list):
        return '[' + ','.join(map(canonical, v)) + ']'
    return '{' + ','.join(canonical(k) + ':' + canonical(v[k]) for k in sorted(v, key=lambda k: k.encode())) + '}'

def scalar(v):
    return b'\0' if v is None else b'\1' + struct.pack('>I', len(v)) + v

def digest(domain, v):
    return hashlib.sha256(domain + v).digest()

def vector(raw):
    c = canonical(json.loads(raw, parse_int=Number, parse_float=Number))
    values = [struct.pack('>q', 1700000000123456), b'team.create', b'system', None, None, b'team', b'', 'é\n'.encode(), None]
    summary = b''.join(map(scalar, values))
    full = summary + b''.join(map(scalar, [None, b'null', c.encode(), b'', None, None, None]))
    sh = digest(b'OMP-AUDIT-SUMMARY\0V1\0', summary)
    eh = digest(b'OMP-AUDIT-ENTRY\0V1\0', full)
    stream = uuid.UUID('00112233-4455-4677-8899-aabbccddeeff').bytes
    genesis = digest(b'OMP-AUDIT-EVIDENCE\0GENESIS\0V2\0', stream)
    record = b'\2\1\0' + stream + struct.pack('>IQ', 1, 1) + b'\xff'*8 + struct.pack('>qq', 42, 1700000000123456) + sh + eh
    assert len(record) == 119
    chain = digest(b'OMP-AUDIT-EVIDENCE\0CHAIN\0V2\0', genesis + record)
    return dict(JSON=raw, Canonical=c, Summary=sh.hex(), Entry=eh.hex(), Record=record.hex(), Genesis=genesis.hex(), Chain=chain.hex())

if __name__ == '__main__':
    vectors = json.load(open(sys.argv[1]))
    for v in vectors:
        assert vector(v['JSON']) == v, v
    print('v2 vectors PASS:', len(vectors))


def verify_records(records, stream_id, start_seq, previous, end_seq, final):
    """Incremental binary-record harness with externally trusted pinned anchors.

    records yields (119-byte record, declared predecessor, declared digest).
    This harness defines no product wire envelope; pull APIs are a later slice.
    """
    pinned = uuid.UUID(stream_id).bytes
    assert 0 <= start_seq <= end_seq < 2**63
    assert end_seq-start_seq <= 1_000_000
    previous = bytes.fromhex(previous)
    final = bytes.fromhex(final)
    assert len(previous) == len(final) == 32
    if start_seq == 0:
        assert previous == digest(b'OMP-AUDIT-EVIDENCE\0GENESIS\0V2\0', pinned)
    seq = start_seq
    for record, predecessor, claimed in records:
        assert seq < end_seq
        assert len(record) == 119
        assert record[0] == 2 and record[1] in (1, 2, 3) and record[2] & ~3 == 0
        assert record[3:19] == pinned
        epoch, number = struct.unpack('>IQ', record[19:31])
        assert epoch > 0 and number == seq + 1
        if record[1] != 1:
            assert record[31:47] == bytes(16) and record[87:119] == bytes(32)
        assert bytes.fromhex(predecessor) == previous
        calculated = digest(b'OMP-AUDIT-EVIDENCE\0CHAIN\0V2\0', previous + record)
        assert bytes.fromhex(claimed) == calculated
        previous, seq = calculated, number
    assert seq == end_seq and previous == final
