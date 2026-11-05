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

def fixed(v):
    return b'\0' if v is None else b'\1' + v


def summary_bytes(row):
    result = fixed(struct.pack('>q', row['occurred_at_unix_micros']))
    for name in ('action', 'actor_kind', 'actor_user_id', 'team_id',
                 'target_type', 'target_id', 'request_id', 'actor_token_id'):
        value = row.get(name)
        if name in ('actor_user_id', 'team_id', 'actor_token_id'):
            result += fixed(None if value is None else uuid.UUID(value).bytes)
        else:
            result += scalar(None if value is None else value.encode())
    return result


def entry_bytes(row):
    result = summary_bytes(row)
    # JSON columns contain stored jsonb text, or None for SQL NULL. The
    # nonnil text "null" therefore remains distinct from an absent column.
    for name in ('before_state', 'after_state', 'metadata'):
        value = row.get(name)
        encoded = None if value is None else canonical(json.loads(
            value, parse_int=Number, parse_float=Number)).encode()
        result += scalar(encoded)
    for name in ('client_ip', 'actor_token_name', 'actor_token_kind', 'txid'):
        value = row.get(name)
        result += scalar(None if value is None else value.encode())
    return result


def verify_entry(record, row):
    assert len(record) == 119 and record[:2] == b'\2\1'
    assert record[47:55] == struct.pack('>q', row['occurred_at_unix_micros'])
    assert record[55:87] == digest(b'OMP-AUDIT-SUMMARY\0V1\0', summary_bytes(row))
    assert record[87:119] == digest(b'OMP-AUDIT-ENTRY\0V1\0', entry_bytes(row))


def vector(raw):
    c = canonical(json.loads(raw, parse_int=Number, parse_float=Number))
    row = dict(occurred_at_unix_micros=1700000000123456, action='team.create',
               actor_kind='system', target_type='team', target_id='',
               request_id='é\n', after_state='null', metadata=raw, client_ip='')
    summary, full = summary_bytes(row), entry_bytes(row)
    sh = digest(b'OMP-AUDIT-SUMMARY\0V1\0', summary)
    eh = digest(b'OMP-AUDIT-ENTRY\0V1\0', full)
    stream = uuid.UUID('00112233-4455-4677-8899-aabbccddeeff').bytes
    genesis = digest(b'OMP-AUDIT-EVIDENCE\0GENESIS\0V2\0', stream)
    record = b'\2\1\0' + stream + struct.pack('>IQ', 1, 1) + b'\xff'*8 + struct.pack('>qq', 42, 1700000000123456) + sh + eh
    assert len(record) == 119
    verify_entry(record, row)
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
    for item in records:
        record, predecessor, claimed = item[:3]
        assert seq < end_seq
        assert len(record) == 119
        assert record[0] == 2 and record[1] in (1, 2) and record[2] & ~3 == 0
        assert record[3:19] == pinned
        epoch, number = struct.unpack('>IQ', record[19:31])
        assert epoch > 0 and number == seq + 1
        if record[1] == 2:
            assert len(item) == 4
            e = item[3]
            assert record[55:87] == epoch_summary(e)
            assert e['gap_from'] is None and e['predecessor_seq'] == seq
            assert bytes.fromhex(e['predecessor_hash']) == previous
            assert epoch == e['previous_epoch'] + 1
            assert record[31:47] == bytes(16) and record[87:119] == bytes(32)
        assert bytes.fromhex(predecessor) == previous
        calculated = digest(b'OMP-AUDIT-EVIDENCE\0CHAIN\0V2\0', previous + record)
        assert bytes.fromhex(claimed) == calculated
        previous, seq = calculated, number
    assert seq == end_seq and previous == final


def epoch_summary(e):
    result = struct.pack('>Iq', e['previous_epoch'], e['predecessor_seq'])
    predecessor = bytes.fromhex(e['predecessor_hash'])
    assert len(predecessor) == 32 and e['reason'] in ('timeline', 'rebase')
    result += predecessor + scalar(e['reason'].encode())
    for prefix in ('old', 'new'):
        result += scalar(e[prefix + '_system_identifier'].encode())
        result += struct.pack('>q', e[prefix + '_timeline'])
    for name in ('gap_from', 'gap_to'):
        result += fixed(None if e[name] is None else struct.pack('>q', e[name]))
    assert (e['gap_from'] is None) == (e['gap_to'] is None)
    if e['gap_from'] is not None:
        assert e['gap_from'] == e['predecessor_seq'] + 1 <= e['gap_to']
    return digest(b'OMP-AUDIT-EPOCH\0V1\0', result)


class Receiver:
    """Pinned stream-wide history. Approval preserves orphaned fork evidence.

    This is a protocol harness, not a product API or a persistence layer.
    """
    def __init__(self, stream_id, seq, anchor):
        self.pinned = uuid.UUID(stream_id).bytes
        self.held = {seq: bytes.fromhex(anchor)}
        self.tip = seq
        self.records = {}
        self.forks = []
        self.approvals = []

    def accept(self, record, previous, claimed, declaration=None, approve=False):
        assert len(record) == 119 and record[0] == 2
        assert record[3:19] == self.pinned
        assert record[1] in (1, 2) and record[2] & ~3 == 0
        epoch, seq = struct.unpack('>IQ', record[19:31])
        assert epoch > 0 and seq > 0
        previous, claimed = bytes.fromhex(previous), bytes.fromhex(claimed)
        assert len(previous) == len(claimed) == 32
        assert digest(b'OMP-AUDIT-EVIDENCE\0CHAIN\0V2\0', previous + record) == claimed
        if seq in self.held and self.held[seq] != claimed:
            self.forks.append((seq, self.held[seq], claimed, self.records.get(seq), record))
            if not approve:
                raise ValueError('fork; approval required')
        clean = seq == self.tip + 1 and self.held.get(seq-1) == previous
        if record[1] == 2:
            e = declaration
            assert record[2] == 0 and record[31:47] == bytes(16) and record[87:] == bytes(32)
            assert record[55:87] == epoch_summary(e)
            assert epoch == e['previous_epoch'] + 1
            assert bytes.fromhex(e['predecessor_hash']) == previous
            expected = e['predecessor_seq'] + 1 if e['gap_to'] is None else e['gap_to'] + 1
            assert seq == expected
            clean = clean and e['gap_from'] is None and e['predecessor_seq'] == seq-1
            if not clean:
                if not approve:
                    raise ValueError('discontinuity; approval required')
                self.approvals.append((record, dict(self.held), dict(self.records)))
        else:
            assert clean
        self.held[seq] = claimed
        self.records[seq] = record
        self.tip = seq
