#!/usr/bin/env python3
"""Independent stdlib-only reference harness. Not independent security evidence.
Usage: python3 reference_verify.py START_SEQ START_HASH END_SEQ END_HASH < file
Anchors must come from a trusted channel; this tool does not authenticate them.
"""
import hashlib
import json
import re
import struct
import sys


def hx(s, n):
    return isinstance(s, str) and re.fullmatch('[0-9a-f]{%d}' % (2*n), s) is not None


def verify(stream, start, previous, end, final):
    assert 0 <= start <= end <= 2**64-1 and end-start <= 1_000_000
    assert hx(previous, 32) and hx(final, 32)
    assert start != 0 or previous == '00'*32
    sequence = start
    for _ in range(1_000_001):
        line = stream.readline(1025)
        if not line:
            assert sequence == end and previous == final
            return
        assert len(line) <= 1024 and line.endswith(b'\n')
        e = json.loads(line)
        assert list(e) == ['record', 'previous', 'hash']
        r = e['record']
        assert list(r) == ['version', 'sequence', 'event_id', 'actor_id', 'correlation_id', 'kind', 'class']
        assert all(type(r[k]) is int for k in ('version', 'sequence', 'kind', 'class'))
        assert r['version'] == 1 and r['sequence'] == sequence+1 <= end
        assert 1 <= r['kind'] <= 4 and 1 <= r['class'] <= 4
        assert all(hx(r[k], 16) for k in ('event_id', 'actor_id', 'correlation_id'))
        assert e['previous'] == previous and hx(e['hash'], 32)
        assert json.dumps(e, separators=(',', ':')).encode()+b'\n' == line
        record = struct.pack('>BQ', 1, r['sequence'])
        record += bytes.fromhex(r['event_id']+r['actor_id']+r['correlation_id'])
        record += bytes([r['kind'], r['class']])
        digest = hashlib.sha256(b'OMP-AUDIT-EVIDENCE\0CHAIN\0V1\0'+bytes.fromhex(previous)+record).hexdigest()
        assert digest == e['hash']
        previous, sequence = digest, r['sequence']
    raise ValueError('limit')


if __name__ == '__main__':
    try:
        verify(sys.stdin.buffer, int(sys.argv[1]), sys.argv[2], int(sys.argv[3]), sys.argv[4])
    except Exception:
        # Never include input, arbitrary parser errors, claims or I/O messages.
        sys.stderr.write('evidence: verification failed\n')
        sys.exit(1)
    print('verified against supplied anchors')
