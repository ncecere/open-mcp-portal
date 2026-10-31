import copy
import io
import json
from pathlib import Path
import unittest
from reference_verify import verify


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.wire = Path(__file__).with_name('golden.ndjson').read_bytes()
        self.e = json.loads(self.wire)

    def check_wire(self, wire):
        verify(io.BytesIO(wire), 0, '00'*32, 1, self.e['hash'])

    def test_golden(self):
        self.check_wire(self.wire)

    def test_reject(self):
        for wire in (b'', self.wire[:-1], self.wire*2,
                     b' '+self.wire, b'x'*1025,
                     self.wire.replace(b'"version":1', b'"version":2'),
                     self.wire.replace(b'"kind":3', b'"kind":2'),
                     self.wire.replace(b'"version":1', b'"version":1,"version":1'),
                     self.wire.replace(b'"sequence":1', b'"sequence":true')):
            with self.assertRaises(Exception):
                self.check_wire(wire)

    def test_independent_hash_mutations(self):
        for field in ('event_id', 'actor_id', 'correlation_id'):
            e = copy.deepcopy(self.e)
            e['record'][field] = 'ff'*16
            with self.assertRaises(Exception):
                self.check_wire(json.dumps(e, separators=(',', ':')).encode()+b'\n')


if __name__ == '__main__':
    unittest.main()
