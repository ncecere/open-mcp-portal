import json
from pathlib import Path
import unittest
from reference_v2 import vector, verify_records

class V2Tests(unittest.TestCase):
    def test_shared_vectors(self):
        path = Path(__file__).parents[2] / 'auditstream/testdata/vectors.json'
        for v in json.loads(path.read_text()):
            self.assertEqual(vector(v['JSON']), v)
            args = ('00112233-4455-4677-8899-aabbccddeeff', 0, v['Genesis'], 1, v['Chain'])
            record = bytes.fromhex(v['Record'])
            good = (record, v['Genesis'], v['Chain'])
            verify_records(iter([good]), *args)
            for offset in (0, 1, 2, 3, 19, 30, 31, 47, 55, 87):
                bad = bytearray(record)
                bad[offset] ^= 128
                with self.assertRaises(AssertionError):
                    verify_records(iter([(bytes(bad), v['Genesis'], v['Chain'])]), *args)
            for records in ([], [good, good]):
                with self.assertRaises(AssertionError):
                    verify_records(iter(records), *args)
            with self.assertRaises(AssertionError):
                verify_records(iter([good]), '10112233-4455-4677-8899-aabbccddeeff', *args[1:])

if __name__ == '__main__':
    unittest.main()
