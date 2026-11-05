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


class RecoveryTests(unittest.TestCase):
    def test_epochs_and_receiver(self):
        from reference_v2 import epoch_summary, Receiver
        vectors = json.loads((Path(__file__).parents[2] / 'auditstream/testdata/epoch_vectors.json').read_text())
        for v in vectors:
            e = v['summary']
            self.assertEqual(epoch_summary(e).hex(), v['hash'])
            r = bytes.fromhex(v['record'])
            recv = Receiver('00112233-4455-4677-8899-aabbccddeeff', 12, e['predecessor_hash'])
            if e['gap_from'] is not None:
                with self.assertRaises(ValueError):
                    recv.accept(r, e['predecessor_hash'], v['chain'], e)
                recv.accept(r, e['predecessor_hash'], v['chain'], e, approve=True)
                self.assertEqual(len(recv.approvals), 1)
            else:
                recv.accept(r, e['predecessor_hash'], v['chain'], e)
            wrong = Receiver('10112233-4455-4677-8899-aabbccddeeff', 12, e['predecessor_hash'])
            with self.assertRaises(AssertionError):
                wrong.accept(r, e['predecessor_hash'], v['chain'], e, approve=True)
            fork = Receiver('00112233-4455-4677-8899-aabbccddeeff', 12, e['predecessor_hash'])
            fork.held[13 if e['gap_from'] is None else 21] = bytes(32)
            with self.assertRaises(ValueError):
                fork.accept(r, e['predecessor_hash'], v['chain'], e)
            self.assertEqual(len(fork.forks), 1)

if __name__ == '__main__':
    unittest.main()
