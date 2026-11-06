import copy
import hashlib
import json
from pathlib import Path
import unittest
from checkpoint_v2 import statement, verify_checkpoint
from ed25519_verify import verify, P, L


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_section_7_1(self):
        # RFC 8032 section 7.1: TEST 1, TEST 2, TEST 3 (Ed25519).
        cases = [
            ('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
             'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f'
             'b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b'),
            ('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
             '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da'
             '085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00'),
            ('fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'af82',
             '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac'
             '18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a'),
        ]
        for public, message, sig in cases:
            public, message, sig = map(bytes.fromhex, (public, message, sig))
            self.assertTrue(verify(public, message, sig))
            self.assertFalse(verify(public, message + b'\0', sig))
            self.assertFalse(verify(public, message, sig[:32] + L.to_bytes(32, 'little')))
            self.assertFalse(verify(public, message, sig[:-1]))
        self.assertFalse(verify(P.to_bytes(32, 'little'), b'', bytes(64)))
        self.assertFalse(verify(b'\1' + bytes(31), b'', bytes(64)))


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.vectors = json.loads((Path(__file__).parents[2] / 'auditstream/testdata/checkpoint_vectors.json').read_text())

    def authority(self, v):
        kids = statement(bytes.fromhex(v['Statement']))[-1]
        return {kid: (bytes.fromhex(public), 13 if i else 1,
                      13 if len(kids) == 2 and i == 0 else None)
                for i, (kid, public) in enumerate(zip(kids, v['public_keys']))}

    def test_shared_normal_and_handover_vectors(self):
        for v in self.vectors:
            raw, sig = bytes.fromhex(v['Statement']), bytes.fromhex(v['Signatures'])
            self.assertEqual(hashlib.sha256(b'OMP-AUDIT-CHECKPOINT-SUMMARY\0V1\0' + raw + sig).hexdigest(), v['Summary'])
            previous = statement(raw)[4]
            chain = verify_checkpoint(bytes.fromhex(v['Record']), v['envelope'], previous, self.authority(v))
            self.assertEqual(chain.hex(), v['Chain'])

    def test_malformed_statements(self):
        raw = bytes.fromhex(self.vectors[0]['Statement'])
        for bad in (b'', raw[:-1], raw + b'\0', bytes(len(raw))):
            with self.assertRaises(AssertionError):
                statement(bad)
        for offset in (0, len(raw)-17):
            bad = bytearray(raw)
            bad[offset] ^= 128
            with self.assertRaises(AssertionError):
                statement(bytes(bad))
        handover = bytes.fromhex(self.vectors[1]['Statement'])
        with self.assertRaises(AssertionError):
            statement(handover[:-16] + handover[-32:-16])

    def test_transplanted_statement_and_unknown_or_retired_key(self):
        for v in self.vectors:
            record = bytearray(bytes.fromhex(v['Record']))
            previous = statement(bytes.fromhex(v['Statement']))[4]
            authority = self.authority(v)
            for offset in (2, 3, 19, 30, 31, 47, 55, 87):
                bad = bytearray(record)
                bad[offset] ^= 1
                with self.assertRaises(AssertionError):
                    verify_checkpoint(bytes(bad), v['envelope'], previous, authority)
            with self.assertRaises(KeyError):
                verify_checkpoint(bytes(record), v['envelope'], previous, {})
            kid = next(iter(authority))
            public, first, _ = authority[kid]
            for limits in ((public, first, 12), (public, 14, None)):
                bad = dict(authority)
                bad[kid] = limits
                with self.assertRaises(AssertionError):
                    verify_checkpoint(bytes(record), v['envelope'], previous, bad)
            for field, value in (('seq', 14), ('covered_seq', 11), ('epoch', True),
                                 ('issued_at', '2023-11-14T22:13:20.123457Z'),
                                 ('statement', v['envelope']['statement'] + '=')):
                bad = copy.deepcopy(v['envelope'])
                bad[field] = value
                with self.assertRaises(AssertionError):
                    verify_checkpoint(bytes(record), bad, previous, authority)


if __name__ == '__main__':
    unittest.main()
