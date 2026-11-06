package auditstream

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
)

type checkpointVector struct {
	Statement, Signatures, Summary, Record, Chain string
	PublicKeys                                    []string           `json:"public_keys"`
	Envelope                                      CheckpointEnvelope `json:"envelope"`
}

func checkpointFixture(t *testing.T, handover bool) (CheckpointStatement, []ed25519.PrivateKey, []byte, []byte, Envelope, map[CheckpointKID]CheckpointAuthority) {
	t.Helper()
	s := CheckpointStatement{Stream: uuid.MustParse("00112233-4455-4677-8899-aabbccddeeff"), Epoch: 2, Seq: 13, CoveredSeq: 12, IssuedAtMicros: 1700000000123456}
	for i := range s.CoveredHash {
		s.CoveredHash[i] = byte(i)
	}
	keys := []ed25519.PrivateKey{ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))}
	if handover {
		keys = append(keys, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)))
	}
	authorities := map[CheckpointKID]CheckpointAuthority{}
	for i, key := range keys {
		public := key.Public().(ed25519.PublicKey)
		kid := CheckpointKeyID(public)
		s.Kids = append(s.Kids, kid)
		a := CheckpointAuthority{Public: public, ActiveFromSeq: 1}
		if handover {
			if i == 0 {
				end := s.Seq
				a.RetiredAtSeq = &end
			} else {
				a.ActiveFromSeq = s.Seq
			}
		}
		authorities[kid] = a
	}
	raw, sigs, err := SignCheckpoint(s, keys...)
	if err != nil {
		t.Fatal(err)
	}
	sh, err := CheckpointSummaryHash(raw, sigs)
	if err != nil {
		t.Fatal(err)
	}
	record := CheckpointRecordBytes(s, sh)
	ch := sha256.Sum256(append(append([]byte("OMP-AUDIT-EVIDENCE\x00CHAIN\x00V2\x00"), s.CoveredHash[:]...), record...))
	e := Envelope{Record: Record{Seq: s.Seq, Kind: "checkpoint", Summary: hex.EncodeToString(sh[:]), Entry: hex.EncodeToString(make([]byte, 32)), Chain: hex.EncodeToString(ch[:])}, Stream: s.Stream, Epoch: s.Epoch, OccurredAt: time.UnixMicro(s.IssuedAtMicros).UTC()}
	return s, keys, raw, sigs, e, authorities
}

func TestCheckpointGolden(t *testing.T) {
	data, err := os.ReadFile("testdata/checkpoint_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []checkpointVector
	if err = json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 2 {
		t.Fatal("expected normal and handover vectors")
	}
	for i, v := range vectors {
		s, keys, raw, sigs, e, a := checkpointFixture(t, i == 1)
		sh, err := CheckpointSummaryHash(raw, sigs)
		if err != nil {
			t.Fatal(err)
		}
		cp, err := NewCheckpointEnvelope(raw, sigs)
		if err != nil {
			t.Fatal(err)
		}
		got := checkpointVector{Statement: hex.EncodeToString(raw), Signatures: hex.EncodeToString(sigs), Summary: e.Record.Summary, Record: hex.EncodeToString(CheckpointRecordBytes(s, sh)), Chain: e.Chain, Envelope: *cp}
		for _, k := range keys {
			got.PublicKeys = append(got.PublicKeys, hex.EncodeToString(k.Public().(ed25519.PublicKey)))
		}
		wantJSON, _ := json.Marshal(v)
		gotJSON, _ := json.Marshal(got)
		if !bytes.Equal(wantJSON, gotJSON) {
			t.Fatalf("vector %d mismatch", i)
		}
		if len(CheckpointRecordBytes(s, sh)) != 119 {
			t.Fatal("record length")
		}
		if err := VerifyCheckpoint(e, *cp, s.CoveredHash, a); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCheckpointMalformedStatement(t *testing.T) {
	_, _, raw, sigs, _, _ := checkpointFixture(t, false)
	for _, bad := range [][]byte{nil, raw[:len(raw)-1], append(bytes.Clone(raw), 0), bytes.Repeat([]byte{0}, len(raw))} {
		if _, err := ParseCheckpointStatement(bad); err == nil {
			t.Fatal("malformed statement accepted")
		}
	}
	const p = len(checkpointDomain)
	for _, offset := range []int{0, p + 16, p + 20, p + 28, p + 76} {
		bad := bytes.Clone(raw)
		bad[offset] ^= 0x80
		if offset == p+16 {
			clear(bad[offset : offset+4])
		}
		if _, err := ParseCheckpointStatement(bad); err == nil {
			t.Fatalf("malformed offset %d accepted", offset)
		}
	}
	s, err := ParseCheckpointStatement(raw)
	if err != nil {
		t.Fatal(err)
	}
	s.Kids = append(s.Kids, s.Kids[0])
	if _, err := s.Bytes(); err == nil {
		t.Fatal("duplicate kids")
	}
	for _, n := range []int{0, 63, 65, 128} {
		if _, err := CheckpointSummaryHash(raw, make([]byte, n)); err == nil {
			t.Fatalf("signature length %d", n)
		}
	}
	if _, err := CheckpointSummaryHash(raw, sigs); err != nil {
		t.Fatal(err)
	}
}

func TestCheckpointRejectsTransplantsAndBadSignatures(t *testing.T) {
	s, _, raw, sigs, e, a := checkpointFixture(t, false)
	cp, err := NewCheckpointEnvelope(raw, sigs)
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*Envelope, *CheckpointEnvelope){
		"stream":          func(e *Envelope, c *CheckpointEnvelope) { e.Stream[0] ^= 1 },
		"epoch":           func(e *Envelope, c *CheckpointEnvelope) { e.Epoch++ },
		"seq":             func(e *Envelope, c *CheckpointEnvelope) { e.Seq++ },
		"time":            func(e *Envelope, c *CheckpointEnvelope) { e.OccurredAt = e.OccurredAt.Add(time.Microsecond) },
		"flags":           func(e *Envelope, c *CheckpointEnvelope) { e.Flags = 1 },
		"identity":        func(e *Envelope, c *CheckpointEnvelope) { id := uuid.New(); e.RowUID = &id },
		"entry":           func(e *Envelope, c *CheckpointEnvelope) { e.Entry = "01" + e.Entry[2:] },
		"summary":         func(e *Envelope, c *CheckpointEnvelope) { e.Record.Summary = "01" + e.Record.Summary[2:] },
		"chain":           func(e *Envelope, c *CheckpointEnvelope) { e.Chain = "01" + e.Chain[2:] },
		"decoded stream":  func(e *Envelope, c *CheckpointEnvelope) { c.Stream[0] ^= 1 },
		"decoded covered": func(e *Envelope, c *CheckpointEnvelope) { c.CoveredSeq-- },
		"decoded time":    func(e *Envelope, c *CheckpointEnvelope) { c.IssuedAt = c.IssuedAt.Add(time.Nanosecond) },
		"base64 padding":  func(e *Envelope, c *CheckpointEnvelope) { c.Statement += "=" },
		"signature": func(e *Envelope, c *CheckpointEnvelope) {
			c.Signatures = append([]string(nil), c.Signatures...)
			c.Signatures[0] = "A" + c.Signatures[0][1:]
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			badE, badCP := e, *cp
			change(&badE, &badCP)
			if VerifyCheckpoint(badE, badCP, s.CoveredHash, a) == nil {
				t.Fatal("accepted")
			}
		})
	}
	// A bad signature with hashes recomputed is still unauthenticated evidence.
	bad := bytes.Clone(sigs)
	bad[0] ^= 1
	badCP, err := NewCheckpointEnvelope(raw, bad)
	if err != nil {
		t.Fatal(err)
	}
	sh, _ := CheckpointSummaryHash(raw, bad)
	e.Record.Summary = hex.EncodeToString(sh[:])
	ch := sha256.Sum256(append(append([]byte("OMP-AUDIT-EVIDENCE\x00CHAIN\x00V2\x00"), s.CoveredHash[:]...), CheckpointRecordBytes(s, sh)...))
	e.Chain = hex.EncodeToString(ch[:])
	if VerifyCheckpoint(e, *badCP, s.CoveredHash, a) == nil {
		t.Fatal("planted bad signature accepted")
	}
}

func TestCheckpointAuthorityRanges(t *testing.T) {
	s, _, raw, sigs, e, a := checkpointFixture(t, false)
	cp, _ := NewCheckpointEnvelope(raw, sigs)
	kid := s.Kids[0]
	original := a[kid]
	for _, change := range []func(CheckpointAuthority) CheckpointAuthority{
		func(k CheckpointAuthority) CheckpointAuthority { k.ActiveFromSeq = s.Seq + 1; return k },
		func(k CheckpointAuthority) CheckpointAuthority { n := s.Seq - 1; k.RetiredAtSeq = &n; return k },
		func(k CheckpointAuthority) CheckpointAuthority { k.Public = make([]byte, 32); return k },
	} {
		a[kid] = change(original)
		if VerifyCheckpoint(e, *cp, s.CoveredHash, a) == nil {
			t.Fatal("out-of-range key accepted")
		}
	}
	delete(a, kid)
	if VerifyCheckpoint(e, *cp, s.CoveredHash, a) == nil {
		t.Fatal("unknown kid accepted")
	}
}

func TestCheckpointSealedKeyBinding(t *testing.T) {
	box, err := secrets.New(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	kid, pub, cipher, err := GenerateCheckpointKey(box)
	if err != nil {
		t.Fatal(err)
	}
	key, err := OpenCheckpointKey(box, kid, pub, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(key)
	otherKid, otherPub, _, err := GenerateCheckpointKey(box)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCheckpointKey(box, otherKid, otherPub, cipher); err == nil {
		t.Fatal("transplanted ciphertext accepted")
	}
	// A valid AES envelope containing an inconsistent Ed25519 private key fails.
	key[63] ^= 1
	bad, err := box.Seal(key, CheckpointKeyAAD(kid))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenCheckpointKey(box, kid, pub, bad); err == nil {
		t.Fatal("inconsistent private key accepted")
	}
}
