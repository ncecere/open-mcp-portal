package auditstream

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
)

const checkpointDomain = "OMP-AUDIT-CHECKPOINT\x00V1\x00"
const checkpointSummaryDomain = "OMP-AUDIT-CHECKPOINT-SUMMARY\x00V1\x00"

// CheckpointKID is the first 16 bytes of SHA-256(public key).
type CheckpointKID [16]byte

func (k CheckpointKID) String() string { return base64.RawURLEncoding.EncodeToString(k[:]) }
func CheckpointKeyID(public ed25519.PublicKey) CheckpointKID {
	sum := sha256.Sum256(public)
	return CheckpointKID(sum[:16])
}
func CheckpointKeyAAD(k CheckpointKID) []byte { return []byte("audit_checkpoint_key:" + k.String()) }

// GenerateCheckpointKey returns public material and an AAD-bound sealed private
// key. A creation-race loser must discard these and open the database winner.
func GenerateCheckpointKey(box *secrets.Box) (CheckpointKID, ed25519.PublicKey, []byte, error) {
	if box == nil {
		return CheckpointKID{}, nil, nil, fmt.Errorf("checkpoint encryption box absent")
	}
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return CheckpointKID{}, nil, nil, err
	}
	defer clear(private)
	kid := CheckpointKeyID(pub)
	cipher, err := box.Seal(private, CheckpointKeyAAD(kid))
	return kid, pub, cipher, err
}

// OpenCheckpointKey checks both the AAD and the private/public relationship.
func OpenCheckpointKey(box *secrets.Box, kid CheckpointKID, pub ed25519.PublicKey, cipher []byte) (ed25519.PrivateKey, error) {
	if box == nil || len(pub) != ed25519.PublicKeySize || CheckpointKeyID(pub) != kid {
		return nil, fmt.Errorf("invalid checkpoint key")
	}
	private, err := box.Open(cipher, CheckpointKeyAAD(kid))
	if err != nil {
		return nil, err
	}
	if len(private) != ed25519.PrivateKeySize {
		clear(private)
		return nil, fmt.Errorf("invalid checkpoint private key")
	}
	derived := ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
	defer clear(derived)
	if !bytes.Equal(derived, private) || !bytes.Equal(derived[32:], pub) {
		clear(private)
		return nil, fmt.Errorf("checkpoint key mismatch")
	}
	return ed25519.PrivateKey(private), nil
}

// CheckpointStatement is the signed binary statement, never a JSON serialization.
// Sequence values are limited to PostgreSQL's positive signed bigint range.
type CheckpointStatement struct {
	Stream          uuid.UUID
	Epoch           uint32
	Seq, CoveredSeq int64
	CoveredHash     [32]byte
	IssuedAtMicros  int64
	Kids            []CheckpointKID
}

func (s CheckpointStatement) Bytes() ([]byte, error) {
	if s.Epoch == 0 || s.Seq <= 0 || s.CoveredSeq != s.Seq-1 || (len(s.Kids) != 1 && len(s.Kids) != 2) || (len(s.Kids) == 2 && s.Kids[0] == s.Kids[1]) {
		return nil, fmt.Errorf("invalid checkpoint statement")
	}
	var b bytes.Buffer
	b.WriteString(checkpointDomain)
	b.Write(s.Stream[:])
	_ = binary.Write(&b, binary.BigEndian, s.Epoch)
	b.Write(i64(s.Seq))
	b.Write(i64(s.CoveredSeq))
	b.Write(s.CoveredHash[:])
	b.Write(i64(s.IssuedAtMicros))
	b.WriteByte(byte(len(s.Kids)))
	for _, kid := range s.Kids {
		b.Write(kid[:])
	}
	return b.Bytes(), nil
}

func ParseCheckpointStatement(raw []byte) (CheckpointStatement, error) {
	var s CheckpointStatement
	const prefix = len(checkpointDomain)
	const fixed = prefix + 16 + 4 + 8 + 8 + 32 + 8 + 1
	if len(raw) != fixed+16 && len(raw) != fixed+32 {
		return s, fmt.Errorf("invalid checkpoint length")
	}
	if string(raw[:prefix]) != checkpointDomain {
		return s, fmt.Errorf("invalid checkpoint domain")
	}
	p := prefix
	copy(s.Stream[:], raw[p:p+16])
	p += 16
	s.Epoch = binary.BigEndian.Uint32(raw[p:])
	p += 4
	s.Seq = int64(binary.BigEndian.Uint64(raw[p:]))
	p += 8
	s.CoveredSeq = int64(binary.BigEndian.Uint64(raw[p:]))
	p += 8
	copy(s.CoveredHash[:], raw[p:p+32])
	p += 32
	s.IssuedAtMicros = int64(binary.BigEndian.Uint64(raw[p:]))
	p += 8
	n := int(raw[p])
	p++
	if n < 1 || n > 2 || len(raw) != p+n*16 {
		return s, fmt.Errorf("invalid checkpoint kid count")
	}
	for range n {
		s.Kids = append(s.Kids, CheckpointKID(raw[p:p+16]))
		p += 16
	}
	_, err := s.Bytes()
	return s, err
}

func CheckpointSummaryHash(statement, signatures []byte) ([32]byte, error) {
	s, err := ParseCheckpointStatement(statement)
	if err != nil {
		return [32]byte{}, err
	}
	if len(signatures) != len(s.Kids)*ed25519.SignatureSize {
		return [32]byte{}, fmt.Errorf("invalid checkpoint signatures length")
	}
	h := sha256.New()
	h.Write([]byte(checkpointSummaryDomain))
	h.Write(statement)
	h.Write(signatures)
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// SignCheckpoint verifies each locally produced signature before returning it.
func SignCheckpoint(s CheckpointStatement, private ...ed25519.PrivateKey) ([]byte, []byte, error) {
	raw, err := s.Bytes()
	if err != nil {
		return nil, nil, err
	}
	if len(private) != len(s.Kids) {
		return nil, nil, fmt.Errorf("checkpoint key count mismatch")
	}
	var signatures []byte
	for i, key := range private {
		if len(key) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("invalid checkpoint private key")
		}
		pub := key.Public().(ed25519.PublicKey)
		if CheckpointKeyID(pub) != s.Kids[i] {
			return nil, nil, fmt.Errorf("checkpoint kid mismatch")
		}
		sig := ed25519.Sign(key, raw)
		if !ed25519.Verify(pub, raw, sig) {
			return nil, nil, fmt.Errorf("checkpoint self verification failed")
		}
		signatures = append(signatures, sig...)
	}
	return raw, signatures, nil
}

// CheckpointRecordBytes has the same fixed 119-byte layout as all v2 records.
func CheckpointRecordBytes(s CheckpointStatement, summary [32]byte) []byte {
	raw := EpochRecordBytes(s.Stream, s.Epoch, s.Seq, time.UnixMicro(s.IssuedAtMicros).UTC(), summary)
	raw[1] = 3
	return raw
}

// CheckpointEnvelope repeats decoded values so receivers can reject any mismatch
// between a JSON projection and the exact signed bytes.
type CheckpointEnvelope struct {
	Statement   string    `json:"statement"`
	Kids        []string  `json:"kids"`
	Signatures  []string  `json:"signatures"`
	Stream      uuid.UUID `json:"stream_id"`
	Epoch       uint32    `json:"epoch"`
	Seq         int64     `json:"seq"`
	CoveredSeq  int64     `json:"covered_seq"`
	CoveredHash string    `json:"covered_chain_hash"`
	IssuedAt    time.Time `json:"issued_at"`
}

func NewCheckpointEnvelope(raw, signatures []byte) (*CheckpointEnvelope, error) {
	s, err := ParseCheckpointStatement(raw)
	if err != nil {
		return nil, err
	}
	if _, err = CheckpointSummaryHash(raw, signatures); err != nil {
		return nil, err
	}
	e := &CheckpointEnvelope{Statement: base64.RawURLEncoding.EncodeToString(raw), Stream: s.Stream, Epoch: s.Epoch, Seq: s.Seq, CoveredSeq: s.CoveredSeq, CoveredHash: hex.EncodeToString(s.CoveredHash[:]), IssuedAt: time.UnixMicro(s.IssuedAtMicros).UTC()}
	for i, kid := range s.Kids {
		e.Kids = append(e.Kids, kid.String())
		e.Signatures = append(e.Signatures, base64.RawURLEncoding.EncodeToString(signatures[i*64:(i+1)*64]))
	}
	return e, nil
}

func decodeCheckpointBase64(value string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, fmt.Errorf("invalid checkpoint base64url")
	}
	return raw, nil
}

// Decode rejects noncanonical base64url and all envelope-binding mismatches.
func (e CheckpointEnvelope) Decode() (CheckpointStatement, []byte, []byte, error) {
	var zero CheckpointStatement
	raw, err := decodeCheckpointBase64(e.Statement)
	if err != nil {
		return zero, nil, nil, err
	}
	s, err := ParseCheckpointStatement(raw)
	if err != nil {
		return zero, nil, nil, err
	}
	if e.Stream != s.Stream || e.Epoch != s.Epoch || e.Seq != s.Seq || e.CoveredSeq != s.CoveredSeq || e.CoveredHash != hex.EncodeToString(s.CoveredHash[:]) || !e.IssuedAt.Equal(time.UnixMicro(s.IssuedAtMicros)) || len(e.Kids) != len(s.Kids) || len(e.Signatures) != len(s.Kids) {
		return zero, nil, nil, fmt.Errorf("checkpoint envelope mismatch")
	}
	var signatures []byte
	for i, kid := range s.Kids {
		if e.Kids[i] != kid.String() {
			return zero, nil, nil, fmt.Errorf("checkpoint envelope kid mismatch")
		}
		sig, err := decodeCheckpointBase64(e.Signatures[i])
		if err != nil || len(sig) != 64 {
			return zero, nil, nil, fmt.Errorf("invalid checkpoint signature")
		}
		signatures = append(signatures, sig...)
	}
	return s, raw, signatures, nil
}

// CheckpointAuthority describes an explicitly approved key's inclusive range.
// A nil RetiredAtSeq is the only representation of current signing authority.
type CheckpointAuthority struct {
	Public        ed25519.PublicKey
	ActiveFromSeq int64
	RetiredAtSeq  *int64
}

// VerifyCheckpoint validates signatures, all envelope bindings and the committed
// hashes. Authorities must come from receiver enrollment, not an untrusted JWK
// response. For a handover the caller must supply both authenticated key ranges;
// this function does not grant authority merely because a key is published.
func VerifyCheckpoint(e Envelope, checkpoint CheckpointEnvelope, prev [32]byte, authorities map[CheckpointKID]CheckpointAuthority) error {
	s, raw, sigs, err := checkpoint.Decode()
	if err != nil {
		return err
	}
	if e.Kind != "checkpoint" || e.Flags != 0 || e.RowUID != nil || e.LegacyID != nil || e.Stream != s.Stream || e.Epoch != s.Epoch || e.Seq != s.Seq || !e.OccurredAt.Equal(checkpoint.IssuedAt) || s.CoveredHash != prev || e.Entry != hex.EncodeToString(make([]byte, 32)) {
		return fmt.Errorf("checkpoint record mismatch")
	}
	for i, kid := range s.Kids {
		a, ok := authorities[kid]
		if !ok || len(a.Public) != 32 || CheckpointKeyID(a.Public) != kid || a.ActiveFromSeq < 1 || s.Seq < a.ActiveFromSeq || (a.RetiredAtSeq != nil && s.Seq > *a.RetiredAtSeq) {
			return fmt.Errorf("checkpoint key outside authority range")
		}
		if len(s.Kids) == 2 && ((i == 0 && (a.RetiredAtSeq == nil || *a.RetiredAtSeq != s.Seq)) || (i == 1 && a.ActiveFromSeq != s.Seq)) {
			return fmt.Errorf("invalid checkpoint handover ranges")
		}
		if !ed25519.Verify(a.Public, raw, sigs[i*64:(i+1)*64]) {
			return fmt.Errorf("invalid checkpoint signature")
		}
	}
	summary, err := CheckpointSummaryHash(raw, sigs)
	if err != nil {
		return err
	}
	h := sha256.New()
	h.Write([]byte("OMP-AUDIT-EVIDENCE\x00CHAIN\x00V2\x00"))
	h.Write(prev[:])
	h.Write(CheckpointRecordBytes(s, summary))
	if e.Record.Summary != hex.EncodeToString(summary[:]) || e.Chain != hex.EncodeToString(h.Sum(nil)) {
		return fmt.Errorf("checkpoint digest mismatch")
	}
	return nil
}
