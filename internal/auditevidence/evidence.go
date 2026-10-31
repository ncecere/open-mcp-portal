// Package auditevidence is an unwired audit export/verification experiment.
// It is not an authorization boundary or a database delivery mechanism.
package auditevidence

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
)

const Version uint8 = 1
const MaxRecords uint64 = 1_000_000

var (
	ErrRecord = errors.New("evidence: invalid record")
	ErrChain  = errors.New("evidence: chain mismatch")
	ErrLimit  = errors.New("evidence: limit exceeded")
	ErrRead   = errors.New("evidence: read failed")
	ErrWrite  = errors.New("evidence: write failed")
	ErrSource = errors.New("evidence: source failed")
)

// Record is a CLOSED projection, not audit.Entry. IDs are lowercase 16-byte
// hex (all-zero means absent); they remain personal/pseudonymous data.
// Kind: 1=user, 2=API key, 3=system, 4=automation token.
// Class: 1=authentication, 2=configuration, 3=authorization, 4=lifecycle.
// These experimental categories require parent review and an explicit mapping.
// There is intentionally no free-form action, target, metadata or request ID.
type Record struct {
	Version       uint8  `json:"version"`
	Sequence      uint64 `json:"sequence"`
	EventID       string `json:"event_id"`
	ActorID       string `json:"actor_id"`
	CorrelationID string `json:"correlation_id"`
	Kind          uint8  `json:"kind"`
	Class         uint8  `json:"class"`
}

type Envelope struct {
	Record   Record `json:"record"`
	Previous string `json:"previous"`
	Hash     string `json:"hash"`
}

func validHex(s string, n int) bool {
	if len(s) != n*2 {
		return false
	}
	for _, c := range []byte(s) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (r Record) validate() error {
	if r.Version != Version || r.Sequence == 0 || r.Kind < 1 || r.Kind > 4 || r.Class < 1 || r.Class > 4 || !validHex(r.EventID, 16) || !validHex(r.ActorID, 16) || !validHex(r.CorrelationID, 16) {
		return ErrRecord
	}
	return nil
}

// Canonical is a custom fixed binary format, NOT RFC8785 or JSON hashing.
// v:u8, sequence:u64 big endian, three raw 16-byte IDs, kind:u8, class:u8.
func Canonical(r Record) ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	b := make([]byte, 59)
	b[0] = r.Version
	binary.BigEndian.PutUint64(b[1:9], r.Sequence)
	for i, s := range []string{r.EventID, r.ActorID, r.CorrelationID} {
		v, _ := hex.DecodeString(s)
		copy(b[9+i*16:], v)
	}
	b[57], b[58] = r.Kind, r.Class
	return b, nil
}

func Seal(r Record, previous string) (Envelope, error) {
	b, err := Canonical(r)
	if err != nil {
		return Envelope{}, err
	}
	if !validHex(previous, 32) {
		return Envelope{}, ErrRecord
	}
	p, _ := hex.DecodeString(previous)
	h := sha256.New()
	_, _ = h.Write([]byte("OMP-AUDIT-EVIDENCE\x00CHAIN\x00V1\x00"))
	_, _ = h.Write(p)
	_, _ = h.Write(b)
	return Envelope{r, previous, hex.EncodeToString(h.Sum(nil))}, nil
}

// Anchor is supplied through a separately trusted channel. Start is the
// predecessor of the first expected record; End is the required final record.
// A zero sequence uses a zero hash. Neither anchor is authenticated here.
type Anchor struct {
	Sequence uint64
	Hash     string
}

type Verifier struct {
	current, end Anchor
	count        uint64
}

func NewVerifier(start, end Anchor) (*Verifier, error) {
	if !validHex(start.Hash, 32) || !validHex(end.Hash, 32) || end.Sequence < start.Sequence || end.Sequence-start.Sequence > MaxRecords || (start.Sequence == 0 && start.Hash != ZeroHash) || (end.Sequence == 0 && end.Hash != ZeroHash) {
		return nil, ErrRecord
	}
	return &Verifier{current: start, end: end}, nil
}

const ZeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Accept rejects ALL duplicate deliveries, even byte-identical retransmissions.
// State advances only on success. Callers must deduplicate outside this verifier.
func (v *Verifier) Accept(e Envelope) error {
	if v.count >= MaxRecords {
		return ErrLimit
	}
	if v.current.Sequence == math.MaxUint64 || e.Record.Sequence != v.current.Sequence+1 || e.Record.Sequence > v.end.Sequence || e.Previous != v.current.Hash {
		return ErrChain
	}
	sealed, err := Seal(e.Record, e.Previous)
	if err != nil {
		return err
	}
	if e.Hash != sealed.Hash {
		return ErrChain
	}
	v.current = Anchor{e.Record.Sequence, e.Hash}
	v.count++
	return nil
}

// Finish is mandatory: EOF alone cannot prove that a suffix was not removed.
func (v *Verifier) Finish() error {
	if v.current != v.end {
		return ErrChain
	}
	return nil
}

// Iterator returns io.EOF at completion. Implementations must honor ctx and
// produce bounded records without accumulating a range. Errors are sanitized.
type Iterator interface {
	Next(context.Context) (Envelope, error)
}
