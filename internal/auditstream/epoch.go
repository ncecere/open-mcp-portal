package auditstream

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"github.com/google/uuid"
	"time"
)

// EpochSummary is the authenticated recovery declaration, independent of JSON spelling.
type EpochSummary struct {
	PreviousEpoch       uint32 `json:"previous_epoch"`
	PredecessorSeq      int64  `json:"predecessor_seq"`
	PredecessorHash     string `json:"predecessor_hash"`
	Reason              string `json:"reason"`
	OldSystemIdentifier string `json:"old_system_identifier"`
	OldTimeline         int64  `json:"old_timeline"`
	NewSystemIdentifier string `json:"new_system_identifier"`
	NewTimeline         int64  `json:"new_timeline"`
	GapFrom             *int64 `json:"gap_from"`
	GapTo               *int64 `json:"gap_to"`
}

func EpochSummaryHash(e EpochSummary) [32]byte {
	var b bytes.Buffer
	b.WriteString("OMP-AUDIT-EPOCH\x00V1\x00")
	_ = binary.Write(&b, binary.BigEndian, e.PreviousEpoch)
	b.Write(i64(e.PredecessorSeq))
	h, _ := hex.DecodeString(e.PredecessorHash)
	b.Write(h)
	text(&b, e.Reason)
	text(&b, e.OldSystemIdentifier)
	b.Write(i64(e.OldTimeline))
	text(&b, e.NewSystemIdentifier)
	b.Write(i64(e.NewTimeline))
	for _, v := range []*int64{e.GapFrom, e.GapTo} {
		if v == nil {
			fixed(&b, nil)
		} else {
			fixed(&b, i64(*v))
		}
	}
	return sha256.Sum256(b.Bytes())
}

// EpochRecordBytes encodes the fixed envelope for a recovery declaration.
func EpochRecordBytes(stream uuid.UUID, epoch uint32, seq int64, at time.Time, summary [32]byte) []byte {
	var b bytes.Buffer
	b.Write([]byte{2, 2, 0})
	b.Write(stream[:])
	_ = binary.Write(&b, binary.BigEndian, epoch)
	b.Write(i64(seq))
	b.Write(make([]byte, 16))
	b.Write(i64(at.UnixMicro()))
	b.Write(summary[:])
	b.Write(make([]byte, 32))
	return b.Bytes()
}
