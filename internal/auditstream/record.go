// Package auditstream implements the version-2 audit sealing protocol.
// Its canonical format is specified in docs/audit-record-v2.md.
package auditstream

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// Row is a lossless database projection. JSON columns retain numeric text tokens.
type Row struct {
	ID             int64           `json:"id"`
	OccurredAt     time.Time       `json:"occurred_at"`
	Action         string          `json:"action"`
	ActorKind      string          `json:"actor_kind"`
	ActorUserID    *uuid.UUID      `json:"actor_user_id"`
	TeamID         *uuid.UUID      `json:"team_id"`
	TargetType     string          `json:"target_type"`
	TargetID       string          `json:"target_id"`
	RequestID      string          `json:"request_id"`
	ActorTokenID   *uuid.UUID      `json:"actor_token_id"`
	BeforeState    json.RawMessage `json:"before_state"`
	AfterState     json.RawMessage `json:"after_state"`
	Metadata       json.RawMessage `json:"metadata"`
	ClientIP       string          `json:"client_ip"`
	ActorTokenName *string         `json:"actor_token_name"`
	ActorTokenKind *string         `json:"actor_token_kind"`
	Txid           *string         `json:"txid"`
	SQLNullJSON    []string        `json:"sql_null_json"`
	RowUID         *uuid.UUID      `json:"row_uid"`
}

func scalar(b *bytes.Buffer, v []byte) {
	if v == nil {
		b.WriteByte(0)
		return
	}
	b.WriteByte(1)
	_ = binary.Write(b, binary.BigEndian, uint32(len(v)))
	b.Write(v)
}
func fixed(b *bytes.Buffer, v []byte) {
	if v == nil {
		b.WriteByte(0)
	} else {
		b.WriteByte(1)
		b.Write(v)
	}
}
func text(b *bytes.Buffer, v string) { scalar(b, []byte(v)) }
func optional(b *bytes.Buffer, v *string) {
	if v == nil {
		scalar(b, nil)
	} else {
		text(b, *v)
	}
}
func id(b *bytes.Buffer, v *uuid.UUID) {
	if v == nil {
		scalar(b, nil)
	} else {
		fixed(b, v[:])
	}
}
func i64(v int64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, uint64(v)); return b }

// SummaryBytes encodes every summary field, including explicit presence and length.
func SummaryBytes(r Row) []byte {
	var b bytes.Buffer
	fixed(&b, i64(r.OccurredAt.UnixMicro()))
	text(&b, r.Action)
	text(&b, r.ActorKind)
	id(&b, r.ActorUserID)
	id(&b, r.TeamID)
	text(&b, r.TargetType)
	text(&b, r.TargetID)
	text(&b, r.RequestID)
	id(&b, r.ActorTokenID)
	return b.Bytes()
}
func SummaryHash(r Row) [32]byte {
	return sha256.Sum256(append([]byte("OMP-AUDIT-SUMMARY\x00V1\x00"), SummaryBytes(r)...))
}

// CanonicalJSON consumes PostgreSQL jsonb text, preserving numeric scale. It
// also implements last-key-wins for reference fixtures supplied before jsonb.
func CanonicalJSON(raw []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON")
	}
	var b bytes.Buffer
	var emit func(any) error
	emit = func(v any) error {
		switch x := v.(type) {
		case nil:
			b.WriteString("null")
		case bool:
			b.WriteString(strconv.FormatBool(x))
		case json.Number:
			b.WriteString(x.String())
		case string:
			b.WriteByte('"')
			for _, c := range x {
				switch c {
				case '"', '\\':
					b.WriteByte('\\')
					b.WriteRune(c)
				default:
					if c < 32 {
						fmt.Fprintf(&b, "\\u%04x", c)
					} else {
						b.WriteRune(c)
					}
				}
			}
			b.WriteByte('"')
		case []any:
			b.WriteByte('[')
			for i, v := range x {
				if i > 0 {
					b.WriteByte(',')
				}
				if err := emit(v); err != nil {
					return err
				}
			}
			b.WriteByte(']')
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			b.WriteByte('{')
			for i, k := range keys {
				if i > 0 {
					b.WriteByte(',')
				}
				_ = emit(k)
				b.WriteByte(':')
				if err := emit(x[k]); err != nil {
					return err
				}
			}
			b.WriteByte('}')
		default:
			return fmt.Errorf("unsupported JSON")
		}
		return nil
	}
	if err := emit(v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// EntryBytes adds full fields. A nil RawMessage denotes SQL NULL; JSON null is
// the nonnil token "null". The SQL projection must preserve this distinction.
func EntryBytes(r Row) ([]byte, error) {
	var b bytes.Buffer
	b.Write(SummaryBytes(r))
	for _, raw := range []json.RawMessage{r.BeforeState, r.AfterState, r.Metadata} {
		if raw == nil {
			scalar(&b, nil)
			continue
		}
		v, err := CanonicalJSON(raw)
		if err != nil {
			return nil, err
		}
		scalar(&b, v)
	}
	text(&b, r.ClientIP)
	optional(&b, r.ActorTokenName)
	optional(&b, r.ActorTokenKind)
	optional(&b, r.Txid)
	return b.Bytes(), nil
}
func EntryHash(r Row) ([32]byte, error) {
	b, err := EntryBytes(r)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append([]byte("OMP-AUDIT-ENTRY\x00V1\x00"), b...)), nil
}
func Genesis(stream uuid.UUID) [32]byte {
	return sha256.Sum256(append([]byte("OMP-AUDIT-EVIDENCE\x00GENESIS\x00V2\x00"), stream[:]...))
}

// Record is the bounded seal_batch input. Stream, epoch, time and predecessor
// come from locked state and the audit row, never from caller assertions in SQL.
type Record struct {
	AuditID  int64      `json:"audit_id"`
	Seq      int64      `json:"seq"`
	Kind     string     `json:"kind"`
	Flags    uint8      `json:"flags"`
	RowUID   *uuid.UUID `json:"row_uid"`
	LegacyID *int64     `json:"legacy_id"`
	Summary  string     `json:"summary_hash"`
	Entry    string     `json:"entry_hash"`
	Chain    string     `json:"chain_hash"`
}

func RecordBytes(stream uuid.UUID, epoch uint32, seq int64, flags uint8, r Row, sh, eh [32]byte) []byte {
	var b bytes.Buffer
	b.Write([]byte{2, 1, flags})
	b.Write(stream[:])
	_ = binary.Write(&b, binary.BigEndian, epoch)
	b.Write(i64(seq))
	if r.RowUID != nil {
		b.Write(r.RowUID[:])
	} else {
		b.Write(bytes.Repeat([]byte{255}, 8))
		b.Write(i64(r.ID))
	}
	b.Write(i64(r.OccurredAt.UnixMicro()))
	b.Write(sh[:])
	b.Write(eh[:])
	return b.Bytes()
}
func NewRecord(stream uuid.UUID, epoch uint32, seq int64, previous [32]byte, r Row) (Record, [32]byte, error) {
	sh := SummaryHash(r)
	eh, err := EntryHash(r)
	if err != nil {
		return Record{}, [32]byte{}, err
	}
	flags := uint8(0)
	raw, err := json.Marshal(r)
	if err != nil {
		return Record{}, [32]byte{}, err
	}
	// Reserve 64 KiB for bounded envelope/summary fields. No full profile
	// record at or above the protocol limit is ever silently downgraded.
	if len(raw) > (16<<20)-(64<<10) {
		flags = 2
	}
	b := append([]byte("OMP-AUDIT-EVIDENCE\x00CHAIN\x00V2\x00"), previous[:]...)
	b = append(b, RecordBytes(stream, epoch, seq, flags, r, sh, eh)...)
	ch := sha256.Sum256(b)
	rec := Record{Flags: flags, AuditID: r.ID, Seq: seq, Kind: "entry", RowUID: r.RowUID, Summary: hex.EncodeToString(sh[:]), Entry: hex.EncodeToString(eh[:]), Chain: hex.EncodeToString(ch[:])}
	if r.RowUID == nil {
		rec.LegacyID = &r.ID
	}
	return rec, ch, nil
}
