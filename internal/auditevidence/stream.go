package auditevidence

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"strconv"
)

// MaxLine bounds one wire record including its required LF terminator.
const MaxLine = 1024

type Format uint8

const (
	NDJSON Format = iota + 1
	CSV
)

var csvHeader = []string{"version", "sequence", "event_id", "actor_id", "correlation_id", "kind", "class", "previous", "hash"}

// Export processes one record at a time. Errors may leave a partial export;
// discard it. It checks record integrity, not range completeness (use Verify).
// Context cannot interrupt a blocked arbitrary io.Writer or io.Reader: callers
// must supply deadline-aware I/O. No callbacks run under authority locks here.
func Export(ctx context.Context, w io.Writer, src Iterator, f Format, limit uint64) error {
	if limit == 0 || limit > MaxRecords {
		return ErrLimit
	}
	if f != NDJSON && f != CSV {
		return ErrRecord
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if f == CSV {
		if err := writeCSV(w, csvHeader); err != nil {
			return err
		}
	}
	for n := uint64(0); ; n++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		e, err := src.Next(ctx)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return ErrSource
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if n >= limit {
			return ErrLimit
		}
		sealed, err := Seal(e.Record, e.Previous)
		if err != nil {
			return err
		}
		if sealed.Hash != e.Hash {
			return ErrChain
		}
		if f == NDJSON {
			b, _ := json.Marshal(e)
			b = append(b, '\n')
			if err := write(w, b); err != nil {
				return err
			}
		} else {
			r := e.Record
			row := []string{strconv.Itoa(int(r.Version)), strconv.FormatUint(r.Sequence, 10), r.EventID, r.ActorID, r.CorrelationID, strconv.Itoa(int(r.Kind)), strconv.Itoa(int(r.Class)), e.Previous, e.Hash}
			if err := writeCSV(w, row); err != nil {
				return err
			}
		}
	}
}
func write(w io.Writer, b []byte) error {
	n, err := w.Write(b)
	if err != nil || n != len(b) {
		return ErrWrite
	}
	return nil
}
func writeCSV(w io.Writer, row []string) error {
	var b bytes.Buffer
	c := csv.NewWriter(&b)
	if c.Write(row) != nil {
		return ErrWrite
	}
	c.Flush()
	if c.Error() != nil {
		return ErrWrite
	}
	return write(w, b.Bytes())
}

// Reader accepts only the exact version-1 JSON serialization emitted by Export:
// no extra fields, duplicate keys, alternative numeric spellings or whitespace.
// Its private buffer is bounded independently of hostile input line length.
type Reader struct{ r *bufio.Reader }

func NewReader(r io.Reader) *Reader { return &Reader{bufio.NewReaderSize(r, MaxLine)} }
func (r *Reader) Next(ctx context.Context) (Envelope, error) {
	if err := ctx.Err(); err != nil {
		return Envelope{}, err
	}
	b, err := r.r.ReadSlice('\n')
	if err == io.EOF && len(b) == 0 {
		return Envelope{}, io.EOF
	}
	if err == bufio.ErrBufferFull || len(b) > MaxLine {
		return Envelope{}, ErrLimit
	}
	if err != nil {
		return Envelope{}, ErrRead
	}
	if err := ctx.Err(); err != nil {
		return Envelope{}, err
	}
	var e Envelope
	if json.Unmarshal(b[:len(b)-1], &e) != nil {
		return Envelope{}, ErrRecord
	}
	canonical, _ := json.Marshal(e)
	if !bytes.Equal(b[:len(b)-1], canonical) {
		return Envelope{}, ErrRecord
	}
	sealed, err := Seal(e.Record, e.Previous)
	if err != nil {
		return Envelope{}, err
	}
	if sealed.Hash != e.Hash {
		return Envelope{}, ErrChain
	}
	return e, nil
}

// Verify is the incremental reference library harness for NDJSON. Both anchors
// must be caller-trusted. It rejects extra records and a missing final newline.
func Verify(ctx context.Context, r io.Reader, start, end Anchor) error {
	v, err := NewVerifier(start, end)
	if err != nil {
		return err
	}
	src := NewReader(r)
	for {
		e, err := src.Next(ctx)
		if err == io.EOF {
			return v.Finish()
		}
		if err != nil {
			return err
		}
		if err = v.Accept(e); err != nil {
			return err
		}
	}
}
