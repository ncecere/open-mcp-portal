package auditevidence

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
)

func fixture(t *testing.T) Envelope {
	t.Helper()
	b, err := os.ReadFile("testdata/golden.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	var e Envelope
	if err = json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return e
}
func chain(t *testing.T, n int) []Envelope {
	t.Helper()
	e := fixture(t)
	out := make([]Envelope, 0, n)
	prev := ZeroHash
	for i := 1; i <= n; i++ {
		e.Record.Sequence = uint64(i)
		e, _ = Seal(e.Record, prev)
		out = append(out, e)
		prev = e.Hash
	}
	return out
}

type source struct {
	es  []Envelope
	n   int
	err error
}

func (s *source) Next(context.Context) (Envelope, error) {
	if s.n == len(s.es) {
		if s.err != nil {
			return Envelope{}, s.err
		}
		return Envelope{}, io.EOF
	}
	e := s.es[s.n]
	s.n++
	return e, nil
}
func anchors(es []Envelope) (Anchor, Anchor) {
	return Anchor{0, ZeroHash}, Anchor{es[len(es)-1].Record.Sequence, es[len(es)-1].Hash}
}
func TestGolden(t *testing.T) {
	e := fixture(t)
	b, err := Canonical(e.Record)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile("testdata/canonical.hex")
	if hex.EncodeToString(b) != strings.TrimSpace(string(want)) {
		t.Fatal("canonical vector")
	}
	sealed, err := Seal(e.Record, e.Previous)
	if err != nil || sealed != e {
		t.Fatal("hash vector", err)
	}
	var out bytes.Buffer
	if err = Export(context.Background(), &out, &source{es: []Envelope{e}}, NDJSON, 1); err != nil {
		t.Fatal(err)
	}
	wire, _ := os.ReadFile("testdata/golden.ndjson")
	if !bytes.Equal(wire, out.Bytes()) {
		t.Fatal("wire vector")
	}
}
func TestRoundTrips(t *testing.T) {
	es := chain(t, 100)
	start, end := anchors(es)
	for _, f := range []Format{NDJSON, CSV} {
		var out bytes.Buffer
		if err := Export(context.Background(), &out, &source{es: es}, f, 100); err != nil {
			t.Fatal(err)
		}
		if f == NDJSON {
			if err := Verify(context.Background(), &out, start, end); err != nil {
				t.Fatal(err)
			}
		} else {
			rows, err := csv.NewReader(&out).ReadAll()
			if err != nil || len(rows) != 101 || !reflect.DeepEqual(rows[0], csvHeader) {
				t.Fatal("csv", err)
			}
			if rows[1][2] != es[0].Record.EventID || rows[100][8] != end.Hash {
				t.Fatal("csv values")
			}
		}
	}
}
func TestChainRejections(t *testing.T) {
	original := chain(t, 3)
	start, end := anchors(original)
	cases := map[string]func([]Envelope) []Envelope{
		"missing":     func(e []Envelope) []Envelope { return append(e[:1], e[2:]...) },
		"duplicate":   func(e []Envelope) []Envelope { return append(e[:1], append([]Envelope{e[0]}, e[1:]...)...) },
		"reorder":     func(e []Envelope) []Envelope { e[0], e[1] = e[1], e[0]; return e },
		"mutate":      func(e []Envelope) []Envelope { e[1].Record.Class = 1; return e },
		"predecessor": func(e []Envelope) []Envelope { e[1].Previous = ZeroHash; return e },
		"hash":        func(e []Envelope) []Envelope { e[2].Hash = ZeroHash; return e },
		"truncate":    func(e []Envelope) []Envelope { return e[:2] },
		"rewrite": func(e []Envelope) []Envelope {
			p := ZeroHash
			for i := range e {
				e[i].Record.Class = 1
				e[i], _ = Seal(e[i].Record, p)
				p = e[i].Hash
			}
			return e
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			v, _ := NewVerifier(start, end)
			es := change(append([]Envelope(nil), original...))
			var err error
			for _, e := range es {
				if err = v.Accept(e); err != nil {
					break
				}
			}
			if err == nil {
				err = v.Finish()
			}
			if err == nil {
				t.Fatal("accepted")
			}
		})
	}
	v, _ := NewVerifier(start, end)
	if v.Accept(original[0]) != nil || v.Accept(original[0]) == nil || v.Accept(original[1]) != nil {
		t.Fatal("duplicate changed state")
	}
	different := original[1]
	different.Record.Class = 1
	different, _ = Seal(different.Record, different.Previous)
	if v.Accept(different) == nil {
		t.Fatal("different event at seen sequence")
	}
	// A trusted midstream predecessor supports bounded suffix verification.
	v, _ = NewVerifier(Anchor{1, original[0].Hash}, end)
	for _, e := range original[1:] {
		if err := v.Accept(e); err != nil {
			t.Fatal(err)
		}
	}
	if v.Finish() != nil {
		t.Fatal("suffix")
	}
}
func TestBoundariesAndHostileFields(t *testing.T) {
	base := fixture(t)
	for _, bad := range []string{"=SUM(A1)", "+1", "-1", "@cmd", "\t=1", "\r\nsecret-payload-sentinel", "\"a,b\"", "é", "\u202e", "\xff", strings.Repeat("a", 100000), strings.Repeat("A", 32)} {
		for field := 0; field < 3; field++ {
			e := base
			switch field {
			case 0:
				e.Record.EventID = bad
			case 1:
				e.Record.ActorID = bad
			case 2:
				e.Record.CorrelationID = bad
			}
			for _, f := range []Format{NDJSON, CSV} {
				var out bytes.Buffer
				err := Export(context.Background(), &out, &source{es: []Envelope{e}}, f, 1)
				if err == nil || strings.Contains(err.Error(), bad) || strings.Contains(out.String(), bad) {
					t.Fatal("unsafe field accepted or echoed")
				}
			}
		}
	}
	for _, mut := range []func(*Record){func(r *Record) { r.Version = 0 }, func(r *Record) { r.Version = 2 }, func(r *Record) { r.Sequence = 0 }, func(r *Record) { r.Kind = 0 }, func(r *Record) { r.Class = 255 }} {
		r := base.Record
		mut(&r)
		if _, err := Canonical(r); err == nil {
			t.Fatal("invalid accepted")
		}
	}
	r := base.Record
	r.Sequence = math.MaxUint64
	e, err := Seal(r, ZeroHash)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(Anchor{math.MaxUint64 - 1, ZeroHash}, Anchor{math.MaxUint64, e.Hash})
	if err != nil || v.Accept(e) != nil || v.Finish() != nil || v.Accept(e) == nil {
		t.Fatal("uint64 boundary", err)
	}
	for _, a := range []Anchor{{0, "bad"}, {0, base.Hash}, {MaxRecords + 1, ZeroHash}} {
		if _, err := NewVerifier(a, Anchor{0, ZeroHash}); err == nil {
			t.Fatal("anchor")
		}
	}
	if _, err := NewVerifier(Anchor{0, ZeroHash}, Anchor{MaxRecords + 1, ZeroHash}); err == nil {
		t.Fatal("count bound")
	}
}

type badWriter struct{ short bool }

func (w badWriter) Write(b []byte) (int, error) {
	if w.short {
		return len(b) - 1, nil
	}
	return 0, errors.New("secret-payload-sentinel")
}

type badReader struct{}

func (badReader) Read([]byte) (int, error) { return 0, errors.New("secret-payload-sentinel") }
func TestIOAndCancellation(t *testing.T) {
	es := chain(t, 2)
	ctx := context.Background()
	for _, f := range []Format{NDJSON, CSV} {
		for _, w := range []io.Writer{badWriter{}, badWriter{true}} {
			if err := Export(ctx, w, &source{es: es}, f, 2); err != ErrWrite {
				t.Fatal(err)
			}
		}
	}
	if err := Export(ctx, io.Discard, &source{err: errors.New("secret-payload-sentinel")}, NDJSON, 1); err != ErrSource {
		t.Fatal(err)
	}
	for _, limit := range []uint64{0, 1, MaxRecords + 1} {
		if err := Export(ctx, io.Discard, &source{es: es}, NDJSON, limit); err != ErrLimit {
			t.Fatal(err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	s := &source{es: es}
	if err := Export(cancelled, io.Discard, s, CSV, 1); err != context.Canceled || s.n != 0 {
		t.Fatal(err)
	}
	if _, err := NewReader(badReader{}).Next(ctx); err != ErrRead {
		t.Fatal(err)
	}
	if _, err := NewReader(strings.NewReader(strings.Repeat("x", MaxLine*10))).Next(ctx); err != ErrLimit {
		t.Fatal(err)
	}
	if _, err := NewReader(strings.NewReader("{}")).Next(ctx); err != ErrRead {
		t.Fatal(err)
	}
	if _, err := NewReader(strings.NewReader("")).Next(cancelled); err != context.Canceled {
		t.Fatal(err)
	}
}
func TestStrictWire(t *testing.T) {
	b, _ := os.ReadFile("testdata/golden.ndjson")
	s := string(b)
	for _, bad := range []string{strings.Replace(s, "\"version\":1", "\"version\":2", 1), strings.Replace(s, "\"version\":1", "\"version\":1,\"version\":1", 1), strings.Replace(s, "\"sequence\":1", "\"sequence\":1.0", 1), strings.Replace(s, "\"sequence\":1", "\"sequence\":18446744073709551616", 1), strings.Replace(s, "{", "{\"payload\":\"secret-payload-sentinel\",", 1), " " + s, strings.Replace(s, "01", "\\u00301", 1)} {
		_, err := NewReader(strings.NewReader(bad)).Next(context.Background())
		if err == nil || strings.Contains(err.Error(), "secret-payload-sentinel") {
			t.Fatal("wire accepted/echoed")
		}
	}
	start, end := anchors([]Envelope{fixture(t)})
	if Verify(context.Background(), strings.NewReader(""), start, end) == nil {
		t.Fatal("empty truncated")
	}
}

// Generated source checks backpressure without allocating a range.
type generated struct {
	next, last uint64
	previous   string
	record     Record
	writes     *uint64
}

func (s *generated) Next(context.Context) (Envelope, error) {
	if s.next == s.last {
		return Envelope{}, io.EOF
	}
	if *s.writes != s.next {
		return Envelope{}, ErrSource
	}
	s.next++
	s.record.Sequence = s.next
	e, _ := Seal(s.record, s.previous)
	s.previous = e.Hash
	return e, nil
}

type counter struct{ n uint64 }

func (c *counter) Write(b []byte) (int, error) { c.n++; return len(b), nil }
func TestStreamingBackpressure(t *testing.T) {
	w := &counter{}
	s := &generated{last: 10000, previous: ZeroHash, record: fixture(t).Record, writes: &w.n}
	if err := Export(context.Background(), w, s, NDJSON, 10000); err != nil || w.n != 10000 {
		t.Fatal(err, w.n)
	}
}
func FuzzReader(f *testing.F) {
	b, _ := os.ReadFile("testdata/golden.ndjson")
	f.Add(b)
	f.Add([]byte("{}\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := NewReader(bytes.NewReader(b)).Next(context.Background())
		if err == nil {
			a, err := Canonical(e.Record)
			if err != nil || len(a) != 59 {
				t.Fatal("accepted invalid")
			}
			sealed, _ := Seal(e.Record, e.Previous)
			if sealed != e {
				t.Fatal("integrity")
			}
		}
	})
}
func FuzzCanonical(f *testing.F) {
	f.Add(uint64(1), uint8(1), uint8(4))
	f.Fuzz(func(t *testing.T, seq uint64, kind, class uint8) {
		r := Record{Version, seq, strings.Repeat("00", 16), strings.Repeat("ff", 16), strings.Repeat("ab", 16), kind, class}
		a, err := Canonical(r)
		b, err2 := Canonical(r)
		if !bytes.Equal(a, b) || (err == nil) != (err2 == nil) {
			t.Fatal("nondeterministic")
		}
	})
}

// No source lookahead or write is permitted after cancellation at a boundary.
type cancellingSource struct {
	e      Envelope
	cancel context.CancelFunc
}

func (s cancellingSource) Next(context.Context) (Envelope, error) { s.cancel(); return s.e, nil }

type cancellingWriter struct {
	cancel context.CancelFunc
	n      int
}

func (w *cancellingWriter) Write(b []byte) (int, error) { w.n++; w.cancel(); return len(b), nil }
func TestCancellationBoundaries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var out bytes.Buffer
	if err := Export(ctx, &out, cancellingSource{fixture(t), cancel}, NDJSON, 1); err != context.Canceled || out.Len() != 0 {
		t.Fatal("post-pull cancellation", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	w := &cancellingWriter{cancel: cancel}
	s := &source{es: chain(t, 2)}
	if err := Export(ctx, w, s, NDJSON, 2); err != context.Canceled || s.n != 1 || w.n != 1 {
		t.Fatal("post-write cancellation", err)
	}
}
func TestTrustedAnchorsAndErrorBoundaries(t *testing.T) {
	es := chain(t, 2)
	start, end := anchors(es)
	v, _ := NewVerifier(Anchor{0, ZeroHash}, Anchor{0, ZeroHash})
	if v.Finish() != nil {
		t.Fatal("empty trusted range")
	}
	var out bytes.Buffer
	_ = Export(context.Background(), &out, &source{es: es}, NDJSON, 2)
	end.Hash = ZeroHash
	if Verify(context.Background(), bytes.NewReader(out.Bytes()), start, end) == nil {
		t.Fatal("untrusted end accepted")
	}
	v, _ = NewVerifier(Anchor{1, ZeroHash}, Anchor{2, es[1].Hash})
	if v.Accept(es[1]) == nil {
		t.Fatal("wrong predecessor anchor")
	}
	if err := Export(context.Background(), io.Discard, &source{}, Format(99), 1); err != ErrRecord {
		t.Fatal(err)
	}
	e := es[0]
	e.Hash = ZeroHash
	if err := Export(context.Background(), io.Discard, &source{es: []Envelope{e}}, NDJSON, 1); err != ErrChain {
		t.Fatal(err)
	}
	if _, err := Seal(es[0].Record, "bad"); err != ErrRecord {
		t.Fatal(err)
	}
	// Reader buffering is fixed even when the input never emits a newline.
	r := NewReader(strings.NewReader(strings.Repeat("x", MaxLine*2)))
	if _, err := r.Next(context.Background()); err != ErrLimit || r.r.Size() != MaxLine {
		t.Fatal(err)
	}
}

func TestClosedProjection(t *testing.T) {
	typ := reflect.TypeOf(Record{})
	want := []string{"version", "sequence", "event_id", "actor_id", "correlation_id", "kind", "class"}
	if typ.NumField() != len(want) {
		t.Fatal("projection changed: privacy review required")
	}
	for i, key := range want {
		if typ.Field(i).Tag.Get("json") != key {
			t.Fatal("projection changed")
		}
	}
	e := fixture(t)
	var out bytes.Buffer
	if err := Export(context.Background(), &out, &source{es: []Envelope{e}}, NDJSON, 1); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"metadata", "payload", "before", "after", "email", "cipher", "token_name", "client_ip", "request_claims", "secret-payload-sentinel"} {
		if bytes.Contains(out.Bytes(), []byte(forbidden)) {
			t.Fatal("unexpected field")
		}
	}
}
