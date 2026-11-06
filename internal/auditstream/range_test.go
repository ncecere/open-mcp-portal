package auditstream

import (
	"bytes"
	"testing"
)

func TestRangeContinuity(t *testing.T) {
	from, to := int64(11), int64(19)
	e := Envelope{Record: Record{Seq: 20, Kind: "epoch_start"}, EpochSummary: &EpochSummary{GapFrom: &from, GapTo: &to, PredecessorSeq: 10}}
	if !contiguous(10, e) {
		t.Fatal("declared gap refused")
	}
	for _, prev := range []int64{9, 11} {
		if contiguous(prev, e) {
			t.Fatal("nonmatching gap accepted")
		}
	}
	e.Kind = "entry"
	if contiguous(10, e) {
		t.Fatal("entry declared gap")
	}
}
func TestEnvelopeLineCap(t *testing.T) {
	for _, n := range []int{5 << 20, 16 << 20} {
		e := Envelope{Record: Record{Seq: 1, Kind: "entry"}, Full: &Row{Metadata: append(append([]byte{'"'}, bytes.Repeat([]byte{'x'}, n)...), '"')}}
		env, line, err := EnvelopeLine(e, true)
		if err != nil {
			t.Fatal(err)
		}
		if n < LineCap {
			if env.Oversized || len(line) < 4<<20 {
				t.Fatal("large single envelope truncated")
			}
		} else if !env.Oversized || env.Full != nil || env.Reference == "" {
			t.Fatal("missing oversized projection")
		}
	}
	e, _, err := EnvelopeLine(Envelope{Record: Record{Seq: 1, Flags: 2}}, true)
	if err != nil || !e.Oversized {
		t.Fatal("flagged oversized projection missing")
	}
}
