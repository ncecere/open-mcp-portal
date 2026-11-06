package auditstream

import (
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"os"
	"strings"
	"testing"
	"time"
)

type vector struct{ JSON, Canonical, Summary, Entry, Record, Genesis, Chain string }

func vectorRow(raw string) Row {
	return Row{ID: 42, OccurredAt: time.Unix(1700000000, 123456000).UTC(), Action: "team.create", ActorKind: "system", TargetType: "team", TargetID: "", RequestID: "é\n", BeforeState: nil, AfterState: json.RawMessage("null"), Metadata: json.RawMessage(raw)}
}
func TestGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	stream := uuid.MustParse("00112233-4455-4677-8899-aabbccddeeff")
	for _, v := range vectors {
		r := vectorRow(v.JSON)
		c, err := CanonicalJSON([]byte(v.JSON))
		if err != nil {
			t.Fatal(err)
		}
		sh := SummaryHash(r)
		eh, err := EntryHash(r)
		if err != nil {
			t.Fatal(err)
		}
		g := Genesis(stream)
		rec, ch, err := NewRecord(stream, 1, 1, g, r)
		if err != nil {
			t.Fatal(err)
		}
		_ = rec
		got := vector{JSON: v.JSON, Canonical: string(c), Summary: hex.EncodeToString(sh[:]), Entry: hex.EncodeToString(eh[:]), Record: hex.EncodeToString(RecordBytes(stream, 1, 1, 0, r, sh, eh)), Genesis: hex.EncodeToString(g[:]), Chain: hex.EncodeToString(ch[:])}
		if got != v {
			t.Fatalf("vector mismatch: %+v", got)
		}
		if len(RecordBytes(stream, 1, 1, 0, r, sh, eh)) != 119 {
			t.Fatal("record length")
		}
	}
}

func TestPresenceDistinctions(t *testing.T) {
	r := vectorRow(`{}`)
	empty := ""
	null := json.RawMessage("null")
	emptyJSON := json.RawMessage(`""`)
	var hashes [][32]byte
	for _, raw := range []json.RawMessage{nil, null, emptyJSON, json.RawMessage(`{}`), json.RawMessage(`[]`)} {
		r.BeforeState = raw
		h, err := EntryHash(r)
		if err != nil {
			t.Fatal(err)
		}
		for _, prev := range hashes {
			if prev == h {
				t.Fatal("SQL NULL/JSON value collision")
			}
		}
		hashes = append(hashes, h)
	}
	r = vectorRow(`{}`)
	absent, err := EntryHash(r)
	if err != nil {
		t.Fatal(err)
	}
	r.ActorTokenName = &empty
	present, err := EntryHash(r)
	if err != nil {
		t.Fatal(err)
	}
	if absent == present {
		t.Fatal("NULL and empty text collision")
	}
	zero := uuid.Nil
	before := SummaryHash(r)
	r.ActorUserID = &zero
	if before == SummaryHash(r) {
		t.Fatal("absent and zero UUID collision")
	}
}

// The oversized flag counts the summary fields a full envelope repeats: a row
// whose own JSON is under the limit but whose target id pushes the envelope
// over the 16 MiB line cap is flagged at sealing. The full envelope of an
// unflagged row always fits the line cap.
func TestOversizedFlagCountsSummaryFields(t *testing.T) {
	big := strings.Repeat("x", 9<<20) // row ~9 MiB; envelope ~18 MiB
	r := vectorRow(`{}`)
	r.TargetID = big
	rec, _, err := NewRecord(uuid.New(), 1, 1, [32]byte{}, r)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Flags&2 == 0 {
		t.Fatal("envelope over the line cap was not flagged oversized")
	}
	r.TargetID = strings.Repeat("x", 7<<20) // envelope ~14 MiB: fits
	rec, _, err = NewRecord(uuid.New(), 1, 1, [32]byte{}, r)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Flags&2 != 0 {
		t.Fatal("row that fits was flagged")
	}
	env := Envelope{Record: rec, Stream: uuid.New(), Epoch: 1, OccurredAt: r.OccurredAt}
	env.SummaryFields, _ = SummaryFieldsJSON(r)
	env.Full = &r
	_, line, err := EnvelopeLine(env, true)
	if err != nil || len(line) > LineCap {
		t.Fatalf("unflagged full line %d > cap %d (%v)", len(line), LineCap, err)
	}
}
