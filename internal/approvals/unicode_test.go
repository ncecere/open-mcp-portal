package approvals

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestGovernedArgumentsRejectLossyUnicode(t *testing.T) {
	for _, raw := range []json.RawMessage{
		[]byte(`{"name":"\ud800"}`), []byte(`{"name":"\udfff"}`),
		[]byte(`{"\ud800":"value"}`), []byte(`{"name":"\ud800x\udc00"}`),
		[]byte(`{"name":"\udc00\ud800"}`), append([]byte(`{"name":"`), append([]byte{0xff}, []byte(`"}`)...)...),
	} {
		if _, err := CanonicalArguments(raw); err == nil {
			t.Errorf("lossy Unicode accepted: %q", raw)
		}
	}
}

func TestGovernedArgumentsPreserveValidUnicodeEscapes(t *testing.T) {
	for _, pair := range [][2]string{
		{`{"name":"\ud83d\ude00"}`, `{"name":"😀"}`},
		{`{"name":"\u00e9"}`, `{"name":"é"}`},
		{`{"name":"\\ud800"}`, `{"name":"\\ud800"}`},
	} {
		a, err := CanonicalArguments(json.RawMessage(pair[0]))
		if err != nil {
			t.Fatal(err)
		}
		b, err := CanonicalArguments(json.RawMessage(pair[1]))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("valid Unicode changed meaning: %q %q", a, b)
		}
	}
}
