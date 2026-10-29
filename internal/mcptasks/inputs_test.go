package mcptasks

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/iotest"
)

func members(t *testing.T, raw json.RawMessage) []member {
	t.Helper()
	m, ok := objectMembers(raw, 1<<20, 1000)
	if !ok {
		t.Fatalf("invalid object %s", raw)
	}
	return m
}

func TestInputRequestsGetStablePrivateMappedKeys(t *testing.T) {
	req := json.RawMessage(`{"server-secret-key-1":{"method":"elicitation/create","params":{"message":"a"}},"k2":{"method":"elicitation/create","params":{"message":"b"}}}`)
	ledger, out, err := MapInputRequests(nil, req, rand.Reader)
	if err != nil || len(ledger) != 2 {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("server-secret-key-1")) || bytes.Contains(out, []byte(`"k2"`)) {
		t.Fatal("server input keys reached the client")
	}
	first := members(t, out)
	if len(first) != 2 || !validInputKey(first[0].key) || first[0].key == first[1].key || !strings.HasPrefix(first[0].key, InputKeyPrefix) {
		t.Fatal("portal keys not issued")
	}
	// Repeated polls (whitespace/member-order changes allowed) keep the same keys.
	again := json.RawMessage(`{ "k2" : {"method":"elicitation/create","params":{"message":"b"}}, "server-secret-key-1":{"method":"elicitation/create","params":{"message":"a"}} }`)
	ledger2, out2, err := MapInputRequests(ledger, again, rand.Reader)
	if err != nil || len(ledger2) != 2 {
		t.Fatal(err)
	}
	second := members(t, out2)
	if second[0].key != first[1].key || second[1].key != first[0].key {
		t.Fatal("portal keys were not stable across polls")
	}
	// Reusing a server key for a different request fails closed.
	changed := json.RawMessage(`{"k2":{"method":"elicitation/create","params":{"message":"DIFFERENT"}}}`)
	if _, _, err := MapInputRequests(ledger, changed, rand.Reader); !errors.Is(err, ErrUnavailable) {
		t.Fatal("server key reuse for a different request accepted")
	}
}

func TestInputResponsesAreSingleUseAndIgnoreUnknown(t *testing.T) {
	req := json.RawMessage(`{"s1":{"m":1},"s2":{"m":2}}`)
	ledger, out, err := MapInputRequests(nil, req, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k := members(t, out)
	resp := json.RawMessage(fmt.Sprintf(`{%q:{"action":"accept"},"ompin_unknownunknownunknownu":{"x":1},"s2":{"spoof":true}}`, k[0].key))
	ledger2, body, n, err := SelectInputResponses(ledger, resp)
	if err != nil || n != 1 || !ledger2[0].Attempted || ledger2[1].Attempted || ledger[0].Attempted {
		t.Fatalf("selection: n=%d err=%v", n, err)
	}
	fwd := members(t, body)
	if len(fwd) != 1 || fwd[0].key != "s1" || string(fwd[0].value) != `{"action":"accept"}` {
		t.Fatalf("forwarded %s", body)
	}
	// The same key again is ignored: no replay after an ambiguous send.
	if _, _, n, err := SelectInputResponses(ledger2, resp); err != nil || n != 0 {
		t.Fatal("attempted key replayed")
	}
	// A later poll no longer offers the attempted request.
	_, again, err := MapInputRequests(ledger2, req, rand.Reader)
	if err != nil || len(members(t, again)) != 1 || members(t, again)[0].key != k[1].key {
		t.Fatalf("attempted request re-offered: %s", again)
	}
}

func TestInputBoundsAndMalformedObjects(t *testing.T) {
	var many strings.Builder
	many.WriteByte('{')
	for i := range MaxOutstandingInputs + 1 {
		if i > 0 {
			many.WriteByte(',')
		}
		fmt.Fprintf(&many, `"k%d":{}`, i)
	}
	many.WriteByte('}')
	for _, raw := range []string{many.String(), `{"a":{},"a":{}}`, `[]`, `{"a":1}`, `{"a":{}} {}`, `{"":{}}`, `{"` + strings.Repeat("k", maxServerInputKeyBytes+1) + `":{}}`, `{"a":{}`, "{\"a\":{\"x\":\"\xff\"}}"} {
		if _, _, err := MapInputRequests(nil, json.RawMessage(raw), rand.Reader); err == nil {
			t.Fatalf("accepted %.60q", raw)
		}
	}
	if _, _, _, err := SelectInputResponses(nil, json.RawMessage(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("duplicate response keys accepted")
	}
	if _, _, _, err := SelectInputResponses(nil, json.RawMessage(`{"a":"`+strings.Repeat("x", MaxInputResponsesBytes)+`"}`)); err == nil {
		t.Fatal("oversized responses accepted")
	}
	full := worstCaseLedger()
	if !validLedger(full) {
		t.Fatal("worst-case ledger invalid")
	}
	if _, _, err := MapInputRequests(full, json.RawMessage(`{"brand-new":{}}`), rand.Reader); err == nil {
		t.Fatal("lifetime input bound exceeded")
	}
	if _, _, err := MapInputRequests(nil, json.RawMessage(`{"a":{}}`), iotest.ErrReader(errors.New("no entropy"))); !errors.Is(err, ErrUnavailable) {
		t.Fatal("entropy failure did not fail closed")
	}
	dup := append(full[:1:1], full[0])
	if validLedger(dup) {
		t.Fatal("duplicate ledger keys accepted")
	}
}

func TestWorstCaseLedgerFitsSealedState(t *testing.T) {
	box, id, digest, b, p := stateFixture(t)
	p.UpstreamID = string(make([]byte, MaxUpstreamIDBytes))
	p.Inputs = worstCaseLedger()
	cipher, err := SealState(box, id, digest, b, p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenState(box, id, digest, b, cipher)
	if err != nil || len(got.Inputs) != MaxLifetimeInputs {
		t.Fatal("worst-case ledger did not round trip", err)
	}
}
