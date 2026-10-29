package mcptasks

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
)

func stateFixture(t *testing.T) (*secrets.Box, uuid.UUID, string, Binding, Payload) {
	t.Helper()
	box, err := secrets.New(bytes.Repeat([]byte{0x17}, 32))
	if err != nil {
		t.Fatal(err)
	}
	_, digest, err := NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	p := Payload{UpstreamID: "upstream-private-task-593842", Arguments: json.RawMessage(`{"service":"owned","value":9007199254740991}`), RedactionOnly: []string{"old-provider-private-9183"}}
	args, err := DigestArguments(p.Arguments)
	if err != nil {
		t.Fatal(err)
	}
	b := Binding{PrincipalKind: PrincipalUser, PrincipalID: uuid.New(), CredentialKind: CredentialOAuthGrant, CredentialID: uuid.New(), GatewayID: uuid.New(), ServerID: uuid.New(), CapabilityID: uuid.New(), ExposedName: "owned__run", ServerURL: "https://tasks.example/mcp", ServerRevision: 4, ToolClass: "read", DefinitionFingerprint: strings.Repeat("1", 64), CurationDigest: strings.Repeat("2", 64), ArgumentsDigest: args, DependencyDigest: strings.Repeat("3", 64)}
	return box, uuid.New(), digest, b, p
}

func TestTaskStateEnvelopeRoundTripAndReservation(t *testing.T) {
	box, id, digest, b, p := stateFixture(t)
	for _, upstreamID := range []string{p.UpstreamID, ""} {
		p.UpstreamID = upstreamID
		cipher, err := SealState(box, id, digest, b, p)
		if err != nil {
			t.Fatal(err)
		}
		if upstreamID != "" && bytes.Contains(cipher, []byte(upstreamID)) || bytes.Contains(cipher, []byte(p.RedactionOnly[0])) {
			t.Fatal("private state not sealed")
		}
		got, err := OpenState(box, id, digest, b, cipher)
		if err != nil || got.UpstreamID != upstreamID || !bytes.Equal(got.Arguments, p.Arguments) || len(got.RedactionOnly) != 1 || got.RedactionOnly[0] != p.RedactionOnly[0] {
			t.Fatal("state did not round trip", err)
		}
	}
}

func TestTaskStateEnvelopeArgumentRepresentationRoundTrip(t *testing.T) {
	box, id, digest, b, p := stateFixture(t)
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{ "text" : "<>&", "n": 1e3 }`),
		json.RawMessage(`{"text":"\u003c\u0026\u003e","slash":"\/","n":1.0}`),
		json.RawMessage("{\"text\":\"line\u2028paragraph\u2029\"}"),
	} {
		p.Arguments = raw
		var err error
		b.ArgumentsDigest, err = DigestArguments(raw)
		if err != nil {
			t.Fatal(err)
		}
		cipher, err := SealState(box, id, digest, b, p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := OpenState(box, id, digest, b, cipher)
		if err != nil {
			t.Fatalf("representation failed round trip: %v", err)
		}
		opened, err := DigestArguments(got.Arguments)
		if err != nil || opened != b.ArgumentsDigest {
			t.Fatal("argument identity changed during sealing")
		}
	}
}

func TestTaskStateEnvelopeRejectsEveryAssociationChange(t *testing.T) {
	box, id, digest, b, p := stateFixture(t)
	cipher, err := SealState(box, id, digest, b, p)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*Binding){
		func(b *Binding) { b.PrincipalID = uuid.New() }, func(b *Binding) { b.CredentialID = uuid.New() },
		func(b *Binding) { b.CredentialKind = CredentialAPIKey }, func(b *Binding) { b.GatewayID = uuid.New() },
		func(b *Binding) { b.ServerID = uuid.New() }, func(b *Binding) { b.CapabilityID = uuid.New() },
		func(b *Binding) { b.ExposedName = "other__run" }, func(b *Binding) { b.ServerURL = "https://another.example/mcp" },
		func(b *Binding) { b.ServerURL = "https://tasks.example/another-path" }, func(b *Binding) { b.ServerRevision++ },
		func(b *Binding) { b.ToolClass = "write" }, func(b *Binding) { b.DefinitionFingerprint = strings.Repeat("a", 64) },
		func(b *Binding) { b.CurationDigest = strings.Repeat("b", 64) }, func(b *Binding) { b.ArgumentsDigest = strings.Repeat("c", 64) },
		func(b *Binding) { b.DependencyDigest = strings.Repeat("d", 64) },
		func(b *Binding) { b.PrincipalKind, b.CredentialKind = PrincipalServiceAccount, CredentialServiceKey },
	}
	for i, change := range mutations {
		other := b
		change(&other)
		_, err := OpenState(box, id, digest, other, cipher)
		if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "example") {
			t.Fatalf("association %d accepted or disclosed: %v", i, err)
		}
	}
	for _, rowID := range []uuid.UUID{uuid.Nil, uuid.New()} {
		if _, err := OpenState(box, rowID, digest, b, cipher); !errors.Is(err, ErrUnavailable) {
			t.Fatal("ciphertext moved to another row")
		}
	}
	if _, err := OpenState(box, id, strings.Repeat("f", 64), b, cipher); !errors.Is(err, ErrUnavailable) {
		t.Fatal("ciphertext moved to another handle")
	}
	cipher[len(cipher)-1] ^= 1
	if _, err := OpenState(box, id, digest, b, cipher); !errors.Is(err, ErrUnavailable) {
		t.Fatal("tampered state accepted")
	}
}

func TestTaskStateEnvelopeStrictVersionShapeAndRotation(t *testing.T) {
	old, id, digest, b, p := stateFixture(t)
	cipher, err := SealState(old, id, digest, b, p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := old.Open(cipher, StateAAD(id))
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{[]byte(`null`), []byte(`{`), append(bytes.Clone(raw), []byte(` {}`)...), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1), bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":1,"unknown":"private"`), 1)} {
		bad, err := old.Seal(invalid, StateAAD(id))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenState(old, id, digest, b, bad); !errors.Is(err, ErrUnavailable) {
			t.Fatal("invalid envelope accepted")
		}
	}
	rotated, err := secrets.New(bytes.Repeat([]byte{0x29}, 32), bytes.Repeat([]byte{0x17}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(rotated, id, digest, b, cipher); err != nil {
		t.Fatal("previous key not readable")
	}
	next, err := SealState(rotated, id, digest, b, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(old, id, digest, b, next); !errors.Is(err, ErrUnavailable) {
		t.Fatal("old-only key opened new ciphertext")
	}
}

func TestTaskStateEnvelopeBoundsAndArguments(t *testing.T) {
	box, id, digest, b, p := stateFixture(t)
	badPayloads := []Payload{
		{UpstreamID: strings.Repeat("x", MaxUpstreamIDBytes+1), Arguments: p.Arguments},
		{UpstreamID: "x", Arguments: json.RawMessage(`null`)},
		{UpstreamID: "x", Arguments: json.RawMessage(`[]`)},
		{UpstreamID: "x", Arguments: json.RawMessage(`{"other":true}`)},
		{UpstreamID: "x", Arguments: p.Arguments, RedactionOnly: []string{""}},
		{UpstreamID: "x", Arguments: p.Arguments, RedactionOnly: []string{string([]byte{0xff})}},
		{UpstreamID: "x", Arguments: p.Arguments, RedactionOnly: []string{strings.Repeat("x", MaxRedactionSecretBytes+1)}},
		{UpstreamID: "x", Arguments: p.Arguments, RedactionOnly: []string{strings.Repeat("x", MaxRedactionSecretBytes), strings.Repeat("y", MaxRedactionSecretBytes), "z"}},
	}
	for i, bad := range badPayloads {
		if _, err := SealState(box, id, digest, b, bad); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("invalid payload %d accepted", i)
		}
	}
	if _, err := SealState(nil, id, digest, b, p); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil encryption accepted")
	}
	for _, url := range []string{"", "ftp://tasks.example/mcp", "https://user:private@tasks.example/mcp", "https://tasks.example/mcp?private=1", "https://tasks.example/mcp#", "https://tasks.example/mcp#private", " https://tasks.example/mcp"} {
		other := b
		other.ServerURL = url
		if _, err := DigestBinding(other); !errors.Is(err, ErrUnavailable) {
			t.Fatal("unusable destination accepted")
		}
	}
	d1, _ := DigestArguments(json.RawMessage(`{ "x" : 9007199254740991 }`))
	d2, _ := DigestArguments(json.RawMessage(`{"x":9007199254740991}`))
	if d1 == "" || d1 != d2 {
		t.Fatal("argument digest changed whitespace or numeric precision")
	}
}
