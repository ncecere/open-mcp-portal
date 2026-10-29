package registry

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
)

func endpointTestBox(t *testing.T, key byte, previous ...[]byte) *secrets.Box {
	t.Helper()
	b, err := secrets.New(bytes.Repeat([]byte{key}, 32), previous...)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEndpointCredentialEnvelopeOriginRowServerAndShapeBinding(t *testing.T) {
	box := endpointTestBox(t, 1)
	server, id := uuid.New(), uuid.New()
	origin := "https://replica.example"
	parts := []CredentialInput{part(CredHeader, "X-Tenant", "tenant-sensitive-4821", ""), part(CredBasic, "", "user-sensitive", "password-sensitive-9372"), part(CredQuery, "api_key", "query-sensitive-5741", "")}
	cipher, views, err := sealEndpointCredentials(box, server, id, origin, parts)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(cipher, []byte("sensitive")) {
		t.Fatal("plaintext in cipher")
	}
	got, err := openEndpointCredentials(box, server, id, origin, cipher, views)
	if err != nil || len(got) != 3 || got[1].Secondary != parts[1].Secondary {
		t.Fatalf("roundtrip: %v", err)
	}
	for name, tc := range map[string]struct {
		server, id uuid.UUID
		origin     string
		cipher     []byte
		views      []CredentialView
	}{
		"other endpoint": {server, uuid.New(), origin, cipher, views}, "other server": {uuid.New(), id, origin, cipher, views},
		"other origin": {server, id, "https://elsewhere.example", cipher, views}, "noncanonical origin": {server, id, origin + ":443", cipher, views},
		"missing shape": {server, id, origin, cipher, nil}, "changed shape": {server, id, origin, cipher, []CredentialView{{Kind: CredBearer, Hint: "5741"}}},
		"primary AAD": {server, id, origin, nil, views},
	} {
		t.Run(name, func(t *testing.T) {
			if name == "primary AAD" {
				tc.cipher, _ = box.Seal([]byte("sensitive-value"), ServerAAD(id))
			}
			p, err := openEndpointCredentials(box, tc.server, tc.id, tc.origin, tc.cipher, tc.views)
			if err == nil || p != nil || strings.Contains(err.Error(), "sensitive") {
				t.Fatal("invalid binding accepted or leaked data")
			}
		})
	}
	cipher[len(cipher)-1] ^= 1
	if _, err := openEndpointCredentials(box, server, id, origin, cipher, views); err == nil {
		t.Fatal("tampered cipher accepted")
	}
}

func TestEndpointCredentialEnvelopeStrictAndRotationCompatible(t *testing.T) {
	old := endpointTestBox(t, 1)
	current := endpointTestBox(t, 2, bytes.Repeat([]byte{1}, 32))
	server, id := uuid.New(), uuid.New()
	origin := "https://replica.example"
	parts := []CredentialInput{part(CredBearer, "", "sensitive-bearer-token", "")}
	cipher, views, err := sealEndpointCredentials(old, server, id, origin, parts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openEndpointCredentials(current, server, id, origin, cipher, views); err != nil {
		t.Fatal("previous key no longer readable")
	}
	raw, err := current.Open(cipher, EndpointCredentialsAAD(id))
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := current.Seal(raw, EndpointCredentialsAAD(id))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openEndpointCredentials(endpointTestBox(t, 2), server, id, origin, rotated, views); err != nil {
		t.Fatal("rotated value not readable")
	}
	if _, err := openEndpointCredentials(old, server, id, origin, rotated, views); err == nil {
		t.Fatal("old key opened new cipher")
	}
	var env endpointCredentialEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Version != 1 || env.ServerID != server {
		t.Fatal("unexpected envelope format")
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"version":1`), []byte(`"version":2`), 1),
		append(append([]byte{}, raw...), []byte(` {}`)...),
		bytes.Replace(raw, []byte(`"version":1`), []byte(`"unknown":true,"version":1`), 1),
		[]byte(`{"version":1}`),
	} {
		c, _ := current.Seal(bad, EndpointCredentialsAAD(id))
		if _, err := openEndpointCredentials(current, server, id, origin, c, views); err == nil {
			t.Fatal("malformed envelope accepted")
		}
	}
	for _, bad := range [][]CredentialInput{{}, {{Kind: CredBearer, Keep: true}}, {{Kind: CredHeader, Name: "Host", Value: "forbidden"}}} {
		if _, _, err := sealEndpointCredentials(current, server, id, origin, bad); err == nil {
			t.Fatal("invalid fresh parts sealed")
		}
	}
}
