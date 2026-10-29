package registry

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

const maxEndpointCredentialEnvelope = 256 * 1024

// EndpointCredentialsAAD isolates this endpoint's complete static credential
// from primary credentials and other endpoints. The sealed envelope also binds
// its server and origin; changing public row associations cannot rebind it.
func EndpointCredentialsAAD(id uuid.UUID) []byte {
	return []byte("mcp_server_endpoint:" + id.String() + ":credentials")
}

type endpointCredentialPart struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Value     string `json:"value"`
	Secondary string `json:"secondary"`
}

type endpointCredentialEnvelope struct {
	Version  int                      `json:"version"`
	ServerID uuid.UUID                `json:"serverId"`
	Origin   string                   `json:"origin"`
	Parts    []endpointCredentialPart `json:"parts"`
}

func endpointCredentialViews(items []CredentialInput) []CredentialView {
	out := make([]CredentialView, len(items))
	for i, p := range items {
		v := p.Value
		if p.Kind == CredBasic {
			v = p.Secondary
		}
		out[i] = CredentialView{Kind: p.Kind, Name: p.Name, Hint: valueHint(v)}
	}
	return out
}

func endpointCredentialFailure() error {
	return &upstream.Error{Class: upstream.ClassConfig, Reason: "endpoint_auth_unavailable", Message: "The endpoint's stored credential is unavailable or no longer matches its destination."}
}

// sealEndpointCredentials takes fully resolved, independently entered parts;
// keep semantics are resolved by the origin-checked mutation plan, never here.
func sealEndpointCredentials(box *secrets.Box, serverID, endpointID uuid.UUID, origin string, items []CredentialInput) ([]byte, []CredentialView, error) {
	if box == nil || serverID == uuid.Nil || endpointID == uuid.Nil || origin == "" || originOf(origin) != origin || len(items) == 0 {
		return nil, nil, endpointCredentialFailure()
	}
	if err := checkCredentialShape(items); err != nil {
		return nil, nil, err
	}
	env := endpointCredentialEnvelope{Version: 1, ServerID: serverID, Origin: origin, Parts: make([]endpointCredentialPart, len(items))}
	for i, p := range items {
		if p.Keep {
			return nil, nil, endpointCredentialFailure()
		}
		env.Parts[i] = endpointCredentialPart{Kind: p.Kind, Name: p.Name, Value: p.Value, Secondary: p.Secondary}
	}
	raw, err := json.Marshal(env)
	if err != nil || len(raw) > maxEndpointCredentialEnvelope {
		return nil, nil, endpointCredentialFailure()
	}
	cipher, err := box.Seal(raw, EndpointCredentialsAAD(endpointID))
	if err != nil {
		return nil, nil, endpointCredentialFailure()
	}
	return cipher, endpointCredentialViews(items), nil
}

// openEndpointCredentials verifies encrypted destination/association and public
// shape before any part is attached to an HTTP target. Errors never quote data.
func openEndpointCredentials(box *secrets.Box, serverID, endpointID uuid.UUID, origin string, cipher []byte, views []CredentialView) ([]CredentialInput, error) {
	fail := endpointCredentialFailure
	if box == nil || serverID == uuid.Nil || endpointID == uuid.Nil || origin == "" || originOf(origin) != origin || len(cipher) > maxEndpointCredentialEnvelope+1024 {
		return nil, fail()
	}
	raw, err := box.Open(cipher, EndpointCredentialsAAD(endpointID))
	if err != nil || len(raw) > maxEndpointCredentialEnvelope {
		return nil, fail()
	}
	var env endpointCredentialEnvelope
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&env); err != nil {
		return nil, fail()
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, fail()
	}
	if env.Version != 1 || env.ServerID != serverID || env.Origin != origin || len(env.Parts) == 0 || len(env.Parts) > MaxCredentials {
		return nil, fail()
	}
	items := make([]CredentialInput, len(env.Parts))
	for i, p := range env.Parts {
		items[i] = CredentialInput{Kind: p.Kind, Name: p.Name, Value: p.Value, Secondary: p.Secondary}
	}
	if err := checkCredentialShape(items); err != nil {
		return nil, fail()
	}
	if !reflect.DeepEqual(endpointCredentialViews(items), views) {
		return nil, fail()
	}
	return items, nil
}
