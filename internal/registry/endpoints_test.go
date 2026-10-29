package registry

import (
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func endpointStored(p endpointPlan) []dbgen.McpServerEndpoint {
	out := make([]dbgen.McpServerEndpoint, len(p.rows))
	for i, r := range p.rows {
		out[i] = dbgen.McpServerEndpoint{ID: r.ID, ServerID: r.ServerID, Position: r.Position, URL: r.URL, Enabled: r.Enabled, AuthMode: r.AuthMode, CredentialOrigin: r.CredentialOrigin, CredentialsCipher: r.CredentialsCipher, CredentialShapes: r.CredentialShapes, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
	}
	return out
}

func endpointErrCode(err error) string {
	if e, ok := apperr.As(err); ok {
		return e.Code
	}
	return "other"
}

func TestEndpointPlanIndependentOriginCredentialsAndNoOp(t *testing.T) {
	s := &Service{box: endpointTestBox(t, 1)}
	sv := dbgen.McpServer{ID: uuid.New(), URL: "https://primary.example/mcp", AuthMode: AuthStaticHeader}
	parts := []CredentialInput{part(CredHeader, "X-Key", "independently-entered-secret", "")}
	in := []EndpointInput{{URL: "https://replica.example/mcp", Credentials: &parts}}
	p, err := s.planEndpointRows(sv, nil, false, "owner", &in, true)
	if err != nil || !p.changed || !p.review || len(p.after) != 1 {
		t.Fatalf("initial plan: %+v %v", p, err)
	}
	stored := endpointStored(p)
	id := stored[0].ID
	keep := []EndpointInput{{ID: id, URL: stored[0].URL}}
	p, err = s.planEndpointRows(sv, stored, false, "owner", &keep, false)
	if err != nil || p.changed || p.review {
		t.Fatalf("retention changed state: %+v %v", p, err)
	}
	if _, err = s.planEndpointRows(sv, nil, false, "owner", &[]EndpointInput{{URL: "https://replica.example/mcp"}}, true); endpointErrCode(err) != "auth_value_required" {
		t.Fatal("new endpoint inherited primary credential")
	}
	keep[0].URL = "https://other.example/mcp"
	if _, err = s.planEndpointRows(sv, stored, false, "owner", &keep, false); endpointErrCode(err) != "auth_value_required" {
		t.Fatal("origin edit retained values")
	}
	retained := []CredentialInput{{Kind: CredHeader, Name: "X-Key", Keep: true}}
	keep[0].Credentials = &retained
	if _, err = s.planEndpointRows(sv, stored, false, "owner", &keep, false); endpointErrCode(err) != "auth_value_required" {
		t.Fatal("keep authorized new origin")
	}
	keep[0].Credentials = &parts
	p, err = s.planEndpointRows(sv, stored, false, "owner", &keep, false)
	if err != nil || !p.review || !p.changed {
		t.Fatalf("explicit re-entry failed: %v", err)
	}
	if _, err := openEndpointCredentials(s.box, sv.ID, id, "https://other.example", p.rows[0].CredentialsCipher, p.after[0].Credentials); err != nil {
		t.Fatal(err)
	}
	if _, err := openEndpointCredentials(s.box, sv.ID, id, "https://replica.example", p.rows[0].CredentialsCipher, p.after[0].Credentials); err == nil {
		t.Fatal("new envelope remained bound to old origin")
	}
}

func TestEndpointPlanRolesModesIDsDuplicatesAndCleanup(t *testing.T) {
	s := &Service{box: endpointTestBox(t, 1)}
	sv := dbgen.McpServer{ID: uuid.New(), URL: "https://primary.example/", AuthMode: AuthNone}
	in := []EndpointInput{{URL: "https://replica.example/mcp"}}
	for _, role := range []string{"editor", "member", ""} {
		if _, err := s.planEndpointRows(sv, nil, false, role, &in, true); err == nil {
			t.Fatalf("%s gained endpoint authority", role)
		}
	}
	for _, mode := range []string{AuthOAuth, AuthPersonSecret, AuthMachineOAuth, "unknown"} {
		other := sv
		other.AuthMode = mode
		if _, err := s.planEndpointRows(other, nil, false, "owner", &in, true); endpointErrCode(err) != "failover_not_supported" {
			t.Fatalf("mode %s accepted: %v", mode, err)
		}
	}
	other := sv
	other.AuthProviderID = uuid.NullUUID{UUID: uuid.New(), Valid: true}
	if _, err := s.planEndpointRows(other, nil, false, "owner", &in, true); endpointErrCode(err) != "failover_not_supported" {
		t.Fatal("provider requirement accepted")
	}
	if _, err := s.planEndpointRows(sv, nil, true, "owner", &in, true); endpointErrCode(err) != "failover_not_supported" {
		t.Fatal("independent TLS settings accepted")
	}
	for _, bad := range [][]EndpointInput{
		{{URL: "https://PRIMARY.example:443"}},
		{{URL: "https://replica.example/mcp"}, {URL: "https://replica.example:443/mcp"}},
		{{ID: uuid.New(), URL: "https://replica.example/mcp"}},
		{{URL: "https://one.example"}, {URL: "https://two.example"}, {URL: "https://three.example"}},
	} {
		if _, err := s.planEndpointRows(sv, nil, false, "owner", &bad, true); err == nil {
			t.Fatal("invalid URL/ID/list accepted")
		}
	}
	p, err := s.planEndpointRows(sv, nil, false, "owner", &in, true)
	if err != nil {
		t.Fatal(err)
	}
	stored := endpointStored(p)
	if _, err := s.planEndpointRows(sv, stored, false, "editor", nil, false); err != nil {
		t.Fatal("unrelated editor metadata refused")
	}
	other = sv
	other.AuthMode = AuthOAuth
	if _, err := s.planEndpointRows(other, stored, false, "owner", nil, false); endpointErrCode(err) != "failover_not_supported" {
		t.Fatal("mode change kept unsupported extras")
	}
	stored[0].CredentialOrigin = "https://corrupt.example"
	empty := []EndpointInput{}
	p, err = s.planEndpointRows(other, stored, true, "owner", &empty, false)
	if err != nil || !p.changed || !p.review || len(p.rows) != 0 {
		t.Fatal("owner could not clear corrupt/incompatible state")
	}
}
