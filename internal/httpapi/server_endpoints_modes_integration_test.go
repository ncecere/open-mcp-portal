package httpapi_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestServerEndpointsRefuseEveryUnsupportedCredentialCombination(t *testing.T) {
	e := newRegistryEnv(t)
	extra := testutil.NewFakeMCP(t)
	ca := testutil.NewCA(t, "Owned endpoint CA")
	client := ca.Issue(t, testutil.IssueOptions{CommonName: "owned-client", Client: true, NotAfter: time.Now().Add(24 * time.Hour)})
	var made apitypes.McpServerCreated
	code, ec := e.owner.call("POST", toolsTeam+"/mcp-servers", map[string]any{"slug": "endpoint-modes", "name": "Endpoint modes", "url": e.fake.URL(), "authMode": "none", "endpoints": []any{map[string]any{"url": extra.URL()}}}, &made, nil)
	mustCode(t, "create compatible replicas", code, ec, 201, "")
	path := toolsTeam + "/mcp-servers/" + made.Server.Id.String()
	for name, change := range map[string]map[string]any{
		"upstream OAuth":       {"authMode": "oauth"},
		"per-person key":       {"authMode": "person_secret", "personSecret": map[string]any{"placement": "header", "name": "X-Person-Key"}},
		"machine client":       {"authMode": "machine_oauth", "machineOAuth": map[string]any{"tokenUrl": extra.URL() + "/token", "clientId": "owned", "clientSecret": "not-for-replicas"}},
		"provider requirement": {"requirement": map[string]any{"providerId": uuid.New().String(), "scopes": []any{}}},
		"private CA":           {"tls": map[string]any{"caPem": ca.CertPEM}},
		"mTLS identity":        {"tls": map[string]any{"clientCertPem": client.CertPEM, "clientKeyPem": client.KeyPEM}},
	} {
		t.Run(name, func(t *testing.T) {
			cur := e.server(e.owner, made.Server.Id.String())
			code, ec := e.owner.call("PATCH", path, change, nil, ifMatch(cur.Revision))
			mustCode(t, name, code, ec, 422, "failover_not_supported")
		})
	}
	cur := e.server(e.owner, made.Server.Id.String())
	if cur.AuthMode == nil || *cur.AuthMode != "none" || cur.Tls != nil || cur.Requirement != nil || cur.Endpoints == nil || len(*cur.Endpoints) != 1 {
		t.Fatal("refused mode change partially persisted")
	}
}
