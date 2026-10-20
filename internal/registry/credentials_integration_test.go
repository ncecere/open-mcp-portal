package registry

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// What a request to a server carries is read from the legacy header columns
// until the credential is saved as a list (no data rewrite after the
// migration), and from the parts after: every part opened with its own AAD.
func TestTargetReadsLegacyHeaderThenParts(t *testing.T) {
	s, exec := testService(t)
	ctx := context.Background()
	team := exec(`INSERT INTO teams (slug, name) VALUES ('t', 'T') RETURNING id::text`)

	// A server saved by the previous release: its header sealed under the server's own AAD.
	id := uuid.New()
	cipher, err := s.box.Seal([]byte("legacy-secret-1234"), ServerAAD(id))
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO mcp_servers (id, team_id, slug, name, url, auth_header_name, auth_value_cipher, auth_value_hint, auth_mode)
		VALUES ($1, $2, 'old', 'Old', 'http://127.0.0.1:9/mcp', 'X-Api-Key', $3, '1234', 'static_header') RETURNING id::text`, id, team, cipher)
	sv, err := s.q.GetMCPServer(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if AuthModeOf(sv) != AuthStaticHeader {
		t.Fatalf("mode = %s", AuthModeOf(sv))
	}
	tgt, err := s.Target(ctx, sv)
	want := []upstream.Credential{{Kind: CredHeader, Name: "X-Api-Key", Value: "legacy-secret-1234"}}
	if err != nil || len(tgt.Credentials) != 1 || tgt.Credentials[0] != want[0] || tgt.AuthorizationHeader() != "" {
		t.Fatalf("legacy target = %+v %v", tgt.Credentials, err)
	}
	views, err := credentialViews(ctx, s.q, []dbgen.McpServer{sv})
	if err != nil || len(views[id]) != 1 || views[id][0] != (CredentialView{Kind: CredHeader, Name: "X-Api-Key", Hint: "1234"}) {
		t.Fatalf("legacy views = %+v %v", views, err)
	}

	// A server whose credential is a list: header, query, basic, in order.
	id2 := uuid.New()
	exec(`INSERT INTO mcp_servers (id, team_id, slug, name, url, auth_mode) VALUES ($1, $2, 'new', 'New', 'http://127.0.0.1:9/mcp', 'static_header') RETURNING id::text`, id2, team)
	sv2, _ := s.q.GetMCPServer(ctx, id2)
	plan, err := s.planCredentials(sv2, storedCredentials{}, []CredentialInput{
		{Kind: CredHeader, Name: "X-Tenant", Value: "acme-1234567890"},
		{Kind: CredQuery, Name: "key", Value: "q v&1"},
		{Kind: CredBasic, Value: "alice", Secondary: "pa:ss-12345678"},
	})
	if err != nil || !plan.write || !plan.valueChanged {
		t.Fatalf("plan = %+v %v", plan, err)
	}
	if err := storeCredentials(ctx, s.q, id2, plan); err != nil {
		t.Fatal(err)
	}
	tgt, err = s.Target(ctx, sv2)
	if err != nil || len(tgt.Credentials) != 3 || tgt.Credentials[0] != (upstream.Credential{Kind: CredHeader, Name: "X-Tenant", Value: "acme-1234567890"}) ||
		tgt.Credentials[1] != (upstream.Credential{Kind: CredQuery, Name: "key", Value: "q v&1"}) ||
		tgt.Credentials[2] != (upstream.Credential{Kind: CredBasic, Value: "alice", Secondary: "pa:ss-12345678"}) || tgt.AuthorizationHeader() != "Authorization" {
		t.Fatalf("parts target = %+v %v", tgt.Credentials, err)
	}
	if got := exec(`SELECT string_agg(hint, ',' ORDER BY position) FROM mcp_server_credentials WHERE server_id = $1`, id2); got != "7890,,5678" {
		t.Errorf("hints = %q", got)
	}
	// A server in none mode sends nothing, even if rows were left behind.
	exec(`UPDATE mcp_servers SET auth_mode = 'none' WHERE id = $1 RETURNING id::text`, id2)
	sv2, _ = s.q.GetMCPServer(ctx, id2)
	if tgt, err = s.Target(ctx, sv2); err != nil || len(tgt.Credentials) != 0 {
		t.Fatalf("none mode target = %+v %v", tgt.Credentials, err)
	}
	// A kept legacy header is sealed again under the part's own row, same secret.
	keep, err := s.planCredentials(sv, storedCredentials{legacy: &CredentialView{Kind: CredHeader, Name: "X-Api-Key", Hint: "1234"}},
		[]CredentialInput{{Kind: CredHeader, Name: "X-Api-Key", Keep: true}, {Kind: CredQuery, Name: "k", Value: "v-1234567890"}})
	if err != nil || !keep.write || keep.rows[0].ID == uuid.Nil || keep.rows[0].Hint != "1234" {
		t.Fatalf("keep plan = %+v %v", keep, err)
	}
	plain, err := s.box.Open(keep.rows[0].ValueCipher, CredentialAAD(keep.rows[0].ID))
	if err != nil || string(plain) != "legacy-secret-1234" {
		t.Fatalf("moved header = %q %v", plain, err)
	}
	if _, err := s.box.Open(keep.rows[0].ValueCipher, ServerAAD(id)); err == nil {
		t.Error("the moved header still opens under the server's AAD")
	}
}
