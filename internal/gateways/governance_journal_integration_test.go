package gateways

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// What decides whether a capability is served is an authority input of the
// approval context (migrations 36/42/47/49): changing a server's sensitivity,
// lifecycle or sunset date, or a gateway's ceiling, ends the validity of an
// approval requested before. Governance bookkeeping decides nothing and
// leaves it alone.
func TestGovernanceInputsJoinTheApprovalAuthorityJournal(t *testing.T) {
	ctx := context.Background()
	pool, _ := testutil.NewDB(t)
	q := dbgen.New(pool)
	run := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	team := uuid.New()
	user := uuid.New()
	srv, gw := uuid.New(), uuid.New()
	run(`INSERT INTO teams(id,slug,name) VALUES($1,'j','J')`, team)
	run(`INSERT INTO users(id,oidc_issuer,oidc_subject,email) VALUES($1,'t','j','j@example.invalid')`, user)
	run(`INSERT INTO mcp_servers(id,team_id,slug,name,url) VALUES($1,$2,'j','J','https://x.example.com/mcp')`, srv, team)
	run(`INSERT INTO gateways(id,slug,name,owner_kind) VALUES($1,'j','J','platform')`, gw)
	epoch := func() int64 {
		t.Helper()
		e, err := q.GetApprovalContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	for _, c := range []struct {
		name    string
		sql     string
		advance bool
	}{
		{"sensitivity", `UPDATE mcp_servers SET sensitivity = 'confidential' WHERE id = $1`, true},
		{"deprecating (lifecycle)", `UPDATE mcp_servers SET lifecycle = 'deprecated', deprecated_at = now() WHERE id = $1`, true},
		{"the sunset date", `UPDATE mcp_servers SET sunset_at = now() + interval '30 days' WHERE id = $1`, true},
		{"sunset (lifecycle)", `UPDATE mcp_servers SET lifecycle = 'sunset' WHERE id = $1`, true},
		{"the owner", `UPDATE mcp_servers SET owner_user_id = '` + user.String() + `' WHERE id = $1`, false},
		{"the on-call contact", `UPDATE mcp_servers SET oncall_contact = '#x' WHERE id = $1`, false},
		{"the review dates", `UPDATE mcp_servers SET last_reviewed_at = now(), review_due_at = now() WHERE id = $1`, false},
		{"the replacement", `UPDATE mcp_servers SET replacement_server_id = NULL WHERE id = $1`, false},
		{"the deprecation date", `UPDATE mcp_servers SET deprecated_at = now() - interval '1 day' WHERE id = $1`, false},
		{"a transfer (the team)", `UPDATE mcp_servers SET team_id = (SELECT id FROM teams WHERE slug = 'j2') WHERE id = $1`, true},
	} {
		if c.name == "a transfer (the team)" {
			run(`INSERT INTO teams(slug,name) VALUES('j2','J2')`)
		}
		before := epoch()
		run(c.sql, srv)
		if got := epoch(); (got > before) != c.advance {
			t.Errorf("%s: epoch %d -> %d, advance should be %v", c.name, before, got, c.advance)
		}
	}
	before := epoch()
	run(`UPDATE gateways SET max_sensitivity = 'internal' WHERE id = $1`, gw)
	if epoch() <= before {
		t.Error("a gateway's ceiling did not advance the epoch")
	}
	before = epoch()
	run(`UPDATE gateways SET max_sensitivity = 'internal' WHERE id = $1`, gw)
	if epoch() != before {
		t.Error("writing the same ceiling advanced the epoch")
	}
	// The new tables are bookkeeping: no fence entry, no journal entry.
	before = epoch()
	run(`INSERT INTO server_transfers(server_id,from_team_id,to_team_id,server_revision) VALUES($1,$2,(SELECT id FROM teams WHERE slug='j2'),1)`, srv, team)
	run(`INSERT INTO server_governance_notices(kind,server_id,stamp) VALUES('review_due',$1,now())`, srv)
	if epoch() != before {
		t.Error("a transfer record or a notice advanced the epoch")
	}
}
