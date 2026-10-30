package registry

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
)

// xferEnv adds a receiving team to the governance fixture.
type xferEnv struct {
	*govEnv
	recv                 uuid.UUID
	recvOwner, recvAdmin uuid.UUID
	recvEditor           uuid.UUID
}

func newXferEnv(t *testing.T) *xferEnv {
	e := &xferEnv{govEnv: newGovEnv(t)}
	e.recv = e.mustID(`INSERT INTO teams (slug, name) VALUES ('recv', 'Recv') RETURNING id`)
	person := func(name, role string) uuid.UUID {
		u := e.mustID(`INSERT INTO users (oidc_issuer, oidc_subject, email, display_name) VALUES ('t', $1, $1 || '@example.invalid', $1) RETURNING id`, name)
		e.run(`INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3)`, e.recv, u, role)
		return u
	}
	e.recvOwner, e.recvAdmin, e.recvEditor = person("recv-owner", "owner"), person("recv-admin", "admin"), person("recv-editor", "editor")
	return e
}

func (e *xferEnv) request(srv uuid.UUID) TransferView {
	e.t.Helper()
	v, err := e.s.RequestTransfer(e.ctx, e.actor(e.admin), "gov", srv, "recv", nil)
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}

func (e *xferEnv) teamOf(srv uuid.UUID) uuid.UUID {
	return e.mustID(`SELECT team_id FROM mcp_servers WHERE id = $1`, srv)
}

func TestTransferRequestRules(t *testing.T) {
	e := newXferEnv(t)
	srv := e.server("tr-rules", "published")
	for name, who := range map[string]uuid.UUID{"editor": e.editor, "member": e.member} {
		if _, err := e.s.RequestTransfer(e.ctx, e.actor(who), "gov", srv, "recv", nil); code(err) != "governance_role" && code(err) != "forbidden" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.s.RequestTransfer(e.ctx, e.actor(e.outsider), "gov", srv, "recv", nil); code(err) != "team_not_found" {
		t.Errorf("outsider: %v", err)
	}
	tok := authz.Actor{Kind: authz.KindAutomationToken, TokenKind: authz.TokenTeamPublisher, TokenTeamID: e.team, TokenScopes: []string{authz.ScopeServersWrite}}
	if _, err := e.s.RequestTransfer(e.ctx, tok, "gov", srv, "recv", nil); code(err) != "token_not_allowed" {
		t.Errorf("token: %v", err)
	}
	archived := e.mustID(`INSERT INTO teams (slug, name, status, archived_at) VALUES ('old', 'Old', 'archived', now()) RETURNING id`)
	_ = archived
	for name, to := range map[string]string{"itself": "gov", "nobody": "nope", "an archived team": "old"} {
		if _, err := e.s.RequestTransfer(e.ctx, e.actor(e.admin), "gov", srv, to, nil); code(err) != "invalid_team" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.s.RequestTransfer(e.ctx, e.actor(e.admin), "gov", e.mustID(`SELECT gen_random_uuid()`), "recv", nil); code(err) != "mcp_server_not_found" {
		t.Errorf("unknown server: %v", err)
	}
	long := strings.Repeat("x", 501)
	if _, err := e.s.RequestTransfer(e.ctx, e.actor(e.admin), "gov", srv, "recv", &long); err == nil {
		t.Error("a 501-character note")
	}
	v := e.request(srv)
	if v.Transfer.State != TransferPending || v.ToTeamSlug != "recv" || v.FromTeamSlug != "gov" || v.Transfer.Revision != 1 || v.Transfer.ServerRevision != e.rev(srv) {
		t.Fatalf("transfer = %+v", v)
	}
	if _, err := e.s.RequestTransfer(e.ctx, e.actor(e.owner), "gov", srv, "recv", nil); code(err) != "transfer_pending" {
		t.Errorf("second request: %v", err)
	}
	if e.teamOf(srv) != e.team {
		t.Error("requesting moved the server")
	}
	if e.count(`SELECT count(*) FROM audit_log WHERE action = 'mcp_server.transfer_request' AND target_id = $1`, srv.String()) != 1 {
		t.Error("the request was not audited")
	}
	// Both teams' admins see it; a member does not; an unrelated team does not.
	for name, c := range map[string]struct {
		team string
		who  uuid.UUID
		n    int
		err  string
	}{"offering admin": {"gov", e.admin, 1, ""}, "receiving admin": {"recv", e.recvAdmin, 1, ""}, "platform": {"recv", e.platform, 1, ""},
		"offering editor": {"gov", e.editor, 0, "governance_role"}, "outsider": {"recv", e.outsider, 0, "team_not_found"}} {
		got, err := e.s.ListTransfers(e.ctx, e.actor(c.who), c.team, true)
		if code(err) != c.err || len(got) != c.n {
			t.Errorf("%s: %d %v", name, len(got), err)
		}
	}
}

// Accepting moves the server with everything bound to it, makes the accepting
// owner its owner and, under approval_required, puts a published server back
// in review.
func TestTransferAcceptKeepsWhatIsBoundToTheServer(t *testing.T) {
	e := newXferEnv(t)
	srv := e.server("tr-keep", "published")
	// What is bound to the server itself: a sealed header, a gateway selection,
	// a grant, an approval rule and an owner of the old team.
	sealed, err := e.s.box.Seal([]byte("s3cret"), ServerAAD(srv))
	if err != nil {
		t.Fatal(err)
	}
	e.run(`UPDATE mcp_servers SET auth_header_name = 'X-Key', auth_value_cipher = $2, auth_value_hint = 'cret', owner_user_id = $3 WHERE id = $1`, srv, sealed, e.editor)
	gw := e.mustID(`INSERT INTO gateways (slug, name, owner_kind) VALUES ('plat', 'Plat', 'platform') RETURNING id`)
	teamGw := e.mustID(`INSERT INTO gateways (slug, name, owner_kind, team_id) VALUES ('mine', 'Mine', 'team', $1) RETURNING id`, e.team)
	capID := e.mustID(`SELECT id FROM mcp_capabilities WHERE server_id = $1`, srv)
	for _, g := range []uuid.UUID{gw, teamGw} {
		e.run(`INSERT INTO gateway_capabilities (gateway_id, capability_id) VALUES ($1, $2)`, g, capID)
	}
	e.run(`INSERT INTO gateway_grants (gateway_id, subject_kind, team_id) VALUES ($1, 'team', $2)`, gw, e.team)
	rule := e.mustID(`INSERT INTO approval_rules (name, team_id, target_kind, target_id, classes, created_by) VALUES ('r', $1, 'server', $2, '{destructive}', $3) RETURNING id`, e.team, srv, e.owner)
	counts := func() string {
		return e.str(`SELECT (SELECT count(*) FROM gateway_capabilities) || '/' || (SELECT count(*) FROM gateway_grants) || '/' || (SELECT count(*) FROM mcp_capabilities)
			|| '/' || (SELECT count(*) FROM gateways)`)
	}
	before := counts()
	tr := e.request(srv)

	// Only an owner of the receiving team accepts; not the offering team, not an admin, not a stale revision.
	if _, err := e.s.AcceptTransfer(e.ctx, e.actor(e.recvAdmin), "recv", tr.Transfer.ID, 1); code(err) != "owner_required" {
		t.Errorf("receiving admin: %v", err)
	}
	if _, err := e.s.AcceptTransfer(e.ctx, e.actor(e.owner), "gov", tr.Transfer.ID, 1); code(err) != "transfer_not_found" {
		t.Errorf("the offering owner accepted: %v", err)
	}
	if _, err := e.s.AcceptTransfer(e.ctx, e.actor(e.outsider), "recv", tr.Transfer.ID, 1); code(err) != "team_not_found" {
		t.Errorf("outsider: %v", err)
	}
	if _, err := e.s.AcceptTransfer(e.ctx, e.actor(e.recvOwner), "recv", tr.Transfer.ID, 9); code(err) != "stale_revision" && code(err) != "revision_conflict" && err == nil {
		t.Errorf("stale revision: %v", err)
	}
	tok := authz.Actor{Kind: authz.KindAutomationToken, TokenKind: authz.TokenPlatformAdmin, TokenScopes: []string{authz.ScopePlatformWrite}}
	if _, err := e.s.AcceptTransfer(e.ctx, tok, "recv", tr.Transfer.ID, 1); code(err) != "token_not_allowed" {
		t.Errorf("token: %v", err)
	}
	if e.teamOf(srv) != e.team {
		t.Fatal("a refused accept moved the server")
	}

	got, err := e.s.AcceptTransfer(e.ctx, e.actor(e.recvOwner), "recv", tr.Transfer.ID, 1)
	if err != nil || got.Transfer.State != TransferAccepted || got.Transfer.Revision != 2 {
		t.Fatalf("accepted: %+v %v", got, err)
	}
	if e.teamOf(srv) != e.recv {
		t.Fatal("the server did not move")
	}
	st, _, _ := e.row(srv)
	if st != "pending" {
		t.Errorf("a published server under approval_required is %s after the move", st)
	}
	if e.mustID(`SELECT owner_user_id FROM mcp_servers WHERE id = $1`, srv) != e.recvOwner {
		t.Error("the accepting owner is not the owner")
	}
	if after := counts(); after != before {
		t.Errorf("selections, grants, capabilities, gateways: %s before, %s after", before, after)
	}
	// The sealed header still opens: it is bound to the server, not the team.
	var cipher []byte
	if err := e.s.pool.QueryRow(e.ctx, `SELECT auth_value_cipher FROM mcp_servers WHERE id = $1`, srv).Scan(&cipher); err != nil {
		t.Fatal(err)
	}
	if plain, err := e.s.box.Open(cipher, ServerAAD(srv)); err != nil || string(plain) != "s3cret" {
		t.Errorf("sealed header after the move: %q %v", plain, err)
	}
	// The approval rule moved with the server, so the old team can't loosen it.
	if e.mustID(`SELECT team_id FROM approval_rules WHERE id = $1`, rule) != e.recv {
		t.Error("the approval rule stayed with the old team")
	}
	for _, a := range []string{"mcp_server.transfer", "mcp_server.publish_request"} {
		if e.count(`SELECT count(*) FROM audit_log WHERE action = $1 AND target_id = $2 AND team_id = $3`, a, srv.String(), e.recv) != 1 {
			t.Errorf("no %s audit entry in the same transaction", a)
		}
	}
	if e.count(`SELECT count(*) FROM audit_log WHERE action = 'mcp_server.transfer' AND (metadata->>'fromTeamGatewaySelections')::int = 1`) != 1 {
		t.Error("the old team's gateway selections were not recorded")
	}
	// The old team no longer reaches it.
	if _, err := e.s.GetTeam(e.ctx, e.actor(e.admin), "gov", srv); code(err) != "mcp_server_not_found" {
		t.Errorf("old team's view: %v", err)
	}
	if _, err := e.s.GetTeam(e.ctx, e.actor(e.recvEditor), "recv", srv); err != nil {
		t.Errorf("new team's view: %v", err)
	}
	// A closed transfer cannot be answered again.
	if _, err := e.s.AcceptTransfer(e.ctx, e.actor(e.recvOwner), "recv", tr.Transfer.ID, 2); code(err) != "transfer_closed" {
		t.Errorf("second accept: %v", err)
	}
	if _, err := e.s.CancelTransfer(e.ctx, e.actor(e.recvOwner), "recv", tr.Transfer.ID, 2); code(err) != "transfer_closed" {
		t.Errorf("cancel after accept: %v", err)
	}
	// Approval again, and the server serves as before.
	if _, err := e.s.Review(e.ctx, e.actor(e.platform), srv, DecisionApprove, nil, e.digestOf(srv)); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := e.row(srv); st != "published" {
		t.Errorf("after approval: %s", st)
	}
}

func TestTransferUnderSelfPublishKeepsPublished(t *testing.T) {
	e := newXferEnv(t)
	e.run(`UPDATE teams SET publish_policy_override = 'self_publish' WHERE id = $1`, e.recv)
	srv := e.server("tr-self", "published")
	priv := e.server("tr-priv", "private")
	for _, s := range []uuid.UUID{srv, priv} {
		tr := e.request(s)
		if _, err := e.s.AcceptTransfer(e.ctx, e.actor(e.recvOwner), "recv", tr.Transfer.ID, 1); err != nil {
			t.Fatal(err)
		}
	}
	if st, _, _ := e.row(srv); st != "published" {
		t.Errorf("the receiving team approves its own: %s", st)
	}
	if st, _, _ := e.row(priv); st != "private" {
		t.Errorf("private server: %s", st)
	}
}

func TestTransferCancelDeclineAndStaleServer(t *testing.T) {
	e := newXferEnv(t)
	// The offering team withdraws; the receiving team declines.
	a, b := e.server("tr-c1", "private"), e.server("tr-c2", "private")
	t1, t2 := e.request(a), e.request(b)
	if _, err := e.s.CancelTransfer(e.ctx, e.actor(e.editor), "gov", t1.Transfer.ID, 1); code(err) != "governance_role" && code(err) != "forbidden" {
		t.Errorf("editor cancelled: %v", err)
	}
	if _, err := e.s.CancelTransfer(e.ctx, e.actor(e.outsider), "gov", t1.Transfer.ID, 1); code(err) != "team_not_found" {
		t.Errorf("outsider: %v", err)
	}
	if _, err := e.s.CancelTransfer(e.ctx, e.actor(e.recvOwner), "gov", t1.Transfer.ID, 1); code(err) != "team_not_found" {
		t.Errorf("a team that is not in the path: %v", err)
	}
	if v, err := e.s.CancelTransfer(e.ctx, e.actor(e.admin), "gov", t1.Transfer.ID, 1); err != nil || v.Transfer.State != TransferCancelled {
		t.Errorf("withdraw: %+v %v", v.Transfer, err)
	}
	if v, err := e.s.CancelTransfer(e.ctx, e.actor(e.recvAdmin), "recv", t2.Transfer.ID, 1); err != nil || v.Transfer.State != TransferDeclined {
		t.Errorf("decline: %+v %v", v.Transfer, err)
	}
	if _, err := e.s.AcceptTransfer(e.ctx, e.actor(e.recvOwner), "recv", t2.Transfer.ID, 2); code(err) != "transfer_closed" {
		t.Errorf("accepting a declined transfer: %v", err)
	}
	if e.teamOf(a) != e.team || e.teamOf(b) != e.team {
		t.Error("a closed transfer moved a server")
	}
	if e.count(`SELECT count(*) FROM audit_log WHERE action = 'mcp_server.transfer_cancel'`) != 2 {
		t.Error("closing was not audited")
	}
	// After a withdrawal the server can be offered again.
	e.request(a)

	// A server edited after the request is not what the owner was shown.
	c := e.server("tr-c3", "private")
	t3 := e.request(c)
	if _, err := e.s.Update(e.ctx, e.actor(e.editor), "gov", c, UpdateInput{Description: str("now different")}, e.rev(c)); err != nil {
		t.Fatal(err)
	}
	_, err := e.s.AcceptTransfer(e.ctx, e.actor(e.recvOwner), "recv", t3.Transfer.ID, 1)
	if code(err) != "changed_since_request" {
		t.Fatalf("accepting a server changed after the request: %v", err)
	}
	if e.teamOf(c) != e.team {
		t.Error("it moved anyway")
	}
}

func TestTransferRefusedWhenItWouldStopTheServersCalls(t *testing.T) {
	e := newXferEnv(t)
	srv := e.server("tr-prov", "private")
	prov := e.mustID(`INSERT INTO auth_providers (slug, name, client_id, token_auth_method, pkce, authorization_url, token_url, access_mode) VALUES ('p', 'P', 'c', 'none', true, 'https://a.example.com/a', 'https://a.example.com/t', 'restricted') RETURNING id`)
	e.run(`UPDATE mcp_servers SET auth_provider_id = $2 WHERE id = $1`, srv, prov)
	e.run(`INSERT INTO auth_provider_teams (provider_id, team_id) VALUES ($1, $2)`, prov, e.team)
	if _, err := e.s.RequestTransfer(e.ctx, e.actor(e.admin), "gov", srv, "recv", nil); code(err) != "provider_not_allowed" {
		t.Fatalf("request: %v", err)
	}
	e.run(`INSERT INTO auth_provider_teams (provider_id, team_id) VALUES ($1, $2)`, prov, e.recv)
	tr := e.request(srv)
	e.run(`DELETE FROM auth_provider_teams WHERE team_id = $1`, e.recv)
	if _, err := e.s.AcceptTransfer(e.ctx, e.actor(e.recvOwner), "recv", tr.Transfer.ID, 1); code(err) != "provider_not_allowed" {
		t.Fatalf("accept after the provider list changed: %v", err)
	}
	if e.teamOf(srv) != e.team {
		t.Error("the server moved although its provider would refuse the new team")
	}
	e.run(`INSERT INTO auth_provider_servers (provider_id, server_id) VALUES ($1, $2)`, prov, srv)
	if _, err := e.s.AcceptTransfer(e.ctx, e.actor(e.recvOwner), "recv", tr.Transfer.ID, 1); err != nil {
		t.Errorf("a provider that lists the server itself: %v", err)
	}
}

func TestForceTransfer(t *testing.T) {
	e := newXferEnv(t)
	srv := e.server("tr-force", "published")
	e.run(`UPDATE mcp_servers SET owner_user_id = $2 WHERE id = $1`, srv, e.editor)
	tr := e.request(srv)
	for name, a := range map[string]authz.Actor{"team owner": e.actor(e.owner), "recv owner": e.actor(e.recvOwner),
		"token": {Kind: authz.KindAutomationToken, PlatformRole: authz.PlatformAdmin, TokenKind: authz.TokenPlatformAdmin, TokenScopes: []string{authz.ScopePlatformWrite}}} {
		if _, err := e.s.ForceTransfer(e.ctx, a, srv, "recv", nil, e.rev(srv)); code(err) != "forbidden" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.s.ForceTransfer(e.ctx, e.actor(e.platform), srv, "recv", nil, e.rev(srv)+5); err == nil {
		t.Error("a stale server revision was accepted")
	}
	if _, err := e.s.ForceTransfer(e.ctx, e.actor(e.platform), srv, "gov", nil, e.rev(srv)); code(err) != "invalid_team" {
		t.Errorf("to its own team: %v", err)
	}
	v, err := e.s.ForceTransfer(e.ctx, e.actor(e.platform), srv, "recv", str("team gone"), e.rev(srv))
	if err != nil {
		t.Fatal(err)
	}
	if v.Server.TeamID != e.recv || v.Server.PublishState != StatePending || v.Governance.OwnerUserID.Valid || !v.Governance.Ownerless {
		t.Errorf("forced: team %v state %s governance %+v", v.Server.TeamID, v.Server.PublishState, v.Governance)
	}
	if got := e.str(`SELECT state FROM server_transfers WHERE id = $1::uuid`, tr.Transfer.ID); got != TransferCancelled {
		t.Errorf("the open transfer is %s", got)
	}
	if e.count(`SELECT count(*) FROM server_transfers WHERE server_id = $1 AND state = 'forced' AND accepted_by = $2`, srv, e.platform) != 1 {
		t.Error("the forced transfer is not recorded")
	}
	if e.count(`SELECT count(*) FROM audit_log WHERE action = 'mcp_server.transfer' AND metadata->>'kind' = 'forced' AND actor_user_id = $1`, e.platform) != 1 {
		t.Error("the forced transfer is not audited")
	}
}

// Concurrent answers to one transfer: exactly one wins and the server ends where
// the winner says.
func TestTransferRaces(t *testing.T) {
	e := newXferEnv(t)
	race := func(fs ...func() error) []error {
		start := make(chan struct{})
		out := make([]error, len(fs))
		var wg sync.WaitGroup
		for i, f := range fs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				out[i] = f()
			}()
		}
		close(start)
		wg.Wait()
		return out
	}
	accept := func(tr uuid.UUID) func() error {
		return func() error {
			_, err := e.s.AcceptTransfer(e.ctx, e.actor(e.recvOwner), "recv", tr, 1)
			return err
		}
	}
	cancel := func(tr uuid.UUID) func() error {
		return func() error {
			_, err := e.s.CancelTransfer(e.ctx, e.actor(e.admin), "gov", tr, 1)
			return err
		}
	}
	for i := 0; i < 12; i++ {
		// accept vs withdraw
		srv := e.server(fmt.Sprintf("race-a-%d", i), "private")
		tr := e.request(srv).Transfer.ID
		res := race(accept(tr), cancel(tr))
		wins := 0
		for _, err := range res {
			if err == nil {
				wins++
			} else if code(err) != "transfer_closed" {
				t.Fatalf("round %d: %v", i, err)
			}
		}
		state := e.str(`SELECT state FROM server_transfers WHERE id = $1::uuid`, tr)
		moved := e.teamOf(srv) == e.recv
		if wins != 1 || (moved && state != TransferAccepted) || (!moved && state != TransferCancelled) {
			t.Fatalf("round %d: %d winners, state %s, moved %v", i, wins, state, moved)
		}
		// two accepts
		srv2 := e.server(fmt.Sprintf("race-b-%d", i), "private")
		tr2 := e.request(srv2).Transfer.ID
		res = race(accept(tr2), accept(tr2))
		if (res[0] == nil) == (res[1] == nil) || e.teamOf(srv2) != e.recv {
			t.Fatalf("round %d: two accepts gave %v", i, res)
		}
		// accept vs an edit of the server by the offering team
		srv3 := e.server(fmt.Sprintf("race-c-%d", i), "private")
		tr3 := e.request(srv3).Transfer.ID
		rev := e.rev(srv3)
		res = race(accept(tr3), func() error {
			_, err := e.s.Update(e.ctx, e.actor(e.editor), "gov", srv3, UpdateInput{Description: str("edit")}, rev)
			return err
		})
		moved = e.teamOf(srv3) == e.recv
		switch {
		case res[0] == nil && res[1] != nil && code(res[1]) == "mcp_server_not_found" && moved:
		case res[0] != nil && code(res[0]) == "changed_since_request" && res[1] == nil && !moved:
		default:
			t.Fatalf("round %d: accept vs edit gave %v / %v (moved %v)", i, res[0], res[1], moved)
		}
		// two requests for one server
		srv4 := e.server(fmt.Sprintf("race-d-%d", i), "private")
		req := func() error {
			_, err := e.s.RequestTransfer(e.ctx, e.actor(e.admin), "gov", srv4, "recv", nil)
			return err
		}
		res = race(req, req)
		if (res[0] == nil) == (res[1] == nil) || e.count(`SELECT count(*) FROM server_transfers WHERE server_id = $1 AND state = 'pending'`, srv4) != 1 {
			t.Fatalf("round %d: two requests gave %v", i, res)
		}
	}
}
