package httpapi_test

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

const sharedBase = toolsTeam + "/service-connections"

func sharedList(t *testing.T, s *session) []apitypes.ServiceConnection {
	t.Helper()
	var cs []apitypes.ServiceConnection
	if code := s.get(sharedBase, &cs); code != 200 {
		t.Fatalf("list shared = %d", code)
	}
	return cs
}
func sharedByName(t *testing.T, s *session, name string) apitypes.ServiceConnection {
	t.Helper()
	for _, c := range sharedList(t, s) {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("missing shared %s", name)
	return apitypes.ServiceConnection{}
}
func startShared(t *testing.T, s *session, p uuid.UUID, name string) apitypes.ConnectStarted {
	t.Helper()
	var st apitypes.ConnectStarted
	c, ec := s.call("POST", sharedBase, map[string]any{"providerId": p, "name": name, "scopes": []string{"repo"}}, &st, nil)
	mustCode(t, "start shared", c, ec, 200, "")
	return st
}
func connectShared(t *testing.T, s *session, p uuid.UUID, name string) apitypes.ServiceConnection {
	t.Helper()
	st := startShared(t, s, p, name)
	if to := callback(t, s, providerAuthorize(t, s, st.AuthorizeUrl)); !strings.Contains(to, "result=connected") {
		t.Fatalf("shared callback = %s", to)
	}
	return sharedByName(t, s, name)
}
func assignShared(t *testing.T, s *session, c apitypes.ServiceConnection, accounts []uuid.UUID, grants []apitypes.ServiceConnectionGrant) (int, string, apitypes.ServiceConnection) {
	t.Helper()
	if accounts == nil {
		accounts = []uuid.UUID{}
	}
	if grants == nil {
		grants = []apitypes.ServiceConnectionGrant{}
	}
	var out apitypes.ServiceConnection
	code, ec := s.call("PUT", sharedBase+"/"+c.Id.String(), map[string]any{"accounts": accounts, "servers": grants}, &out, ifMatch(c.Revision))
	return code, ec, out
}
func serviceDenied(t *testing.T, out map[string]any, reason string) {
	t.Helper()
	c, msg, data := rpcErr(out)
	if c != -32010 || data["reason"] != reason || strings.Contains(msg, "http") || data["elicitations"] != nil {
		t.Fatalf("want link-free %s: %v", reason, out)
	}
}
func TestServiceConnectionsPlatformRuntimeAndOwnership(t *testing.T) {
	e := newProvEnv(t)
	sa := createSA(t, e.owner, map[string]any{"name": "shared-ci"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
	serviceDenied(t, e.callTool(key, f3Tool), "service_connection_missing")
	if n := e.scalar(`SELECT count(*)::text FROM provider_connect_requests`); n != "0" {
		t.Fatal("service call created personal consent")
	}
	c := connectShared(t, e.owner, e.provider.Id, "release")
	if c.AccountLabel == nil || c.Status != "active" {
		t.Fatalf("metadata = %+v", c)
	}
	if n := e.scalar(`SELECT count(*)::text FROM provider_connections`); n != "0" {
		t.Fatal("service callback wrote personal connection")
	}
	serviceDenied(t, e.callTool(key, f3Tool), "service_connection_missing")
	code, ec, c := assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, nil)
	mustCode(t, "account assign", code, ec, 200, "")
	serviceDenied(t, e.callTool(key, f3Tool), "service_connection_not_allowed")
	grant := apitypes.ServiceConnectionGrant{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}}
	code, ec, c = assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{grant})
	mustCode(t, "grant", code, ec, 200, "")
	if rep := e.providerReport(e.callTool(key, f3Tool)); !rep.Received || rep.Provider != "github" {
		t.Fatalf("provider = %+v", rep)
	}
	// The metadata identity remains the service account, never its connector.
	if principal := e.scalar(`SELECT principal_kind FROM mcp_calls ORDER BY id DESC LIMIT 1`); principal != "service_account" {
		t.Fatalf("principal = %s", principal)
	}
	// Exactly one assignment per account/provider, enforced even across connections.
	other := connectShared(t, e.owner, e.provider.Id, "other")
	code, ec, _ = assignShared(t, e.owner, other, []uuid.UUID{sa.Id}, nil)
	mustCode(t, "assignment conflict", code, ec, 409, "connection_conflict")
	code, ec, _ = assignShared(t, e.member, c, []uuid.UUID{sa.Id}, nil)
	mustCode(t, "member change", code, ec, 403, "")
	code, ec, _ = assignShared(t, e.outsider, c, nil, nil)
	mustCode(t, "foreign team", code, ec, 404, "")
	foreignID := uuid.MustParse(e.scalar(`INSERT INTO service_accounts(team_id,name) SELECT id,'foreign-ci' FROM teams WHERE slug='other' RETURNING id::text`))
	code, ec, _ = assignShared(t, e.owner, c, []uuid.UUID{foreignID}, nil)
	mustCode(t, "foreign account", code, ec, 404, "service_account_not_found")
	code, ec, _ = assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{{ServerId: e.other.Id, Origin: registry.OriginOf(e.other.Url), Scopes: []string{"repo"}}})
	mustCode(t, "foreign private server", code, ec, 404, "server_not_found")
	stale := c
	stale.Revision--
	code, ec, _ = assignShared(t, e.owner, stale, nil, nil)
	mustCode(t, "stale update", code, ec, 412, "")
	// Derived lapse, without erasing the account: demotion, suspension, removal.
	owner := e.scalar(`SELECT connected_by::text FROM service_connections WHERE id=$1`, c.Id)
	for _, change := range []struct{ set, restore string }{
		{`UPDATE team_members SET role='member' WHERE user_id=$1`, `UPDATE team_members SET role='owner' WHERE user_id=$1`},
		{`UPDATE users SET status='suspended' WHERE id=$1`, `UPDATE users SET status='active' WHERE id=$1`},
	} {
		e.scalar(change.set+` RETURNING 'ok'`, owner)
		serviceDenied(t, e.callTool(key, f3Tool), "service_connection_lapsed")
		if x := e.scalar(`SELECT status FROM service_connections WHERE id=$1`, c.Id); x != "active" {
			t.Fatal("lapse destroyed tokens")
		}
		e.scalar(change.restore+` RETURNING 'ok'`, owner)
		if !e.providerReport(e.callTool(key, f3Tool)).Received {
			t.Fatal("role restore didn't restore delivery")
		}
	}
	// Destination provider access, not the connection team's membership.
	e.provider = e.setAccess(e.provider, "restricted", nil, []string{e.other.Id.String()})
	serviceDenied(t, e.callTool(key, f3Tool), "provider_not_allowed")
	e.provider = e.setAccess(e.provider, "open", nil, nil)
	if !e.providerReport(e.callTool(key, f3Tool)).Received {
		t.Fatal("provider access restore failed")
	}
	// Browser session lifetime is irrelevant after successful consent.
	e.scalar(`DELETE FROM sessions WHERE user_id=$1 RETURNING 'ok'`, owner)
	if !e.providerReport(e.callTool(key, f3Tool)).Received {
		t.Fatal("completed consent depended on browser lifetime")
	}
	e.owner = e.app.signIn("user")
	code, ec = e.owner.call("DELETE", sharedBase+"/"+c.Id.String(), nil, nil, nil)
	mustCode(t, "revoke", code, ec, 200, "")
	serviceDenied(t, e.callTool(key, f3Tool), "service_connection_missing")
}
func TestServiceConnectionsStateIsolationAndRaces(t *testing.T) {
	for _, kind := range []string{"wrong_person", "wrong_session", "session_expired", "logout", "revision", "revoke", "provider", "expired", "single_use"} {
		t.Run(kind, func(t *testing.T) {
			e := newProvEnv(t)
			st := startShared(t, e.owner, e.provider.Id, "pending")
			c := sharedByName(t, e.owner, "pending")
			if c.Status != "needs_reconsent" {
				t.Fatalf("first row = %+v", c)
			}
			u, _ := url.Parse(st.AuthorizeUrl)
			state := u.Query().Get("state")
			if n := e.scalar(`SELECT count(*)::text FROM provider_auth_states`); n != "0" {
				t.Fatal("state wasn't isolated from old callbacks")
			}
			loc := providerAuthorize(t, e.owner, st.AuthorizeUrl)
			browser := e.owner
			switch kind {
			case "wrong_person":
				browser = e.member
			case "wrong_session":
				browser = e.app.signIn("user")
			case "session_expired":
				e.scalar(`UPDATE sessions SET expires_at=now()-interval '1 second' WHERE user_id=(SELECT connected_by FROM service_connections WHERE id=$1) RETURNING 'ok'`, c.Id)
			case "logout":
				code, ec := e.owner.call("POST", "/auth/logout", nil, nil, nil)
				mustCode(t, "logout", code, ec, 200, "")
				if n := e.scalar(`SELECT count(*)::text FROM service_connection_auth_states`); n != "0" {
					t.Fatal("logout kept service state")
				}
			case "revision":
				code, ec, _ := assignShared(t, e.owner, c, nil, nil)
				mustCode(t, "update pending", code, ec, 200, "")
			case "revoke":
				code, ec := e.owner.call("DELETE", sharedBase+"/"+c.Id.String(), nil, nil, nil)
				mustCode(t, "revoke pending", code, ec, 200, "")
			case "provider":
				e.scalar(`UPDATE auth_providers SET enabled=false,revision=revision+1 WHERE id=$1 RETURNING 'ok'`, e.provider.Id)
			case "expired":
				e.scalar(`UPDATE service_connection_auth_states SET expires_at=now()-interval '1 minute' RETURNING 'ok'`)
			case "single_use":
				if to := callback(t, browser, loc); !strings.Contains(to, "result=connected") {
					t.Fatalf("first callback %s", to)
				}
			}
			if to := callback(t, browser, loc); strings.Contains(to, "result=connected") {
				t.Fatalf("invalid %s callback succeeded: %s", kind, to)
			}
			if n := e.scalar(`SELECT count(*)::text FROM provider_connections`); n != "0" {
				t.Fatal("callback wrote personal tokens")
			}
			_ = state
		})
	}
}
func TestServiceConnectionOriginAndSecretSentinel(t *testing.T) {
	e := newProvEnv(t)
	sa := createSA(t, e.owner, map[string]any{"name": "origin-ci"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
	c := connectShared(t, e.owner, e.provider.Id, "origin")
	grant := apitypes.ServiceConnectionGrant{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}}
	code, ec, _ := assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{grant})
	mustCode(t, "grant", code, ec, 200, "")
	e.providerReport(e.callTool(key, f3Tool))
	e.scalar(`UPDATE mcp_servers SET url=url||'/path' WHERE id=$1 RETURNING 'ok'`, e.server.Id)
	if n := e.scalar(`SELECT count(*)::text FROM service_connection_server_grants WHERE connection_id=$1`, c.Id); n != "1" {
		t.Fatal("path edit ended grant")
	}
	e.scalar(`UPDATE mcp_servers SET url='https://other.example/mcp' WHERE id=$1 RETURNING 'ok'`, e.server.Id)
	if n := e.scalar(`SELECT count(*)::text FROM service_connection_server_grants WHERE connection_id=$1`, c.Id); n != "0" {
		t.Fatal("origin edit kept grant")
	}
	serviceDenied(t, e.callTool(key, f3Tool), "service_connection_not_allowed")
	metadata := e.scalar(`SELECT coalesce(json_agg(x)::text,'') FROM (SELECT * FROM audit_log) x`) + e.scalar(`SELECT coalesce(json_agg(x)::text,'') FROM (SELECT * FROM mcp_calls) x`) + e.logs.String()
	for _, c := range sharedList(t, e.owner) {
		b, _ := json.Marshal(c)
		metadata += string(b)
	}
	for _, secret := range append(e.oauth.Issued(), e.oauth.IssuedRefresh()...) {
		if strings.Contains(metadata, secret) {
			t.Fatal("upstream token leaked into stored metadata, logs or responses")
		}
	}
}
