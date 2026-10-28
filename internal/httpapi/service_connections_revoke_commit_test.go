package httpapi_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestServiceConnectionRevokeLocalAuditFailureDoesNotCallProvider(t *testing.T) {
	e := newProvEnv(t)
	c := connectShared(t, e.owner, e.provider.Id, "revoke-rollback")
	_, err := testutil.OwnerPool(t, e.app.Pool).Exec(context.Background(), `CREATE FUNCTION fail_local_revoke() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='service_connection.revoke' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
CREATE TRIGGER fail_local_revoke BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fail_local_revoke();`)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := e.owner.call("DELETE", sharedBase+"/"+c.Id.String(), nil, nil, nil)
	if code != 500 {
		t.Fatalf("local audit failure = %d", code)
	}
	if n := e.scalar(`SELECT count(*)::text FROM service_connections WHERE id=$1 AND access_token_cipher IS NOT NULL`, c.Id); n != "1" {
		t.Fatal("failed local audit did not roll back deletion")
	}
	if len(e.oauth.Revoked()) != 0 {
		t.Fatal("provider token was revoked despite local rollback")
	}
}

func TestServiceConnectionRevokeCommitsBeforeProviderHTTP(t *testing.T) {
	for _, kind := range []string{"success", "remote_failure", "outcome_audit_failure"} {
		t.Run(kind, func(t *testing.T) {
			e := newProvEnv(t)
			sa := createSA(t, e.owner, map[string]any{"name": "revoke-ci"})
			key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
			c := connectShared(t, e.owner, e.provider.Id, "revoke-committed")
			code, ec, c := assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}}})
			mustCode(t, "assign before revoke", code, ec, 200, "")
			if kind == "outcome_audit_failure" {
				_, err := testutil.OwnerPool(t, e.app.Pool).Exec(context.Background(), `CREATE FUNCTION fail_revocation_outcome() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='service_connection.revocation_result' THEN RAISE EXCEPTION 'outcome unavailable'; END IF; RETURN NEW; END; $$;
CREATE TRIGGER fail_revocation_outcome BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fail_revocation_outcome();`)
				if err != nil {
					t.Fatal(err)
				}
			}
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			e.oauth.Set(func(f *testutil.FakeOAuth) {
				f.BeforeRevoke = func() { close(entered); <-release }
				f.FailRevoke = kind == "remote_failure"
			})
			g := pauseServiceMutation(t, e, `SELECT 1`)
			done := g.launch("DELETE", sharedBase+"/"+c.Id.String(), nil, c.Revision)
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("provider revocation not reached")
			}
			// Independent runtime reads see BOTH the deletion and its local audit
			// while provider HTTP is still blocked. Cascaded assignments are gone.
			if n := e.scalar(`SELECT count(*)::text FROM service_connections WHERE id=$1`, c.Id); n != "0" {
				t.Fatal("provider HTTP began before local deletion committed")
			}
			if n := e.scalar(`SELECT count(*)::text FROM service_connection_accounts WHERE connection_id=$1`, c.Id); n != "0" {
				t.Fatal("assignment survived local deletion")
			}
			if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action='service_connection.revoke' AND target_id=$1`, c.Id.String()); n != "1" {
				t.Fatal("local revoke audit is not committed during provider HTTP")
			}
			// This mutation would block if revocation held team/user row locks.
			if _, err := e.app.Pool.Exec(g.ctx, `UPDATE team_members SET role='editor' WHERE user_id=$1`, e.owner.me.User.Id); err != nil {
				t.Fatal(err)
			}
			serviceDenied(t, e.callTool(key, f3Tool), "service_connection_missing")
			code, ec = e.owner.call("POST", sharedBase, map[string]any{"providerId": e.provider.Id, "name": "still-denied"}, nil, nil)
			mustCode(t, "demoted actor remains denied", code, ec, 403, "forbidden")
			unblock()
			g.finish(done, 200, "")
			if n := e.scalar(`SELECT count(*)::text FROM service_connections WHERE id=$1`, c.Id); n != "0" {
				t.Fatal("post-commit remote result reinstated deleted connection")
			}
			if kind == "outcome_audit_failure" {
				if !strings.Contains(e.logs.String(), "revocation outcome audit failed") || !strings.Contains(e.logs.String(), c.Id.String()) {
					t.Fatal("missing safe post-commit audit failure log")
				}
			} else {
				want := "true"
				if kind == "remote_failure" {
					want = "false"
				}
				if got := e.scalar(`SELECT metadata->>'providerRevoked' FROM audit_log WHERE action='service_connection.revocation_result' AND target_id=$1 AND actor_kind='system' AND actor_user_id IS NULL`, c.Id.String()); got != want {
					t.Fatalf("remote outcome = %q, want %q", got, want)
				}
			}
		})
	}
}
