package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// A real deferred commit failure must not occur after an irreversible provider
// request. The local row and its original sealed tokens must remain untouched.
func TestPersonalDisconnectDoesNotRevokeOnCommitFailure(t *testing.T) {
	var calls atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer remote.Close()
	s, pool, actor, id := personalDisconnectFixture(t, remote.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := testutil.OwnerPool(t, pool).Exec(ctx, `
CREATE FUNCTION reject_personal_disconnect_commit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'owned fixture commit failure'; END $$;
CREATE CONSTRAINT TRIGGER reject_personal_disconnect_commit AFTER DELETE ON provider_connections
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_personal_disconnect_commit()`); err != nil {
		t.Fatal("install deferred commit failure:", err)
	}
	before, err := s.q.LockProviderConnectionByID(ctx, id)
	if err != nil {
		t.Fatal("read original connection:", err)
	}
	if err := s.RevokeMine(ctx, actor, id); err == nil {
		t.Fatal("expected the real transaction commit to fail")
	}
	if calls.Load() != 0 {
		t.Error("provider revocation was sent before local deletion committed")
	}
	after, err := s.q.LockProviderConnectionByID(ctx, id)
	if err != nil {
		t.Fatal("failed commit did not preserve the original connection")
	}
	if string(before.AccessTokenCipher) != string(after.AccessTokenCipher) || string(before.RefreshTokenCipher) != string(after.RefreshTokenCipher) {
		t.Error("failed commit changed sealed tokens")
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE target_type='provider_connection' AND target_id=$1`, id.String()).Scan(&audits); err != nil || audits != 0 {
		t.Error("failed commit left a successful revocation audit")
	}
}

// The HTTP barrier measures actual network entry, not a sleep or an SQL model.
// Local deletion and its initiating audit must already be visible while the
// provider is blocked; remote failure cannot undo that commit.
func TestPersonalDisconnectCommitsBeforeRemoteRevocation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"success", http.StatusOK},
		{"remote_failure", http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			var calls atomic.Int32
			remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if err := r.ParseForm(); err != nil || r.Form.Get("token") != "disconnect-fixture-refresh" || r.Form.Get("token_type_hint") != "refresh_token" {
					t.Error("revocation did not use the original refresh token and hint")
				}
				close(entered)
				select {
				case <-release:
				case <-r.Context().Done():
				}
				w.WriteHeader(tc.status)
			}))
			defer remote.Close()
			defer unblock()
			s, pool, actor, id := personalDisconnectFixture(t, remote.URL)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			finished := make(chan error, 1)
			go func() { finished <- s.RevokeMine(ctx, actor, id) }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("provider request did not reach the explicit HTTP barrier")
			}
			var remaining, intent int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM provider_connections WHERE id=$1`, id).Scan(&remaining); err != nil || remaining != 0 {
				t.Error("local connection deletion is not committed while provider revocation is blocked")
			}
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='provider_connection.revoke' AND target_id=$1 AND actor_user_id=$2 AND metadata->>'reason'='user' AND metadata->>'providerRevocation'='best_effort_after_commit'`, id.String(), actor.UserID).Scan(&intent); err != nil || intent != 1 {
				t.Error("initiating local revocation audit is not committed before provider I/O")
			}
			unblock()
			select {
			case err := <-finished:
				if err != nil {
					t.Error("remote result changed committed local success:", err)
				}
			case <-ctx.Done():
				t.Fatal("disconnect failed to finish after releasing the HTTP barrier")
			}
			var outcomes int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='provider_connection.revocation_result' AND target_id=$1 AND actor_kind='system' AND actor_user_id IS NULL AND (metadata->>'providerRevoked')::boolean=$2`, id.String(), tc.status == http.StatusOK).Scan(&outcomes); err != nil || outcomes != 1 {
				t.Error("missing exact secret-free system outcome with actual provider result")
			}
			if calls.Load() != 1 {
				t.Error("revocation was retried or omitted")
			}
		})
	}
}

func personalDisconnectFixture(t *testing.T, endpoint string) (*Service, *pgxpool.Pool, authz.Actor, uuid.UUID) {
	t.Helper()
	pool, _ := testutil.NewDB(t)
	s := testService(t, &upstream.Client{AllowPrivate: true})
	s.pool, s.q = pool, dbgen.New(pool)
	t.Cleanup(s.tr.CloseIdleConnections)
	ctx := context.Background()
	user, provider, connection := uuid.New(), uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,display_name,oidc_issuer,oidc_subject)
VALUES ($1,'disconnect-fixture@example.test','Disconnect fixture','test-disconnect',$2)`, user, user.String()); err != nil {
		t.Fatal("create owned fixture user:", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO auth_providers(id,slug,name,client_id,token_auth_method,authorization_url,token_url,revocation_url)
VALUES ($1,'disconnect-fixture','Disconnect fixture','disconnect-fixture-client','none',$2,$2,$2)`, provider, endpoint); err != nil {
		t.Fatal("create owned fixture provider:", err)
	}
	access, err := s.seal(connection, "access", "disconnect-fixture-access")
	if err != nil {
		t.Fatal("seal fixture access token:", err)
	}
	refresh, err := s.seal(connection, "refresh", "disconnect-fixture-refresh")
	if err != nil {
		t.Fatal("seal fixture refresh token:", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO provider_connections(id,user_id,provider_id,status,access_token_cipher,refresh_token_cipher)
VALUES ($1,$2,$3,'active',$4,$5)`, connection, user, provider, access, refresh); err != nil {
		t.Fatal("create owned fixture connection:", err)
	}
	return s, pool, authz.Actor{UserID: user, RequestID: "disconnect-commit-proof"}, connection
}
