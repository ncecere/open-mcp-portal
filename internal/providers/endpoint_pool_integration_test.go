package providers

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// One connection makes any recursive pool read fail deterministically; the
// linked client and every live network-policy read must use the locked TX.
func TestTransactionRefreshSingleConnectionPool(t *testing.T) {
	pool, dsn := testutil.NewDB(t)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1
	tiny, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tiny.Close()
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("client_id") != "linked-client" || r.Form.Get("client_secret") != "linked-secret" {
			t.Error("wrong linked client authentication")
		}
		if r.Form.Get("refresh_token") != "old-refresh" {
			t.Error("wrong refresh token")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`))
	}))
	defer srv.Close()
	nets := registry.NewNetworks(tiny, nil, testutil.Logger())
	s := testService(t, &upstream.Client{AllowPrivate: true, Networks: nets})
	s.pool, s.q = tiny, dbgen.New(tiny)
	defer s.tr.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	linkedID, providerID, userID, connectionID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	secret, err := s.box.Seal([]byte("linked-secret"), SecretAAD(linkedID))
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO auth_providers(id,slug,name,client_id,client_secret_cipher,authorization_url,token_url)
		VALUES ($1,'linked','Linked','linked-client',$2,$3,$3), ($4,'refresh-owner','Owner','unused',$2,$3,$3)`, linkedID, secret, srv.URL, providerID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO users(id,email,display_name,oidc_issuer,oidc_subject) VALUES ($1,'refresh@example.test','Refresh','test','refresh')`, userID)
	if err != nil {
		t.Fatal(err)
	}
	access, err := s.seal(connectionID, "access", "old-access")
	if err != nil {
		t.Fatal(err)
	}
	rt, err := s.seal(connectionID, "refresh", "old-refresh")
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO provider_connections(id,user_id,provider_id,status,access_token_cipher,refresh_token_cipher,expires_at)
		VALUES ($1,$2,$3,'active',$4,$5,now()-interval '1 minute')`, connectionID, userID, providerID, access, rt)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.q.GetAuthProvider(ctx, providerID)
	if err != nil {
		t.Fatal(err)
	}
	p.LinkProviderID = uuid.NullUUID{UUID: linkedID, Valid: true}
	c, err := s.q.GetProviderConnection(ctx, dbgen.GetProviderConnectionParams{UserID: userID, ProviderID: providerID})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := s.refreshConnection(ctx, p, c)
	if err != nil {
		t.Fatalf("single-connection linked refresh: %v", err)
	}
	got, err := s.open(updated.ID, "access", updated.AccessTokenCipher)
	if err != nil || got != "new-access" || requests.Load() != 1 {
		t.Fatalf("refresh = %q, %v; requests = %d", got, err, requests.Load())
	}
	stored, err := s.q.GetProviderConnection(ctx, dbgen.GetProviderConnectionParams{UserID: userID, ProviderID: providerID})
	if err != nil {
		t.Fatal(err)
	}
	got, err = s.open(stored.ID, "refresh", stored.RefreshTokenCipher)
	if err != nil || got != "new-refresh" {
		t.Fatalf("persisted rotation = %q, %v", got, err)
	}

	// A narrowed token must not enter the cache before its rotation commits.
	if _, err := pool.Exec(ctx, `UPDATE provider_connections SET refresh_token_cipher=$2 WHERE id=$1`, connectionID, rt); err != nil {
		t.Fatal(err)
	}
	if _, err := testutil.OwnerPool(t, pool).Exec(ctx, `CREATE FUNCTION reject_refresh_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture commit failure'; END $$;
		CREATE CONSTRAINT TRIGGER reject_refresh_commit AFTER UPDATE ON provider_connections DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_refresh_commit()`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.narrowedToken(ctx, p, c, []string{"read"}); err == nil {
		t.Fatal("expected commit failure")
	}
	if s.narrow.len() != 0 {
		t.Fatal("published a narrowed token before its refresh rotation committed")
	}
}

type endpointRoundTrip func(*http.Request) (*http.Response, error)

func (f endpointRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTransactionRefreshLateDetachedDialCannotUseTransaction(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	nets := registry.NewNetworks(pool, nil, testutil.Logger())
	var connects atomic.Int32
	up := &upstream.Client{Networks: nets, Dial: func(context.Context, string, string) (net.Conn, error) {
		connects.Add(1)
		return nil, errors.New("must not connect")
	}}
	s := testService(t, up)
	var detached context.Context
	s.http = &http.Client{Transport: endpointRoundTrip(func(r *http.Request) (*http.Response, error) {
		detached = context.WithoutCancel(r.Context())
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"access_token":"access"}`))}, nil
	})}
	err := store.InTx(context.Background(), pool, func(q *dbgen.Queries, tx pgx.Tx) error {
		_, ee, err := s.refreshInTransaction(context.Background(), q, dbgen.AuthProvider{TokenUrl: "https://8.8.8.8/token"}, "refresh", nil)
		if err != nil || ee != nil {
			t.Fatalf("refresh = %v, %v", ee, err)
		}
		// Original TX SQL is safe as soon as the helper returns.
		if _, err := tx.Exec(context.Background(), "SELECT 1"); err != nil {
			return err
		}
		if _, err := up.GuardedDial()(detached, "tcp", "8.8.8.8:443"); !errors.Is(err, store.ErrEndpointReadsClosed) {
			t.Fatalf("late dial = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if connects.Load() != 0 {
		t.Fatal("late dial connected")
	}
}

type endpointSleepingDB struct {
	dbgen.DBTX
	reads   int
	entered chan struct{}
}

func (d *endpointSleepingDB) QueryRow(ctx context.Context, query string, args ...any) pgx.Row {
	d.reads++
	if d.reads == 2 {
		close(d.entered)
		return d.DBTX.QueryRow(ctx, "SELECT pg_sleep(60)")
	}
	return d.DBTX.QueryRow(ctx, query, args...)
}

// HTTP can succeed while a detached dial is still reading policy. Closing the
// scope must cancel/drain that SQL and report its failure before token writes.
func TestTransactionRefreshDrainsLateSQLAfterHTTPSuccess(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	nets := registry.NewNetworks(pool, nil, testutil.Logger())
	s := testService(t, &upstream.Client{Networks: nets})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := store.InTx(ctx, pool, func(_ *dbgen.Queries, tx pgx.Tx) error {
		db := &endpointSleepingDB{DBTX: tx, entered: make(chan struct{})}
		readDone := make(chan error, 1)
		s.http = &http.Client{Transport: endpointRoundTrip(func(r *http.Request) (*http.Response, error) {
			q, ok := store.EndpointReads(r.Context())
			if !ok {
				t.Fatal("missing scope")
			}
			go func() { _, err := q.GetNetworkSettings(context.WithoutCancel(r.Context())); readDone <- err }()
			select {
			case <-db.entered:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"access_token":"must-not-escape"}`))}, nil
		})}
		tok, ee, err := s.refreshInTransaction(ctx, dbgen.New(db), dbgen.AuthProvider{TokenUrl: "https://8.8.8.8/token"}, "refresh", nil)
		if err == nil || ee != nil || tok.Access != "" {
			t.Fatalf("late SQL failure escaped: tok=%+v endpoint=%v err=%v", tok, ee, err)
		}
		var down *UnavailableError
		if !errors.As(err, &down) {
			t.Fatalf("late SQL error = %v", err)
		}
		select {
		case readErr := <-readDone:
			if readErr == nil {
				t.Fatal("late SQL was not cancelled")
			}
		case <-ctx.Done():
			t.Fatal("helper returned before its late SQL finished")
		}
		return err
	})
	if err == nil {
		t.Fatal("late SQL failure did not abort transaction")
	}
}

func TestTransactionRefreshPolicySQLFailureAborts(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx := context.Background()
	nets := registry.NewNetworks(pool, nil, testutil.Logger())
	// Even a fresh usable cache must not conceal a failed transaction read.
	nets.Current(ctx)
	if _, err := testutil.OwnerPool(t, pool).Exec(ctx, `ALTER TABLE network_settings RENAME TO unavailable_network_settings`); err != nil {
		t.Fatal(err)
	}
	s := testService(t, &upstream.Client{Networks: nets})
	defer s.tr.CloseIdleConnections()
	err := store.InTx(ctx, pool, func(q *dbgen.Queries, tx pgx.Tx) error {
		tok, ee, err := s.refreshInTransaction(ctx, q, dbgen.AuthProvider{TokenUrl: "https://8.8.8.8/token"}, "refresh", nil)
		if err == nil || ee != nil || tok.Access != "" {
			t.Fatalf("SQL failure became credential outcome: tok=%+v endpoint=%v err=%v", tok, ee, err)
		}
		// The caller must receive the SQL failure itself to roll back, not
		// try marking the grant needs_reconsent in an aborted transaction.
		return err
	})
	var pgerr interface{ SQLState() string }
	if !errors.As(err, &pgerr) || pgerr.SQLState() != "42P01" {
		t.Fatalf("SQL failure not retained: %v", err)
	}
}
