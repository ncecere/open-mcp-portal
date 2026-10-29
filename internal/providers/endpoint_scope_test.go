package providers

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

type providerScopeReader struct {
	p     dbgen.AuthProvider
	err   error
	calls int
}

func (r *providerScopeReader) GetAuthProvider(context.Context, uuid.UUID) (dbgen.AuthProvider, error) {
	r.calls++
	return r.p, r.err
}
func (*providerScopeReader) GetNetworkSettings(context.Context) (dbgen.NetworkSetting, error) {
	panic("unexpected network read")
}

func TestClientOfUsesScopeAndPreservesLinkedClientChecks(t *testing.T) {
	linked := dbgen.AuthProvider{ID: uuid.New(), Enabled: true, ClientID: "linked", AuthorizationUrl: "https://issuer.example/authorize", TokenUrl: "https://issuer.example/token"}
	p := dbgen.AuthProvider{LinkProviderID: uuid.NullUUID{UUID: linked.ID, Valid: true}, AuthorizationUrl: linked.AuthorizationUrl, TokenUrl: linked.TokenUrl}
	s := testService(t, nil) // s.q is nil: any pool fallback is a bug.
	r := &providerScopeReader{p: linked}
	ctx, scope := store.WithEndpointReads(context.Background(), r)
	defer scope.Close()
	got, err := s.clientOf(ctx, p)
	if err != nil || got.ClientID != "linked" {
		t.Fatalf("client = %+v, %v", got, err)
	}
	r.p.Enabled = false
	if _, err := s.clientOf(ctx, p); !errors.Is(err, errLinkMismatch) {
		t.Fatalf("disabled client = %v", err)
	}
	r.p = linked
	r.p.TokenUrl = "https://other.example/token"
	if _, err := s.clientOf(ctx, p); !errors.Is(err, errLinkMismatch) {
		t.Fatalf("mismatched token endpoint = %v", err)
	}
	r.p = linked
	r.p.AuthorizationUrl = "https://other.example/authorize"
	if _, err := s.clientOf(ctx, p); !errors.Is(err, errLinkMismatch) {
		t.Fatalf("mismatched authorization endpoint = %v", err)
	}
	r.err = errors.New("SQL failed")
	if _, err := s.clientOf(ctx, p); !errors.Is(err, r.err) {
		t.Fatalf("SQL error = %v", err)
	}
	scope.Close()
	calls := r.calls
	if _, err := s.clientOf(context.WithoutCancel(ctx), p); !errors.Is(err, store.ErrEndpointReadsClosed) {
		t.Fatalf("late client lookup = %v", err)
	}
	if calls != r.calls {
		t.Fatal("closed client read reached SQL")
	}
}

type endpointDeadlineDB struct {
	t      *testing.T
	called bool
}

type endpointScanError struct{}

func (endpointScanError) Scan(...any) error { return errors.New("stop before HTTP") }
func (d *endpointDeadlineDB) QueryRow(ctx context.Context, _ string, _ ...any) pgx.Row {
	d.called = true
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > endpointTimeout {
		d.t.Error("linked client lookup ran before the endpoint deadline was installed")
	}
	return endpointScanError{}
}
func (*endpointDeadlineDB) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("unexpected exec")
}
func (*endpointDeadlineDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	panic("unexpected query")
}

func TestEndpointDeadlinePrecedesLinkedClientLookup(t *testing.T) {
	db := &endpointDeadlineDB{t: t}
	s := testService(t, nil)
	s.q = dbgen.New(db)
	p := dbgen.AuthProvider{LinkProviderID: uuid.NullUUID{UUID: uuid.New(), Valid: true}}
	_, _, _, _ = s.postForm(context.Background(), p, "https://public.example/token", url.Values{})
	if !db.called {
		t.Fatal("client not looked up")
	}
}

type deadlinePolicy struct {
	t      *testing.T
	called bool
}

func (p *deadlinePolicy) Current(context.Context) *netpolicy.Policy { panic("unchecked policy") }
func (p *deadlinePolicy) CurrentChecked(ctx context.Context) (*netpolicy.Policy, error) {
	p.called = true
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > endpointTimeout {
		p.t.Error("policy normalization ran before the endpoint deadline was installed")
	}
	return nil, errors.New("stop before HTTP")
}

func TestEndpointDeadlinePrecedesPolicyNormalization(t *testing.T) {
	for _, post := range []bool{false, true} {
		p := &deadlinePolicy{t: t}
		s := testService(t, &upstream.Client{Networks: p})
		if post {
			_, _, _, _ = s.postForm(context.Background(), dbgen.AuthProvider{}, "https://public.example/token", url.Values{})
		} else {
			req, _ := http.NewRequest(http.MethodGet, "https://public.example/userinfo", nil)
			_, _, _, _ = s.do(context.Background(), req, userinfoTimeout)
		}
		if !p.called {
			t.Fatal("policy not checked")
		}
	}
}
