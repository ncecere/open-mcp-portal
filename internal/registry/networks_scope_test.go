package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/netpolicy"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

type networkScopeReader struct {
	calls   int
	entries []byte
	err     error
}

func (r *networkScopeReader) GetNetworkSettings(context.Context) (dbgen.NetworkSetting, error) {
	r.calls++
	return dbgen.NetworkSetting{Entries: r.entries}, r.err
}
func (*networkScopeReader) GetAuthProvider(context.Context, uuid.UUID) (dbgen.AuthProvider, error) {
	panic("unexpected provider read")
}

func TestNetworksScopedReadsBypassAndNeverPublishCache(t *testing.T) {
	dep, _ := netpolicy.ParseList("10.30.0.0/16")
	n := NewNetworks(nil, dep, nil)
	cached := n.set([]netpolicy.Entry{{Kind: netpolicy.KindCIDR, Value: "10.10.0.0/16"}})
	expires := n.expires
	r := &networkScopeReader{entries: []byte(`[{"kind":"cidr","value":"10.20.0.0/16"}]`)}
	ctx, scope := store.WithEndpointReads(context.Background(), r)
	defer scope.Close()
	for range 2 {
		p, err := n.CurrentChecked(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !allowed(p, "10.20.0.1") || !allowed(p, "10.30.0.1") || allowed(p, "10.10.0.1") {
			t.Fatal("wrong scoped policy")
		}
	}
	if r.calls != 2 {
		t.Fatalf("reads = %d, want a read per check", r.calls)
	}
	if n.policy != cached || n.expires != expires {
		t.Fatal("transaction read changed shared cache/TTL")
	}
	r.err = errors.New("database read failed")
	c := &upstream.Client{Networks: n}
	if _, err := c.NormalizeURL(ctx, "https://8.8.8.8/token"); !errors.Is(err, r.err) {
		t.Fatalf("public URL did not fail closed: %v", err)
	}
	if res := c.Check(ctx, "https://8.8.8.8/token"); res.Allowed || res.Reason != upstream.ReasonPolicyFailed {
		t.Fatalf("check = %+v", res)
	}
	if n.policy != cached || n.expires != expires {
		t.Fatal("failed read changed shared cache/TTL")
	}
	scope.Close()
	if _, err := c.NormalizeURL(context.WithoutCancel(ctx), "https://8.8.8.8/token"); !errors.Is(err, store.ErrEndpointReadsClosed) {
		t.Fatalf("late check = %v", err)
	}
	if r.calls != 4 {
		t.Fatalf("late check made SQL call: %d", r.calls)
	}
}
