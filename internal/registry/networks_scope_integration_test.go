package registry

import (
	"context"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestNetworksScopedTransactionDoesNotPublishUncommittedEntries(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx := context.Background()
	n := NewNetworks(pool, nil, testutil.Logger())
	cached := n.Current(ctx)
	expires := n.expires
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `UPDATE network_settings SET entries='[{"kind":"cidr","value":"10.20.0.0/16"}]'::jsonb`); err != nil {
		t.Fatal(err)
	}
	q := dbgen.New(tx)
	scoped, scope := store.WithEndpointReads(ctx, q)
	defer scope.Close()
	for range 2 {
		p, err := n.CurrentChecked(scoped)
		if err != nil {
			t.Fatal(err)
		}
		if !allowed(p, "10.20.0.1") {
			t.Fatal("policy did not use its own transaction's settings")
		}
	}
	scope.Close() // Drain before resuming original transaction SQL.
	if _, err := q.GetNetworkSettings(ctx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if n.policy != cached || n.expires != expires {
		t.Fatal("transaction read published entries or extended shared TTL")
	}
	if allowed(n.Current(ctx), "10.20.0.1") {
		t.Fatal("uncommitted entries escaped the scope")
	}
}
