package gateways

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestGrantExpiryDatabaseClockReleasesSoleConnection(t *testing.T) {
	ctx := context.Background()
	fixture, _ := testutil.NewDB(t)
	config := fixture.Config().Copy()
	config.MaxConns, config.MinConns, config.MinIdleConns = 1, 0, 0
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	svc := New(pool, "http://localhost", testutil.Logger())
	var past, future time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()-interval '1 hour',clock_timestamp()+interval '1 hour'`).Scan(&past, &future); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		deadline time.Time
		want     bool
	}{{past, false}, {future, true}} {
		live, err := svc.GrantDeadlineLive(ctx, tt.deadline)
		if err != nil || live != tt.want {
			t.Fatalf("database deadline live=%v want=%v err=%v", live, tt.want, err)
		}
		if pool.Stat().AcquiredConns() != 0 {
			t.Fatal("deadline check retained the only connection across transport")
		}
	}
	pool.Close()
	if live, err := svc.GrantDeadlineLive(ctx, future); err == nil || live {
		t.Fatalf("missing database clock fell back to a permit: %v %v", live, err)
	}
}
