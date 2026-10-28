package approvals

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

type atomicClock struct{ value atomic.Pointer[time.Time] }

func (c *atomicClock) Store(at time.Time) { c.value.Store(&at) }
func (c *atomicClock) Load() time.Time    { return *c.value.Load() }

func waitForApprovalLock(t *testing.T, f *serviceFixture, queryPattern string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if e := f.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE usename=current_user AND pid<>pg_backend_pid() AND query LIKE $1 AND wait_event_type='Lock')`, queryPattern).Scan(&blocked); e != nil {
			t.Fatal(e)
		}
		if blocked {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("approval service never reached the expected lock wait")
		case <-ticker.C:
		}
	}
}
