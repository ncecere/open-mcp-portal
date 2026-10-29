package mcptasks

import (
	"context"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

const maxPruneBatches = 10

// Prune deletes expired or abandoned task rows, at most limit per statement and
// a bounded number of statements per call so a retention pass is never
// unbounded. Expiry already denies every lookup independently of cleanup; this
// only reclaims storage. It never contacts an upstream and cancels nothing.
func (s *Store) Prune(ctx context.Context, limit int32) (int64, error) {
	if s == nil || s.pool == nil {
		return 0, ErrUnavailable
	}
	limit = min(max(limit, 1), 1000)
	q := dbgen.New(s.pool)
	var total int64
	for range maxPruneBatches {
		stmtCtx, cancel := context.WithTimeout(ctx, storeSQLBudget*2)
		n, err := q.PruneExpiredMCPTasks(stmtCtx, limit)
		cancel()
		if err != nil {
			return total, storeError(err)
		}
		total += n
		if n < int64(limit) || ctx.Err() != nil {
			break
		}
	}
	return total, nil
}
