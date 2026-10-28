package approvals

import (
	"context"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Caller holds the epoch fence and this requester's advisory lock. Audit every
// expired/stale row, including OLD epoch bindings that the current digest lookup
// can never find. Bounded batches avoid an unbounded ciphertext result slice.
func (s *Service) clearStaleRequester(ctx context.Context, q *dbgen.Queries, b Binding) error {
	for {
		rows, err := q.ApprovalStaleRequesterRequests(ctx, dbgen.ApprovalStaleRequesterRequestsParams{RequesterKind: b.RequesterKind, RequesterID: b.RequesterID, ContextEpoch: b.Epoch, AtTime: s.clock()})
		if err != nil {
			return err
		}
		for _, r := range rows {
			next, e := s.expire(ctx, q, r, b.Epoch, nil)
			if e != nil {
				return e
			}
			if !terminal(next.Status) {
				return ErrUnavailable
			}
		}
		if len(rows) < 200 {
			return nil
		}
	}
}
