package retention

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// LockKey is the loop's advisory lock: one replica runs a pass at a time.
const LockKey = "omp.retention"

// Pass runs one pass if no other replica is running one (ran false then).
// Each kind is deleted in batches (one transaction each, at most MaxBatches);
// a failing kind doesn't stop the others. A pass that deleted something is
// audited as retention.purge (counts only); every pass is stored as the
// last run.
func (s *Service) Pass(ctx context.Context) (run Run, ran bool, err error) {
	release, ok, err := store.TryAdvisoryLockText(ctx, s.pool, LockKey)
	if err != nil {
		return Run{}, false, err
	}
	if !ok {
		if s.Observe != nil {
			s.Observe(Run{}, false)
		}
		return Run{}, false, nil
	}
	defer release()
	run = Run{StartedAt: s.now().UTC(), Deleted: map[string]int64{}, Errors: map[string]string{}}
	st, err := s.Current(ctx)
	if err != nil {
		return run, true, err
	}
	state, err := s.q.GetUsageRollupState(ctx)
	if err != nil {
		return run, true, err
	}
	// Calls are deleted only once rolled up: the rollup recomputes the hour
	// before its watermark's hour, so older calls are final.
	watermark := time.Time{}
	if state.RolledUpTo != nil {
		watermark = state.RolledUpTo.Truncate(time.Hour).Add(-time.Hour)
	}
	for _, k := range Kinds {
		n, err := s.purge(ctx, k.Kind, st.Periods[k.Kind], watermark)
		if n > 0 {
			run.Deleted[k.Kind] = n
		}
		if err != nil {
			if ctx.Err() != nil {
				return run, true, ctx.Err()
			}
			run.Errors[k.Kind] = errorClass(err)
			s.log.WarnContext(ctx, "retention: purge failed", "kind", k.Kind, "err", err)
		}
	}
	for _, h := range s.Hooks {
		if _, err := h(ctx); err != nil && ctx.Err() == nil {
			s.log.WarnContext(ctx, "retention: clean-up failed", "err", err)
		}
	}
	run.FinishedAt = s.now().UTC()
	if err := s.finish(ctx, run); err != nil {
		return run, true, err
	}
	if s.Observe != nil {
		s.Observe(run, true)
	}
	return run, true, nil
}

func errorClass(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "database"
	}
}

// finish stores the last run and audits retention.purge when anything was
// deleted.
func (s *Service) finish(ctx context.Context, run Run) error {
	raw, err := json.Marshal(run)
	if err != nil {
		return err
	}
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if err := q.SetRetentionLastRun(ctx, raw); err != nil {
			return err
		}
		if len(run.Deleted) == 0 {
			return nil
		}
		return audit.Record(ctx, q, audit.Entry{
			ActorKind: audit.ActorSystem, Action: "retention.purge", TargetType: "platform_settings", TargetID: "retention",
			Metadata: map[string]any{"deleted": run.Deleted, "errors": run.Errors},
		})
	})
}

// purge deletes one kind in batches.
func (s *Service) purge(ctx context.Context, kind string, days int32, watermark time.Time) (int64, error) {
	total := int64(0)
	for i := 0; i < s.cfg.MaxBatches; i++ {
		var n int64
		err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
			var err error
			switch kind {
			case CapturedPayloads:
				n, err = q.PurgeMCPCallPayloads(ctx, dbgen.PurgeMCPCallPayloadsParams{PlatformDays: days, BatchSize: s.cfg.BatchSize})
			case CallMetadata:
				if watermark.IsZero() {
					return nil
				}
				n, err = q.PurgeMCPCalls(ctx, dbgen.PurgeMCPCallsParams{Watermark: watermark, PlatformDays: days, BatchSize: s.cfg.BatchSize})
			case AuditLog:
				n, err = q.PurgeAuditLog(ctx, dbgen.PurgeAuditLogParams{Days: days, BatchSize: s.cfg.BatchSize})
			case UsageRollups:
				n, err = q.PurgeUsageRollups(ctx, dbgen.PurgeUsageRollupsParams{Days: days, BatchSize: s.cfg.BatchSize})
			}
			return err
		})
		total += n
		if err != nil {
			return total, err
		}
		if n < int64(s.cfg.BatchSize) {
			return total, nil
		}
	}
	return total, nil
}

// Loop runs Pass at start and every Interval until ctx is cancelled.
func (s *Service) Loop(ctx context.Context) {
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		run, ran, err := s.Pass(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			s.log.Warn("retention pass failed", "err", err)
		case ran && len(run.Deleted) > 0:
			s.log.Info("retention pass", "deleted", run.Deleted, "errors", len(run.Errors))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
