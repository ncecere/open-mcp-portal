package registry

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// The health loop re-tests every enabled server of an active team on
// HEALTH_CHECK_INTERVAL the way Test does (it lists, never calls a tool) and
// stores a scheduled check. Archived teams' servers are skipped.
// One replica runs a pass at a time (a PostgreSQL advisory lock), and a
// server checked within the last 90% of the interval is skipped, so
// replicas taking turns don't test it twice.

// healthLockKey is the advisory lock of the health loop.
const healthLockKey = "omp.mcp-health-checks"

// healthConcurrency bounds the servers tested at once.
const healthConcurrency = 4

// HealthSummary describes one pass.
type HealthSummary struct {
	Skipped                  bool // another replica holds the lock
	Servers, Healthy, Failed int
}

// RunHealthChecks runs one pass if no other replica is running one.
func (s *Service) RunHealthChecks(ctx context.Context, interval time.Duration) (HealthSummary, error) {
	release, ok, err := store.TryAdvisoryLockText(ctx, s.pool, healthLockKey)
	if err != nil {
		return HealthSummary{}, err
	}
	if !ok {
		return HealthSummary{Skipped: true}, nil
	}
	defer release()
	due := time.Now().Add(-interval * 9 / 10)
	servers, err := s.q.ListMCPServersDueForCheck(ctx, due)
	if err != nil {
		return HealthSummary{}, err
	}
	sum := HealthSummary{Servers: len(servers)}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, healthConcurrency)
	for _, sv := range servers {
		wg.Add(1)
		sem <- struct{}{}
		go func(sv dbgen.McpServer) {
			defer wg.Done()
			defer func() { <-sem }()
			res, _, _ := s.probe(ctx, sv, TriggerScheduled)
			s.checkExtraEndpoints(ctx, sv, TriggerScheduled, authz.Actor{})
			if err := recordCheck(ctx, s.q, sv.ID, res, TriggerScheduled, uuid.NullUUID{}); err != nil {
				// The server may have been deleted meanwhile.
				s.log.DebugContext(ctx, "could not store a scheduled MCP health check", "server", sv.ID, "err", err)
			} else {
				s.notifier().ServerChecked(ctx, s.q, sv.ID)
			}
			result := "failing"
			if res.OK {
				result = "healthy"
			}
			observability.ServerHealthChecks.WithLabelValues(result).Inc()
			mu.Lock()
			defer mu.Unlock()
			if res.OK {
				sum.Healthy++
			} else {
				sum.Failed++
			}
		}(sv)
	}
	wg.Wait()
	return sum, nil
}

// HealthLoop runs RunHealthChecks at start and every interval until ctx is
// cancelled. interval <= 0 turns it off.
func (s *Service) HealthLoop(ctx context.Context, interval time.Duration, log *slog.Logger) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		sum, err := s.RunHealthChecks(ctx, interval)
		switch {
		case err != nil && ctx.Err() == nil:
			log.Warn("mcp health checks failed", "err", err)
		case sum.Servers > 0:
			log.Info("mcp health checks", "servers", sum.Servers, "healthy", sum.Healthy, "failing", sum.Failed)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
