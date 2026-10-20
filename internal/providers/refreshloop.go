package providers

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Background refresh (issue #27, decision 69): with PROVIDER_REFRESH_INTERVAL
// set, a pass every interval refreshes the access tokens of active
// connections that expire before the next pass (and a few minutes more) and
// were used in the last week. A provider that revoked the grant answers
// invalid_grant, so the connection turns needs_reconsent (and the person is
// told) before a call finds out, not after. Default off (0).
//
// One replica runs a pass at a time (a PostgreSQL advisory lock), and a
// connection is refreshed under its row lock with the expiry checked again
// inside it, so a connection is never refreshed twice for one expiry however
// replicas and calls interleave (a provider that rotates refresh tokens
// would otherwise invalidate the token the other request holds).

const (
	// refreshLockKey is the advisory lock of the background refresh.
	refreshLockKey = "omp.provider-refresh"
	// refreshSlack is how much further than the interval a pass looks ahead.
	refreshSlack = 5 * time.Minute
	// refreshUsedWithin is how recently a connection must have been used.
	refreshUsedWithin = 7 * 24 * time.Hour
	// refreshBatch bounds the connections one pass refreshes.
	refreshBatch = 500
	// refreshConcurrency bounds the refreshes in flight.
	refreshConcurrency = 4
)

// RefreshSummary describes one pass.
type RefreshSummary struct {
	Skipped                      bool // another replica holds the lock
	Due, Refreshed, Failed, Lost int
}

// RunRefresh runs one pass if no other replica is running one. Lost counts
// connections the provider refused (now needs_reconsent).
func (s *Service) RunRefresh(ctx context.Context, interval time.Duration) (RefreshSummary, error) {
	release, ok, err := store.TryAdvisoryLockText(ctx, s.pool, refreshLockKey)
	if err != nil {
		return RefreshSummary{}, err
	}
	if !ok {
		return RefreshSummary{Skipped: true}, nil
	}
	defer release()
	now := s.now()
	ahead := interval + refreshSlack
	due, err := s.q.ListConnectionsDueForRefresh(ctx, dbgen.ListConnectionsDueForRefreshParams{
		ExpiresBefore: now.Add(ahead), UsedSince: now.Add(-refreshUsedWithin), PageSize: refreshBatch})
	if err != nil {
		return RefreshSummary{}, err
	}
	sum := RefreshSummary{Due: len(due)}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, refreshConcurrency)
	for _, c := range due {
		p, err := s.q.GetAuthProvider(ctx, c.ProviderID)
		if err != nil {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(c dbgen.ProviderConnection, p dbgen.AuthProvider) {
			defer wg.Done()
			defer func() { <-sem }()
			_, err := s.refreshConnectionAhead(ctx, p, c, ahead)
			observeRefresh(p.Slug, err)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				sum.Refreshed++
			case errors.Is(err, errReconsent):
				sum.Lost++
			default:
				sum.Failed++
			}
		}(c, p)
	}
	wg.Wait()
	return sum, nil
}

// RefreshLoop runs RunRefresh at start and every interval until ctx is
// cancelled. interval <= 0 turns it off.
func (s *Service) RefreshLoop(ctx context.Context, interval time.Duration, log *slog.Logger) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		sum, err := s.RunRefresh(ctx, interval)
		switch {
		case err != nil && ctx.Err() == nil:
			log.Warn("provider token refresh failed", "err", err)
		case sum.Due > 0:
			log.Info("provider token refresh", "due", sum.Due, "refreshed", sum.Refreshed, "failed", sum.Failed, "needsReconsent", sum.Lost)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
