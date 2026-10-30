package registry

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// The governance loop (decision 88, docs/registry.md "Governance"): every
// GovernanceInterval one replica (a PostgreSQL advisory lock) tells the
// people a server's governance needs: the team of a published server whose
// re-review is overdue, the owners of gateways that select a deprecated server
// and the teams and gateway owners of a server whose sunset is near. With the
// platform setting on it also sends an overdue published server back to review
// (under approval_required). Nothing is unpublished, disabled or deleted, and
// a sunset stops serving by its date (gateway availability), not by this loop.
//
// Every candidate is handled in a transaction of its own, a run handles at most
// GovernanceBatch of each kind (the rest wait for the next), and each notice is
// recorded in server_governance_notices in the same transaction as its event,
// so a retry, a second replica or a purged event never tells anyone twice.

const (
	// governanceLockKey is the advisory lock of the loop.
	governanceLockKey = "omp.governance"
	// GovernanceInterval is the time between runs.
	GovernanceInterval = 5 * time.Minute
	// GovernanceBatch bounds the servers (or gateway pairs) one run handles per kind.
	GovernanceBatch = 50
	// SunsetSoonDays is how long before a sunset its teams and gateway owners are told.
	SunsetSoonDays = 14
)

// GovernanceSummary describes one run.
type GovernanceSummary struct {
	// Skipped: another replica holds the lock.
	Skipped bool
	// ReviewDueTold, SunsetSoonTold and DeprecatedTold count the new notices;
	// ReturnedToReview the servers sent back to review.
	ReviewDueTold, SunsetSoonTold, DeprecatedTold, ReturnedToReview int
}

// RunGovernance runs one pass if no other replica is running one, at the
// service's clock.
func (s *Service) RunGovernance(ctx context.Context) (GovernanceSummary, error) {
	release, ok, err := store.TryAdvisoryLockText(ctx, s.pool, governanceLockKey)
	if err != nil {
		return GovernanceSummary{}, err
	}
	if s.ObserveLeader != nil {
		s.ObserveLeader(ok)
	}
	if !ok {
		return GovernanceSummary{Skipped: true}, nil
	}
	defer release()
	now := s.clock()
	st, err := s.q.GetPlatformSettings(ctx)
	if err != nil {
		return GovernanceSummary{}, err
	}
	var sum GovernanceSummary
	for _, step := range []func(context.Context, time.Time, dbgen.PlatformSetting, *GovernanceSummary) error{
		s.governReviews, s.governSunsetSoon, s.governDeprecated,
	} {
		if err := step(ctx, now, st, &sum); err != nil {
			return sum, err
		}
	}
	return sum, nil
}

// governReviews tells the team of each overdue published server (once per due
// date) and, with the setting on, sends it back to review.
func (s *Service) governReviews(ctx context.Context, now time.Time, st dbgen.PlatformSetting, sum *GovernanceSummary) error {
	type candidate struct {
		server dbgen.McpServer
		policy *string
	}
	var rows []candidate
	if st.GovernanceReturnOverdue {
		// Approval-required rows leave published; already-notified self-publish
		// rows are excluded so they cannot occupy the whole batch forever.
		r, err := s.q.GovernanceReviewDue(ctx, dbgen.GovernanceReviewDueParams{Now: now, PageSize: GovernanceBatch})
		if err != nil {
			return err
		}
		for _, x := range r {
			rows = append(rows, candidate{x.McpServer, x.TeamPolicyOverride})
		}
	} else {
		r, err := s.q.GovernanceReviewDueUnnotified(ctx, dbgen.GovernanceReviewDueUnnotifiedParams{Now: now, PageSize: GovernanceBatch})
		if err != nil {
			return err
		}
		for _, x := range r {
			rows = append(rows, candidate{x.McpServer, x.TeamPolicyOverride})
		}
	}
	for _, c := range rows {
		err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
			sv, err := q.LockMCPServer(ctx, c.server.ID)
			if err != nil {
				return err
			}
			if !ReviewOverdue(sv, now) {
				return nil // changed since it was listed
			}
			team, err := q.GetTeamByID(ctx, sv.TeamID)
			if err != nil {
				return err
			}
			returned := st.GovernanceReturnOverdue && authz.EffectivePolicy(team.PublishPolicyOverride, st.PublishDefaultPolicy) == authz.PolicyApprovalRequired
			if s.notifier().ReviewDue(ctx, q, sv, returned) {
				sum.ReviewDueTold++
			}
			if !returned {
				return nil
			}
			note := "Its periodic re-review is overdue."
			if _, err := q.SetMCPServerPublishState(ctx, dbgen.SetMCPServerPublishStateParams{ID: sv.ID, PublishState: StatePending, Requested: true, Note: &note}); err != nil {
				return err
			}
			s.notifier().PublishRequested(ctx, q, sv.ID, "review_due", authz.Actor{})
			sum.ReturnedToReview++
			return audit.Record(ctx, q, audit.Entry{ActorKind: audit.ActorSystem, TeamID: sv.TeamID, Action: "mcp_server.publish_request",
				TargetType: "mcp_server", TargetID: sv.ID.String(), Before: map[string]any{"publishState": StatePublished},
				After:    map[string]any{"publishState": StatePending},
				Metadata: map[string]any{"name": sv.Name, "reason": "review_due", "dueAt": sv.ReviewDueAt.UTC()}})
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// governSunsetSoon tells a deprecated server's team, and the owners of the
// gateways that select it, that its sunset is within SunsetSoonDays.
func (s *Service) governSunsetSoon(ctx context.Context, now time.Time, _ dbgen.PlatformSetting, sum *GovernanceSummary) error {
	servers, err := s.q.GovernanceSunsetSoonServers(ctx, dbgen.GovernanceSunsetSoonServersParams{Now: now, WindowEnd: now.AddDate(0, 0, SunsetSoonDays), PageSize: GovernanceBatch})
	if err != nil {
		return err
	}
	for _, r := range servers {
		err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
			sv, err := q.LockMCPServer(ctx, r.McpServer.ID)
			if err != nil {
				return err
			}
			if sv.Lifecycle != LifecycleDeprecated || sv.SunsetAt == nil || !sv.SunsetAt.After(now) {
				return nil
			}
			if s.notifier().SunsetSoon(ctx, q, sv, nil) {
				sum.SunsetSoonTold++
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	pairs, err := s.q.GovernanceSunsetSoonPairs(ctx, dbgen.GovernanceSunsetSoonPairsParams{Now: now, WindowEnd: now.AddDate(0, 0, SunsetSoonDays), PageSize: GovernanceBatch})
	if err != nil {
		return err
	}
	for _, p := range pairs {
		err := s.governPair(ctx, p.ServerID, p.GatewayID, func(q *dbgen.Queries, sv dbgen.McpServer, g dbgen.Gateway) {
			if sv.SunsetAt != nil && sv.SunsetAt.After(now) && s.notifier().SunsetSoon(ctx, q, sv, &g) {
				sum.SunsetSoonTold++
			}
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// governDeprecated tells the owners of each gateway that selects a deprecated
// server, once per gateway and deprecation: also for a gateway that selected
// it after the deprecation.
func (s *Service) governDeprecated(ctx context.Context, now time.Time, _ dbgen.PlatformSetting, sum *GovernanceSummary) error {
	pairs, err := s.q.GovernanceDeprecatedPairs(ctx, dbgen.GovernanceDeprecatedPairsParams{Now: now, PageSize: GovernanceBatch})
	if err != nil {
		return err
	}
	for _, p := range pairs {
		err := s.governPair(ctx, p.ServerID, p.GatewayID, func(q *dbgen.Queries, sv dbgen.McpServer, g dbgen.Gateway) {
			if sv.Lifecycle == LifecycleDeprecated && !SunsetReached(sv, now) && s.notifier().Deprecated(ctx, q, sv, g) {
				sum.DeprecatedTold++
			}
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// governPair runs notice in a transaction with the server and the gateway read
// again under their locks (they may have changed or gone since the pair was
// listed).
func (s *Service) governPair(ctx context.Context, serverID, gatewayID uuid.UUID, notice func(*dbgen.Queries, dbgen.McpServer, dbgen.Gateway)) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		sv, err := q.LockMCPServer(ctx, serverID)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		g, err := q.LockGateway(ctx, gatewayID)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return nil
		} else if err != nil {
			return err
		}
		if g.Enabled {
			notice(q, sv, g)
		}
		return nil
	})
}

// GovernanceLoop runs RunGovernance at start and every GovernanceInterval
// until ctx is cancelled.
func (s *Service) GovernanceLoop(ctx context.Context, log *slog.Logger) {
	t := time.NewTicker(GovernanceInterval)
	defer t.Stop()
	for {
		sum, err := s.RunGovernance(ctx)
		switch {
		case err != nil && ctx.Err() == nil:
			log.Warn("governance run failed", "err", err)
		case sum.ReviewDueTold+sum.SunsetSoonTold+sum.DeprecatedTold+sum.ReturnedToReview > 0:
			log.Info("governance", "reviewDue", sum.ReviewDueTold, "sunsetSoon", sum.SunsetSoonTold, "deprecated", sum.DeprecatedTold,
				"returnedToReview", sum.ReturnedToReview)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
