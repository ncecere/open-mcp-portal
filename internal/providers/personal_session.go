package providers

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

var errPersonalConsentEnded = errors.New("personal connection browser authority ended")

// lockPersonalSession revalidates the original browser after the exchange and
// after locking any existing connection. Connection refresh may hold that row
// across bounded network I/O, so no user/session authority lock precedes that
// wait. Both later locks are NOWAIT: a concurrent suspension/logout must not
// form a CONNECTION -> USER/SESSION wait cycle. Contention requires fresh
// consent; the already-consumed code/state is never retried or restored.
func (s *Service) lockPersonalSession(ctx context.Context, q *dbgen.Queries, user uuid.UUID, session string) error {
	id, err := uuid.Parse(session)
	if err != nil {
		return errPersonalConsentEnded
	}
	status, err := q.LockPersonalConsentUser(ctx, user)
	if personalConsentUnavailable(err) || err == nil && status != auth.StatusActive {
		return errPersonalConsentEnded
	}
	if err != nil {
		return err
	}
	since := time.Time{}
	if s.SessionIdleTimeout > 0 {
		since = s.now().Add(-s.SessionIdleTimeout)
	}
	_, err = q.LockPersonalConsentSession(ctx, dbgen.LockPersonalConsentSessionParams{
		ID: id, UserID: user, AsOf: s.now(), IdleSince: since,
	})
	if personalConsentUnavailable(err) {
		return errPersonalConsentEnded
	}
	return err
}

func personalConsentUnavailable(err error) bool {
	if errors.Is(err, pgx.ErrNoRows) {
		return true
	}
	var problem *pgconn.PgError
	return errors.As(err, &problem) && problem.Code == "55P03" // lock_not_available
}
