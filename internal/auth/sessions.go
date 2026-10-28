package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// WithClock replaces the session clock, before serving requests. Intended for
// deterministic integration tests; production uses time.Now.
func (s *Service) WithClock(now func() time.Time) *Service { s.now = now; return s }

func (s *Service) idleSince(now time.Time) time.Time {
	if s.cfg.SessionIdleTimeout == 0 {
		return time.Time{}
	}
	return now.Add(-s.cfg.SessionIdleTimeout)
}

// All browser entry points share the same expiry and activity check. A recent
// session costs only a read; the conditional write arbitrates concurrent uses
// across replicas and never revives an expired session.
func (s *Service) session(ctx context.Context, digest string) (dbgen.GetSessionUserRow, error) {
	now := s.now()
	row, err := s.q.GetSessionUser(ctx, dbgen.GetSessionUserParams{TokenDigest: digest, AsOf: now, IdleSince: s.idleSince(now)})
	if err != nil {
		return row, err
	}
	if !row.Session.LastSeenAt.After(now.Add(-time.Minute)) {
		err = s.q.TouchSession(ctx, dbgen.TouchSessionParams{ID: row.Session.ID, AsOf: now, TouchBefore: now.Add(-time.Minute), IdleSince: s.idleSince(now)})
	}
	return row, err
}

// ListSessions never returns secrets, digests or CSRF tokens. Admin access to
// browser metadata is deliberately narrower than ordinary platform reads.
func (s *Service) ListSessions(ctx context.Context, a authz.Actor, userID uuid.UUID, admin bool) ([]dbgen.ListUserSessionsRow, error) {
	if err := sessionAccess(a, userID, admin); err != nil {
		return nil, err
	}
	if _, err := s.q.GetUser(ctx, userID); err != nil {
		return nil, sessionUserError(err)
	}
	now := s.now()
	return s.q.ListUserSessions(ctx, dbgen.ListUserSessionsParams{UserID: userID, AsOf: now, IdleSince: s.idleSince(now)})
}

func sessionAccess(a authz.Actor, userID uuid.UUID, admin bool) error {
	if a.IsToken() {
		return apperr.Forbidden("Browser sessions require a browser session")
	}
	if admin {
		if !a.IsPlatformAdmin() {
			return apperr.Forbidden("Only platform admins can manage other people's sessions")
		}
	} else if a.UserID != userID {
		return apperr.NotFound("user_not_found", "User not found")
	}
	return nil
}

func sessionUserError(err error) error {
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return apperr.NotFound("user_not_found", "User not found")
	}
	return err
}

// RevokeSessions authorizes, deletes sessions and their pending connect flows,
// and audits in one transaction. A nil sessionID means all, a keepID excludes
// only that session. Counts include expired rows still awaiting cleanup.
func (s *Service) RevokeSessions(ctx context.Context, a authz.Actor, userID uuid.UUID, sessionID, keepID *uuid.UUID, admin bool) error {
	if err := sessionAccess(a, userID, admin); err != nil {
		return err
	}
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if _, err := q.GetUser(ctx, userID); err != nil {
			return sessionUserError(err)
		}
		p := dbgen.RevokeSessionsParams{UserID: userID}
		if sessionID != nil {
			p.SessionID = uuid.NullUUID{UUID: *sessionID, Valid: true}
		}
		if keepID != nil {
			p.KeepID = uuid.NullUUID{UUID: *keepID, Valid: true}
		}
		ids, err := q.RevokeSessions(ctx, p)
		if err != nil {
			return err
		}
		if sessionID != nil && len(ids) == 0 {
			return apperr.NotFound("session_not_found", "Session not found")
		}
		for _, id := range ids {
			if err := q.DeleteSessionAuthStates(ctx, Digest(id.String())); err != nil {
				return err
			}
		}
		action := "session.revoke_all"
		if sessionID != nil {
			action = "session.revoke"
		}
		if admin {
			action = "session.admin_revoke"
		}
		e := a.Audit(action, "user", userID.String())
		e.Metadata = map[string]any{"count": len(ids)}
		return audit.Record(ctx, q, e)
	})
}

// ClearSessionCookie removes the local cookie after a successful self-revoke.
func (s *Service) ClearSessionCookie(w http.ResponseWriter) {
	s.setCookie(w, s.sessionCookieName(), "", -1)
}
