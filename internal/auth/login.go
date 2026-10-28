package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

var errSuspended = errors.New("user suspended")

// loginIdentity is a verified identity from OIDC or the development login.
type loginIdentity struct {
	Issuer, Subject, Email, Name string
	Claims                       json.RawMessage
	// Groups are the IdP groups of this sign-in (bounded; see Groups).
	Groups []string
	Method string // "oidc" or "dev"
	// EmailVerified gates invite acceptance: an unverified address must
	// never claim a team membership.
	EmailVerified bool
	// BootstrapRole, when set, is granted once per (issuer, subject). A later
	// demotion is never undone by signing in again.
	BootstrapRole string
}

// completeLogin provisions the user, applies one-time bootstrap roles,
// accepts open invites, creates a session and audits the sign-in, all in one
// transaction.
func (s *Service) completeLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, li loginIdentity) (dbgen.User, error) {
	var (
		user      dbgen.User
		secret    string
		suspended bool
	)
	reqID, ip := httpx.RequestID(ctx), s.clientIP(r)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		q := dbgen.New(tx)
		var err error
		user, err = q.UpsertLoginUser(ctx, dbgen.UpsertLoginUserParams{
			OIDCIssuer:  li.Issuer,
			OIDCSubject: li.Subject,
			Email:       li.Email,
			DisplayName: li.Name,
			Claims:      li.Claims,
			Groups:      boundGroups(li.Groups),
		})
		if err != nil {
			return err
		}
		if err := q.SetUserEmailVerified(ctx, dbgen.SetUserEmailVerifiedParams{ID: user.ID, Verified: li.EmailVerified}); err != nil {
			return err // notification email goes to verified addresses only
		}
		if user.Status != StatusActive {
			suspended = true
			return audit.Record(ctx, q, audit.Entry{
				ActorUserID: user.ID, Action: "auth.login_denied", TargetType: "user", TargetID: user.ID.String(),
				Metadata: map[string]any{"method": li.Method, "reason": "suspended"}, RequestID: reqID, ClientIP: ip,
			})
		}
		if user, err = applyBootstrapRole(ctx, q, user, li, reqID, ip); err != nil {
			return err
		}
		if li.EmailVerified {
			if err := teams.AcceptInvites(ctx, q, user, reqID, ip); err != nil {
				return err
			}
		}
		if secret, err = s.createSession(ctx, r, q, user); err != nil {
			return err
		}
		return audit.Record(ctx, q, audit.Entry{
			ActorUserID: user.ID, Action: "auth.login", TargetType: "user", TargetID: user.ID.String(),
			Metadata: map[string]any{"method": li.Method}, RequestID: reqID, ClientIP: ip,
		})
	})
	if err != nil {
		return dbgen.User{}, err
	}
	if suspended {
		return user, errSuspended
	}
	s.setSessionCookie(w, secret)
	return user, nil
}

// applyBootstrapRole grants li.BootstrapRole the first time this identity
// signs in, and records that it did so it is never granted again.
func applyBootstrapRole(ctx context.Context, q *dbgen.Queries, user dbgen.User, li loginIdentity, reqID, ip string) (dbgen.User, error) {
	if li.BootstrapRole == "" {
		return user, nil
	}
	n, err := q.InsertBootstrapMarker(ctx, dbgen.InsertBootstrapMarkerParams{OIDCIssuer: li.Issuer, OIDCSubject: li.Subject})
	if err != nil || n != 1 {
		return user, err
	}
	before := user.PlatformRole
	if user, err = q.SetPlatformRole(ctx, dbgen.SetPlatformRoleParams{ID: user.ID, PlatformRole: li.BootstrapRole}); err != nil {
		return user, err
	}
	return user, audit.Record(ctx, q, audit.Entry{
		ActorKind: audit.ActorSystem, Action: "platform.bootstrap_role", TargetType: "user", TargetID: user.ID.String(),
		Before: map[string]string{"platformRole": before}, After: map[string]string{"platformRole": user.PlatformRole},
		RequestID: reqID, ClientIP: ip,
	})
}

// Logout ends the current session. It must be wrapped by RequireSession so the
// CSRF token and Origin are checked.
func (s *Service) Logout(w http.ResponseWriter, r *http.Request) {
	id, _ := FromContext(r.Context())
	if c, err := r.Cookie(s.sessionCookieName()); err == nil {
		err := pgx.BeginFunc(r.Context(), s.pool, func(tx pgx.Tx) error {
			q := dbgen.New(tx)
			// Match RevokeSessions' lock order: session first, then its
			// connect states, so concurrent logout and revoke cannot deadlock.
			if err := q.DeleteSessionByDigest(r.Context(), Digest(c.Value)); err != nil {
				return err
			}
			if err := q.DeleteSessionAuthStates(r.Context(), Digest(id.SessionID)); err != nil {
				return err
			}
			return audit.Record(r.Context(), q, audit.Entry{
				ActorUserID: id.User.ID, Action: "auth.logout", TargetType: "user", TargetID: id.User.ID.String(),
				RequestID: httpx.RequestID(r.Context()), ClientIP: s.clientIP(r),
			})
		})
		if err != nil {
			httpx.Internal(w, r, err)
			return
		}
	}
	s.setCookie(w, s.sessionCookieName(), "", -1)
	httpx.JSON(w, http.StatusOK, apitypes.Ok{Ok: true})
}

// AuthConfig tells the SPA which sign-in methods are available and how this
// instance presents itself (names, theme, links). It is public.
func (s *Service) AuthConfig(w http.ResponseWriter, r *http.Request) {
	in := s.cfg.Instance
	out := apitypes.AuthConfig{
		Instance: apitypes.InstanceInfo{
			Name:       in.Name,
			OrgName:    in.OrgName,
			Theme:      apitypes.InstanceInfoTheme(in.Theme),
			LogoUrl:    nilIfEmpty(in.LogoURL),
			SupportUrl: nilIfEmpty(in.SupportURL),
		},
		OidcEnabled:    s.cfg.OIDC.Enabled(),
		DevAuthEnabled: s.cfg.DevAuth,
		LoginUrl:       "/auth/login",
		DevAccounts:    []apitypes.DevAccount{},
		TeamRequestUrl: nilIfEmpty(s.cfg.TeamRequestURL),
	}
	if s.cfg.DevAuth {
		out.DevAccounts = s.devPersonas(r.Context())
	}
	httpx.JSON(w, http.StatusOK, out)
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
