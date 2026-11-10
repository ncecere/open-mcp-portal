package httpapi

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/automation"
	"github.com/ncecere/open-mcp-portal/internal/credentials"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

// Automation tokens (docs/automation-tokens.md; decisions 55 and 58)
// authenticate /v1/* with `Authorization: Bearer ompadm_...` or
// `omppub_...` and nothing else: never /mcp, never a browser route. A
// request with an Authorization header is a token request; the session
// middleware (internal/auth) is not involved, so there is no cookie, CSRF
// token or Origin rule and no cookie is ever set on the answer.
//
// Which operations a token may call is the spec's x-omp-token-scopes,
// compiled into apitypes.TokenOperations (default deny: an operation
// without the extension answers 403 token_not_allowed).

// tokenManagement are the operations that create or revoke tokens: browser
// session only, so a token can't mint or kill tokens.
var tokenManagement = map[string]bool{
	"POST /v1/admin/automation-tokens":                    true,
	"DELETE /v1/admin/automation-tokens/{tokenId}":        true,
	"POST /v1/teams/{team}/automation-tokens":             true,
	"DELETE /v1/teams/{team}/automation-tokens/{tokenId}": true,
}

// session requires a browser session. On /v1, a request carrying an
// Authorization header is authenticated as an automation token instead
// (serveToken), for the operations the spec allows.
func (a *api) session(h http.HandlerFunc) http.Handler {
	sess := a.Auth.RequireSession(h)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" && strings.HasPrefix(r.URL.Path, "/v1/") && a.Automation != nil {
			a.serveToken(w, r, h)
			return
		}
		sess.ServeHTTP(w, r)
	})
}

// tokenOnly is for operations that take an automation token and nothing
// else (getToken): a browser session doesn't count (401 invalid_token).
func (a *api) tokenOnly(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			httpx.Error(w, http.StatusUnauthorized, "invalid_token", "Send an automation token as Authorization: Bearer")
			return
		}
		a.serveToken(w, r, h)
	})
}

func invalidToken(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	httpx.Error(w, http.StatusUnauthorized, "invalid_token", message)
}

// bearer extracts the token of "Authorization: Bearer <token>": exactly that
// shape, nothing else.
func bearer(r *http.Request) (string, bool) {
	vals := r.Header.Values("Authorization")
	if len(vals) != 1 {
		return "", false
	}
	scheme, token, found := strings.Cut(vals[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func (a *api) observeToken(result string) { a.Automation.Count(result) }

// failedToken counts a failed attempt against the address's own limit (the
// sign-in attempts' number, in a bucket of its own: bad tokens from a shared
// address never lock people out of signing in, and a valid token is never
// refused for the address's failures) and answers: 429 once the address is
// over it, else the 401.
func (a *api) failedToken(w http.ResponseWriter, r *http.Request, message string) {
	ok, wait, err := ratelimit.Allow(r.Context(), a.limiter, ratelimit.Bucket("tokenfail", httpx.ClientIP(r, a.Config.TrustedProxies)), a.Config.LoginAttemptsPerMinute)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	if !ok {
		a.observeToken(automation.ResultRateLimited)
		w.Header().Set("Retry-After", strconv.Itoa(ratelimit.RetryAfter(wait)))
		httpx.Error(w, http.StatusTooManyRequests, "rate_limited", "Too many failed attempts. Try again shortly.")
		return
	}
	invalidToken(w, message)
}

// serveToken authenticates an automation token on /v1 and, when the
// operation allows it, serves h as the token's actor.
func (a *api) serveToken(w http.ResponseWriter, r *http.Request, h http.HandlerFunc) {
	// An Authorization header means token only: a session cookie that comes
	// with it is never read (and none is ever set on the answer).
	secret, ok := bearer(r)
	if !ok {
		a.observeToken(automation.ResultWrongShape)
		a.failedToken(w, r, "Send an automation token as Authorization: Bearer <token>")
		return
	}
	// The shape check comes before any lookup; MCP credentials never
	// authorize /v1.
	switch k := credentials.Classify(secret); {
	case k == credentials.MCPCredential:
		a.observeToken(automation.ResultMCPKey)
		a.failedToken(w, r, "MCP credentials aren't accepted here: this API takes automation tokens")
		return
	case !k.IsAutomationToken():
		a.observeToken(automation.ResultWrongShape)
		a.failedToken(w, r, "Invalid token")
		return
	}
	p, err := a.Automation.Authenticate(r.Context(), secret)
	switch {
	case errors.Is(err, automation.ErrInvalid):
		a.failedToken(w, r, "Invalid token")
		return
	case err != nil:
		httpx.Internal(w, r, err)
		return
	}
	// The per-token request limit.
	ok, wait, err := ratelimit.Allow(r.Context(), a.limiter, "t:"+p.Row.ID.String(), a.Config.RequestsPerMinute)
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	if !ok {
		a.observeToken(automation.ResultRateLimited)
		w.Header().Set("Retry-After", strconv.Itoa(ratelimit.RetryAfter(wait)))
		httpx.Error(w, http.StatusTooManyRequests, "rate_limited", "Too many requests. Try again shortly.")
		return
	}
	actor := p.Actor(httpx.RequestID(r.Context()), httpx.ClientIP(r, a.Config.TrustedProxies))
	if !a.tokenMayCall(w, r, actor) {
		return
	}
	// last_used_at: written at most once a minute (the statement says so).
	if err := a.Automation.Touch(r.Context(), p.Row); err != nil {
		a.Log.WarnContext(r.Context(), "could not record an automation token's use", "err", err)
	}
	ctx := authz.WithActor(r.Context(), actor)
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h(rec, r.WithContext(ctx))
	if r.Method != http.MethodGet && r.Method != http.MethodHead && rec.status < 300 {
		a.auditTokenRequest(ctx, r, actor)
	}
}

// auditTokenRequest makes sure every successful mutation a token made is in
// the audit log with the token's ID, name and kind: the services audit their
// changes (with the actor, so entries carry the token), and a mutation that
// wrote no entry of its own (a manual test, a probe) gets a generic one.
func (a *api) auditTokenRequest(ctx context.Context, r *http.Request, actor authz.Actor) {
	n, err := a.q.CountTokenAuditEntries(ctx, dbgen.CountTokenAuditEntriesParams{TokenID: uuid.NullUUID{UUID: actor.TokenID, Valid: true}, RequestID: actor.RequestID})
	if err == nil && n > 0 {
		return
	}
	e := actor.Audit("automation_token.request", "automation_token", actor.TokenID.String())
	e.TeamID = actor.TokenTeamID
	e.Metadata = map[string]any{"name": actor.TokenName, "route": r.Pattern, "method": r.Method}
	if err := audit.Record(ctx, a.q, e); err != nil {
		a.Log.ErrorContext(ctx, "could not audit an automation token's request", "err", err, "request_id", actor.RequestID)
	}
}

// tokenMayCall decides whether the token may call the operation: the
// session-only ones answer 403 session_required, operations without
// x-omp-token-scopes 403 token_not_allowed, scopes without overlap the same
// with the scopes in details, and a team token reaches only its own team
// (404 team_not_found, as a non-member gets).
func (a *api) tokenMayCall(w http.ResponseWriter, r *http.Request, actor authz.Actor) bool {
	if tokenManagement[r.Pattern] {
		a.observeToken(automation.ResultSessionOnly)
		httpx.Error(w, http.StatusForbidden, "session_required", "Automation tokens are created and revoked in a browser session only")
		return false
	}
	op, ok := apitypes.TokenOperations[r.Pattern]
	if !ok {
		a.observeToken(automation.ResultNotAllowed)
		httpx.Error(w, http.StatusForbidden, "token_not_allowed", "Automation tokens can't call this operation")
		return false
	}
	if !slices.ContainsFunc(op.Scopes, actor.HasScope) {
		a.observeToken(automation.ResultNotAllowed)
		httpx.ErrorDetails(w, http.StatusForbidden, "token_not_allowed", "This token's scopes don't allow this operation",
			map[string]any{"requiredScopes": op.Scopes, "tokenScopes": actor.TokenScopes})
		return false
	}
	// Team routes only: /v1/admin/teams/{team} is a platform route.
	if ref := r.PathValue("team"); ref != "" && strings.HasPrefix(r.URL.Path, "/v1/teams/") {
		if !a.tokenTeam(r, actor, ref) {
			a.observeToken(automation.ResultTeamMismatch)
			httpx.Error(w, http.StatusNotFound, "team_not_found", "Team not found")
			return false
		}
	}
	return true
}

// tokenTeam reports whether a team reference (slug or ID) is the token's
// team.
func (a *api) tokenTeam(r *http.Request, actor authz.Actor, ref string) bool {
	if actor.TokenKind != authz.TokenTeamPublisher {
		return false
	}
	t, err := teams.Resolve(r.Context(), a.q, ref)
	return err == nil && t.ID == actor.TokenTeamID
}
