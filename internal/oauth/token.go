package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
)

// TokenRequest is a token request's form (RFC 6749 §4.1.3 and §6, with
// PKCE and a resource indicator).
type TokenRequest struct {
	Scope        string
	ScopePresent bool
	GrantType    string
	ClientID     string
	Code         string
	RedirectURI  string
	CodeVerifier string
	RefreshToken string
	Resource     string
	RequestID    string
	ClientIP     string
}

// Tokens is a token response (RFC 6749 §5.1).
type Tokens struct {
	Scope        *string `json:"scope,omitempty"`
	AccessToken  string  `json:"access_token"`
	TokenType    string  `json:"token_type"`
	ExpiresIn    int     `json:"expires_in"`
	RefreshToken string  `json:"refresh_token"`
}

// Token answers the token endpoint.
func (s *Service) Token(ctx context.Context, r TokenRequest) (Tokens, error) {
	if r.ClientID == "" {
		return Tokens{}, &Error{Code: "invalid_client", Description: "Send client_id (public clients authenticate with it alone).", Status: http.StatusUnauthorized}
	}
	switch r.GrantType {
	case "authorization_code":
		return s.exchange(ctx, r)
	case "refresh_token":
		return s.refresh(ctx, r)
	}
	return Tokens{}, oauthError("unsupported_grant_type", "Only the authorization_code and refresh_token grant types are supported.")
}

// pkceVerifier is a code verifier's form (RFC 7636 §4.1).
var pkceVerifier = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// verifyPKCE checks a verifier against an S256 challenge, in constant time.
func verifyPKCE(verifier, challenge string) bool {
	if !pkceVerifier.MatchString(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// takeCode consumes a code: it is deleted before anything else is checked,
// so a code works once even when the exchange then fails.
func (s *Service) takeCode(ctx context.Context, code string) (dbgen.OauthCode, bool, error) {
	if !validTokenShape(code, codePrefix) {
		return dbgen.OauthCode{}, false, nil
	}
	for _, d := range s.digests(code) {
		row, err := s.q.TakeOAuthCode(ctx, d)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			continue
		}
		return row, err == nil, err
	}
	return dbgen.OauthCode{}, false, nil
}

// exchange redeems an authorization code (with its PKCE verifier) for tokens.
func (s *Service) exchange(ctx context.Context, r TokenRequest) (Tokens, error) {
	code, ok, err := s.takeCode(ctx, r.Code)
	if err != nil {
		return Tokens{}, err
	}
	switch {
	case !ok, !code.ExpiresAt.After(s.now()), code.ClientID != r.ClientID, code.RedirectUri != r.RedirectURI:
		return Tokens{}, errInvalidGrant()
	case r.Resource != "" && r.Resource != code.Resource:
		return Tokens{}, oauthError("invalid_target", "The resource must be the one the code was issued for: "+code.Resource)
	case !verifyPKCE(r.CodeVerifier, code.CodeChallenge):
		return Tokens{}, errInvalidGrant()
	}
	var out Tokens
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		g, err := s.usableGrant(ctx, q, code.GrantID)
		if err != nil {
			return err
		}
		if out, err = s.issue(ctx, q, g, newToken(AccessPrefix), newToken(RefreshPrefix)); err != nil {
			return err
		}
		return s.auditIssue(ctx, q, g, r, "authorization_code", nil)
	})
	return out, err
}

// usableGrant locks a grant that is active and whose person is active.
// Access to the gateway is checked when a token is used.
func (s *Service) usableGrant(ctx context.Context, q *dbgen.Queries, id uuid.UUID) (dbgen.OauthGrant, error) {
	g, err := q.LockOAuthGrant(ctx, id)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return g, errInvalidGrant()
	} else if err != nil {
		return g, err
	}
	if g.RevokedAt != nil {
		return g, errInvalidGrant()
	}
	u, err := q.GetUser(ctx, g.UserID)
	if err != nil {
		return g, err
	}
	if u.Status != "active" {
		return g, errInvalidGrant()
	}
	return g, nil
}

// refresh rotates a refresh token.
//
//   - Its grant must be within the absolute lifetime (OAUTH_REFRESH_ABSOLUTE_TTL,
//     counted from the last time the person signed the app in): past it the
//     grant is revoked (reason expired_absolute) and the answer is invalid_grant,
//     so the app signs in again.
//   - A token already rotated more than RefreshReuseGrace ago is reuse (a
//     stolen copy, or a client that lost the new one): the whole grant is
//     revoked, and the person connects the client again.
//   - Inside the grace a token that was rotated is a client that refreshed
//     twice at once: it gets the same pair the rotation issued, not another
//     one. The pair is derived from the presented token (successor), so no
//     token is stored in the clear to hand out again, and a second pair is
//     never minted for a token that was already used.
func (s *Service) refresh(ctx context.Context, r TokenRequest) (Tokens, error) {
	row, ok, err := s.lookup(ctx, r.RefreshToken, RefreshPrefix, kindRefresh)
	if err != nil {
		return Tokens{}, err
	}
	if !ok || row.OauthGrant.ClientID != r.ClientID {
		return Tokens{}, errInvalidGrant()
	}
	if r.Resource != "" && r.Resource != row.OauthToken.Resource {
		return Tokens{}, oauthError("invalid_target", "The resource must be the one the grant is for: "+row.OauthToken.Resource)
	}
	var (
		out            Tokens
		reused, lapsed bool
	)
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		// Same lock order as replacement/revocation: grant before its tokens.
		g, err := s.usableGrant(ctx, q, row.OauthGrant.ID)
		if err != nil {
			return err
		}
		if r.ScopePresent || r.Scope != "" {
			requested, e := toolscope.OAuth(r.Scope, true)
			if e != nil || !toolscope.Equal(requested, toolscope.OAuthStored(g.ToolScope)) {
				return oauthError("invalid_scope", "Refresh scope must equal the grant's scope or be omitted.")
			}
		}
		tok, err := q.LockOAuthToken(ctx, row.OauthToken.ID)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errInvalidGrant()
		} else if err != nil {
			return err
		}
		if tok.RotatedAt != nil && s.now().Sub(*tok.RotatedAt) > RefreshReuseGrace {
			reused = true
			return s.revokeGrant(ctx, q, grantActor(row.OauthGrant, r.RequestID, r.ClientIP), row.OauthGrant.ID, ReasonReuse)
		}
		if !tok.ExpiresAt.After(s.now()) {
			return errInvalidGrant()
		}
		if s.expired(g) {
			lapsed = true
			return s.revokeGrant(ctx, q, grantActor(g, r.RequestID, r.ClientIP), g.ID, ReasonExpired)
		}
		access, refresh := s.successor(r.RefreshToken)
		if tok.RotatedAt != nil {
			// Inside the grace: the rotation already issued this pair.
			if out, err = s.repeat(ctx, q, g, access, refresh); err != nil {
				return err
			}
			return s.auditIssue(ctx, q, g, r, "refresh_token", map[string]any{"repeat": true})
		}
		if n, err := q.RotateOAuthToken(ctx, tok.ID); err != nil || n == 0 {
			return errors.Join(err, errInvalidGrant())
		}
		if out, err = s.issue(ctx, q, g, access, refresh); err != nil {
			return err
		}
		return s.auditIssue(ctx, q, g, r, "refresh_token", nil)
	})
	if err == nil && (reused || lapsed) {
		return Tokens{}, errInvalidGrant()
	}
	return out, err
}

// successor is the access and refresh token a rotation of a refresh token
// issues: keyed digests of it under the pepper, so the same token always
// has the same successors and only someone who holds the token (and the
// pepper) can compute them. A repeat inside the grace answers them again.
func (s *Service) successor(refreshToken string) (access, refresh string) {
	derive := func(label, prefix string) string {
		m := hmac.New(sha256.New, s.pepper)
		m.Write([]byte("oauth-successor:" + label + ":" + refreshToken))
		return prefix + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
	}
	return derive("access", AccessPrefix), derive("refresh", RefreshPrefix)
}

// repeat answers a refresh token presented again inside the grace: the pair
// its rotation issued, if both tokens are still there (a client that
// revoked one, or a rotation by the previous release, which issued a random
// pair, gets invalid_grant and signs in again).
func (s *Service) repeat(ctx context.Context, q *dbgen.Queries, g dbgen.OauthGrant, access, refresh string) (Tokens, error) {
	var expires time.Time
	for _, t := range []struct{ kind, token string }{{kindRefresh, refresh}, {kindAccess, access}} {
		row, err := q.GetOAuthToken(ctx, dbgen.GetOAuthTokenParams{TokenHash: s.digest(t.token), Kind: t.kind})
		if errors.Is(store.NotFound(err), store.ErrNotFound) || (err == nil && row.OauthToken.GrantID != g.ID) {
			return Tokens{}, errInvalidGrant()
		} else if err != nil {
			return Tokens{}, err
		}
		if t.kind == kindAccess {
			expires = row.OauthToken.ExpiresAt
		}
	}
	return Tokens{AccessToken: access, RefreshToken: refresh, TokenType: "Bearer", ExpiresIn: max(1, int(expires.Sub(s.now()).Seconds())), Scope: toolscope.OAuthString(toolscope.OAuthStored(g.ToolScope))}, nil
}

// issue stores an access and a refresh token for a grant, bound to its
// resource.
func (s *Service) issue(ctx context.Context, q *dbgen.Queries, g dbgen.OauthGrant, access, refresh string) (Tokens, error) {
	if err := q.DeleteExpiredOAuthTokens(ctx); err != nil {
		return Tokens{}, err
	}
	if g.ClientKind == KindRegistered {
		if err := q.TouchOAuthClient(ctx, g.ClientID); err != nil {
			return Tokens{}, err
		}
		if err := q.MarkOAuthClientAuthorized(ctx, g.ClientID); err != nil {
			return Tokens{}, err
		}
	}
	out := Tokens{AccessToken: access, RefreshToken: refresh, TokenType: "Bearer", ExpiresIn: int(AccessTokenTTL.Seconds()), Scope: toolscope.OAuthString(toolscope.OAuthStored(g.ToolScope))}
	now := s.now()
	for _, t := range []struct {
		kind, token string
		ttl         time.Duration
	}{{kindAccess, out.AccessToken, AccessTokenTTL}, {kindRefresh, out.RefreshToken, RefreshTokenTTL}} {
		if err := q.InsertOAuthToken(ctx, dbgen.InsertOAuthTokenParams{
			GrantID: g.ID, Kind: t.kind, TokenHash: s.digest(t.token), Resource: g.Resource, ExpiresAt: now.Add(t.ttl),
			PepperID: s.pepperID(),
		}); err != nil {
			return Tokens{}, err
		}
	}
	return out, nil
}

// grantActor is a grant's person acting through its client (audit).
func grantActor(g dbgen.OauthGrant, requestID, clientIP string) authz.Actor {
	return authz.Actor{UserID: g.UserID, PlatformRole: authz.PlatformNone, RequestID: requestID, ClientIP: clientIP}
}

// grantAudit is an audit entry by a grant's person through its client.
func grantAudit(a authz.Actor, g dbgen.OauthGrant, action string) audit.Entry {
	e := a.Audit(action, "oauth_grant", g.ID.String())
	e.Metadata = map[string]any{"via": "oauth", "client": g.ClientName, "clientId": g.ClientID, "gatewayId": g.GatewayID.String()}
	return e
}

// auditIssue records oauth.token_issue: the grant and the grant type
// (extra: "repeat" for a pair answered again inside the grace), never a
// token.
func (s *Service) auditIssue(ctx context.Context, q *dbgen.Queries, g dbgen.OauthGrant, r TokenRequest, grantType string, extra map[string]any) error {
	e := grantAudit(grantActor(g, r.RequestID, r.ClientIP), g, "oauth.token_issue")
	e.Metadata["grantType"] = grantType
	for k, v := range extra {
		e.Metadata[k] = v
	}
	return audit.Record(ctx, q, e)
}

// lookup finds a token of a kind by its digest, with its grant, person and
// gateway. ok is false for anything else.
func (s *Service) lookup(ctx context.Context, token, prefix, kind string) (dbgen.GetOAuthTokenRow, bool, error) {
	if !validTokenShape(token, prefix) {
		return dbgen.GetOAuthTokenRow{}, false, nil
	}
	for _, d := range s.digests(token) {
		row, err := s.q.GetOAuthToken(ctx, dbgen.GetOAuthTokenParams{TokenHash: d, Kind: kind})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			continue
		}
		return row, err == nil, err
	}
	return dbgen.GetOAuthTokenRow{}, false, nil
}

// ErrInvalidToken: the access token is unknown, expired or revoked, its
// grant or person is not active, or it is for another gateway.
var ErrInvalidToken = errors.New("oauth: invalid access token")

// Principal is who an access token acts as: a person through a client on
// one gateway.
type Principal struct {
	Grant dbgen.OauthGrant
	User  dbgen.User
	// GatewaySlug is the gateway the token is for.
	GatewaySlug string
	// TokenID and ExpiresAt permit a dispatch boundary to retain the exact
	// authenticated credential's identity/deadline without retaining its secret.
	TokenID   uuid.UUID
	ExpiresAt time.Time
}

// Authenticate checks an access token presented to /mcp/{slug}: its digest
// is looked up, then its expiry, its grant, its person (suspended:
// refused) and its audience, which must be that gateway (RFC 8707). Access
// to the gateway is checked by the caller, on every request.
func (s *Service) Authenticate(ctx context.Context, token, slug string) (Principal, error) {
	row, ok, err := s.lookup(ctx, token, AccessPrefix, kindAccess)
	if err != nil {
		return Principal{}, err
	}
	g := row.OauthGrant
	resource := s.Resource(slug)
	if !ok || !row.OauthToken.ExpiresAt.After(s.now()) || g.RevokedAt != nil || row.User.Status != "active" ||
		row.GatewaySlug != slug || row.OauthToken.Resource != resource || g.Resource != resource {
		return Principal{}, ErrInvalidToken
	}
	return Principal{Grant: g, User: row.User, GatewaySlug: row.GatewaySlug, TokenID: row.OauthToken.ID, ExpiresAt: row.OauthToken.ExpiresAt}, nil
}

// Touch records that a grant was used (at most once a minute).
func (s *Service) Touch(ctx context.Context, grantID uuid.UUID) error {
	return s.q.TouchOAuthGrant(ctx, grantID)
}

// Revoke is the revocation endpoint (RFC 7009): a refresh token revokes
// its whole grant; an access token only itself. A token of another client,
// or no token of ours, changes nothing (the answer is the same).
func (s *Service) Revoke(ctx context.Context, token, clientID, requestID, clientIP string) error {
	for _, k := range []struct{ prefix, kind string }{{RefreshPrefix, kindRefresh}, {AccessPrefix, kindAccess}} {
		row, ok, err := s.lookup(ctx, token, k.prefix, k.kind)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		if row.OauthGrant.ClientID != clientID {
			return nil
		}
		a := grantActor(row.OauthGrant, requestID, clientIP)
		return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
			if k.kind == kindRefresh {
				return s.revokeGrant(ctx, q, a, row.OauthGrant.ID, ReasonClient)
			}
			if err := q.DeleteOAuthToken(ctx, row.OauthToken.ID); err != nil {
				return err
			}
			e := grantAudit(a, row.OauthGrant, "oauth.revoke")
			e.Metadata["token"], e.Metadata["reason"] = kindAccess, ReasonClient
			return audit.Record(ctx, q, e)
		})
	}
	return nil
}
