package mcpgw

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apikeys"
	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/oauth"
	"github.com/ncecere/open-mcp-portal/internal/serviceaccounts"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
)

// principal is who a request authenticates as: a person with an API key
// (calls.PrincipalAPIKey), a person through a connected OAuth client
// (calls.PrincipalOAuth), or a service account with one of its keys
// (calls.PrincipalServiceAccount).
type principal struct {
	toolPolicy toolscope.Policy
	kind       string
	// expiresAt is the exact MCP credential deadline; nil means no fixed
	// expiry. Approval dispatch must not rely on an earlier authentication.
	expiresAt *time.Time
	// user is the person (API keys and OAuth clients).
	user dbgen.User
	// keyID and keyName are the API key or service account key used.
	keyID   uuid.UUID
	keyName string
	// scope limits a key to these gateways (empty: every gateway its owner
	// may use). An OAuth token is bound to its gateway when authenticated.
	scope []uuid.UUID
	// grant is the connected client's grant (OAuth).
	grant *dbgen.OauthGrant
	// account is the service account and its team.
	account *serviceaccounts.Principal
}

func (p principal) inScope(gatewayID uuid.UUID) bool {
	return len(p.scope) == 0 || slices.Contains(p.scope, gatewayID)
}

// authenticate checks the credential: an OAuth access token (only for its
// own gateway), a service account key or an API key. Anything else is 401
// with a WWW-Authenticate challenge pointing at the gateway's protected
// resource metadata, where OAuth clients learn how to sign in.
func (h *Handler) authenticate(w http.ResponseWriter, r *http.Request, slug string) (principal, bool) {
	return h.credential(w, r, slug)
}

// credential authenticates the Authorization header (see authenticate).
func (h *Handler) credential(w http.ResponseWriter, r *http.Request, slug string) (principal, bool) {
	metadata := h.AppURL + "/.well-known/oauth-protected-resource/mcp"
	if slugRE.MatchString(slug) {
		metadata += "/" + slug
	}
	raw := r.Header.Get("Authorization")
	scheme, token, found := strings.Cut(raw, " ")
	token = strings.TrimSpace(token)
	if raw == "" || !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+metadata+`"`)
		refuse(w, http.StatusUnauthorized, "Sign in with OAuth, or send a key as Authorization: Bearer omp_...")
		return principal{}, false
	}
	invalid := func(msg string) (principal, bool) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", resource_metadata="`+metadata+`"`)
		refuse(w, http.StatusUnauthorized, msg)
		return principal{}, false
	}
	failed := func(err error) (principal, bool) {
		h.log().ErrorContext(r.Context(), "mcp authentication failed", "err", err, "request_id", httpx.RequestID(r.Context()))
		refuse(w, http.StatusInternalServerError, "Something went wrong")
		return principal{}, false
	}
	ctx := r.Context()
	switch {
	case oauth.IsAccessToken(token):
		if h.OAuth == nil {
			return invalid("The access token is invalid, expired or revoked. Sign in again.")
		}
		p, err := h.OAuth.Authenticate(ctx, token, slug)
		if errors.Is(err, oauth.ErrInvalidToken) {
			return invalid("The access token is invalid, expired, revoked or for another gateway. Sign in again.")
		} else if err != nil {
			return failed(err)
		}
		if err := h.OAuth.Touch(ctx, p.Grant); err != nil {
			h.log().WarnContext(ctx, "could not record a connected app's use", "err", err)
		}
		g := p.Grant
		return principal{kind: calls.PrincipalOAuth, user: p.User, grant: &g, expiresAt: &p.ExpiresAt, toolPolicy: toolscope.Union(toolscope.OAuthStored(g.ToolScope))}, true
	case serviceaccounts.LooksLikeKey(token):
		if h.ServiceAccounts == nil {
			return invalid("The service account key is invalid, expired or revoked")
		}
		p, err := h.ServiceAccounts.Authenticate(ctx, token)
		if errors.Is(err, serviceaccounts.ErrInvalid) {
			return invalid("The service account key is invalid, expired or revoked, or the account is turned off")
		} else if err != nil {
			return failed(err)
		}
		if err := h.ServiceAccounts.Touch(ctx, p); err != nil {
			h.log().WarnContext(ctx, "could not record a service account key's use", "err", err)
		}
		return principal{kind: calls.PrincipalServiceAccount, keyID: p.Key.ID, keyName: p.Key.Name, scope: p.Gateways, account: &p, expiresAt: &p.Key.ExpiresAt, toolPolicy: toolscope.Intersect(toolscope.Union(toolscope.Stored(p.Key.ToolScope)), toolscope.Union(toolscope.Stored(p.Account.ToolScope)))}, true
	}
	p, err := h.Keys.Authenticate(ctx, token)
	if errors.Is(err, apikeys.ErrInvalid) {
		return invalid("The API key is invalid, expired or revoked")
	} else if err != nil {
		return failed(err)
	}
	if err := h.Keys.Touch(ctx, p.Key); err != nil {
		h.log().WarnContext(ctx, "could not record API key use", "err", err)
	}
	return principal{kind: calls.PrincipalAPIKey, user: p.User, keyID: p.Key.ID, keyName: p.Key.Name, scope: p.Gateways, expiresAt: &p.Key.ExpiresAt, toolPolicy: toolscope.Union(toolscope.Stored(p.Key.ToolScope))}, true
}
