// OAuth sign-in for MCP clients, the /v1 side (api/openapi.yaml, tag
// oauth): the consent page's view of an authorization request and its
// decision, a person's connected apps (theirs, or anyone's for platform
// admins and auditors), and the trusted-client list.

package httpapi

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/oauth"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
)

// oauthRESTRoutes: the consent page, connected apps and trusted clients.
func (a *api) oauthRESTRoutes() []route {
	return []route{
		{"GET", "/v1/oauth/consent", a.session(a.getOAuthConsent)},
		{"POST", "/v1/oauth/consent", a.session(a.decideOAuthConsent)},
		{"GET", "/v1/me/oauth-grants", a.session(a.listMyOAuthGrants)},
		{"DELETE", "/v1/me/oauth-grants/{grantId}", a.session(a.revokeMyOAuthGrant)},
		{"GET", "/v1/admin/users/{userId}/oauth-grants", a.admin(a.adminListUserOAuthGrants)},
		{"DELETE", "/v1/admin/users/{userId}/oauth-grants/{grantId}", a.admin(a.adminRevokeUserOAuthGrant)},
		{"GET", "/v1/admin/settings/oauth-clients", a.admin(a.adminGetTrustedClients)},
		{"PUT", "/v1/admin/settings/oauth-clients", a.admin(a.adminUpdateTrustedClients)},
	}
}

// consentRequest is a checked authorization request as the consent page
// sends it: the client and the gateway the caller may use.
type consentRequest struct {
	client    oauth.Client
	req       oauth.AuthorizeRequest
	gateway   dbgen.Gateway
	user      dbgen.User
	toolScope *toolscope.Scope
}

// checkConsent reads and checks an authorization request for the consent
// page. A request that isn't valid is a 400 with the reason (the page shows
// it and never sends the browser anywhere); a resource that names no
// gateway the caller can use is a 404.
func (a *api) checkConsent(w http.ResponseWriter, r *http.Request, q url.Values) (consentRequest, bool) {
	id, _ := auth.FromContext(r.Context())
	cr := consentRequest{user: id.User}
	var err error
	if cr.req, err = oauth.RequestFromQuery(q); err == nil {
		cr.client, err = a.OAuth.Check(oauth.WithSource(r.Context(), httpx.ClientIP(r, a.Config.TrustedProxies)), cr.req)
	}
	var oe *oauth.Error
	if errors.As(err, &oe) {
		status := http.StatusBadRequest
		if oe.Status == http.StatusTooManyRequests { // too many metadata fetches from this address
			status = oe.Status
		}
		httpx.Error(w, status, "oauth_"+oe.Code, oe.Description)
		return cr, false
	} else if failed(w, r, err) {
		return cr, false
	}
	cr.toolScope, err = cr.req.ToolScope()
	if failed(w, r, err) {
		return cr, false
	}
	cr.gateway, err = a.OAuth.Gateway(r.Context(), id.User, cr.req)
	if errors.As(err, &oe) {
		httpx.Error(w, http.StatusNotFound, "gateway_not_found", "The app asks for a gateway you can't use")
		return cr, false
	}
	return cr, !failed(w, r, err)
}

func toAPIClientInfo(c oauth.Client, trusted bool) apitypes.OAuthClientInfo {
	return apitypes.OAuthClientInfo{Id: c.ID, Kind: apitypes.OAuthClientInfoKind(c.Kind), Name: c.Name, Host: c.Host(),
		Uri: nonEmpty(c.URI), LogoUrl: nonEmpty(c.LogoURI), Trusted: trusted && c.Kind == oauth.KindMetadata}
}

func (a *api) getOAuthConsent(w http.ResponseWriter, r *http.Request) {
	cr, ok := a.checkConsent(w, r, r.URL.Query())
	if !ok {
		return
	}
	state, err := a.OAuth.ConsentState(r.Context(), cr.user.ID, cr.client, cr.gateway.ID, cr.req.RedirectURI, cr.toolScope)
	if failed(w, r, err) {
		return
	}
	mine, _, err := a.Gateways.GetMine(r.Context(), cr.user, cr.gateway.ID)
	if failed(w, r, err) {
		return
	}
	redirect, _ := url.Parse(cr.req.RedirectURI)
	httpx.JSON(w, http.StatusOK, apitypes.OAuthConsent{
		Client: toAPIClientInfo(cr.client, state.Trusted), Gateway: a.toAPIMyGateway(mine),
		RedirectUri: cr.req.RedirectURI, RedirectHost: redirect.Host, Remembered: state.Remembered, Notice: state.Notice, RequestedToolScope: toAPIToolScope(toolscope.JSON(cr.toolScope)),
	})
}

func (a *api) decideOAuthConsent(w http.ResponseWriter, r *http.Request) {
	var in oauthScopeDecision
	if !httpx.Decode(w, r, &in) {
		return
	}
	q, err := url.ParseQuery(in.Query)
	if err != nil || len(in.Query) > oauth.MaxQueryLen || !in.Decision.Valid() {
		httpx.Error(w, http.StatusBadRequest, "invalid_request", "Send the authorization request's query and allow or deny.")
		return
	}
	cr, ok := a.checkConsent(w, r, q)
	if !ok {
		return
	}
	to := a.OAuth.DenyRedirect(cr.req)
	if in.Decision == apitypes.Allow {
		chosen := cr.toolScope
		if in.ToolScope != nil {
			var err error
			chosen, err = toolscope.Parse(in.ToolScope)
			if err != nil || chosen != nil && len(chosen.Tools) > 0 || !toolscope.Subset(chosen, cr.toolScope) {
				httpx.Error(w, http.StatusBadRequest, "oauth_invalid_scope", "Consent may narrow but not widen the requested classes; named tools are not OAuth scopes.")
				return
			}
		}
		// A trusted client's first loopback sign-in is a confirmation, not a consent.
		state, err := a.OAuth.ConsentState(r.Context(), cr.user.ID, cr.client, cr.gateway.ID, cr.req.RedirectURI, cr.toolScope)
		if failed(w, r, err) {
			return
		}
		if to, err = a.OAuth.Approve(r.Context(), a.actor(r), cr.client, cr.gateway, cr.req, state.How(), chosen); failed(w, r, err) {
			return
		}
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"redirectUrl": to})
}

// writeGrants writes a person's connected apps, marking trusted clients.
func (a *api) writeGrants(w http.ResponseWriter, r *http.Request, grants []oauth.Grant, err error) {
	if failed(w, r, err) {
		return
	}
	trusted, err := a.OAuth.TrustedIDs(r.Context())
	if failed(w, r, err) {
		return
	}
	writeList(w, r, grants, nil, func(g oauth.Grant) apitypes.OAuthGrant {
		gr := g.OauthGrant
		c := oauth.GrantClient(gr)
		return apitypes.OAuthGrant{Id: gr.ID, Client: toAPIClientInfo(c, trusted[c.ID]), CreatedAt: gr.CreatedAt, LastUsedAt: gr.LastUsedAt,
			ExpiresAt: a.OAuth.GrantExpiry(gr), ToolScope: toAPIToolScope(toolscope.JSON(toolscope.OAuthStored(gr.ToolScope))),
			Gateway: apitypes.CallRef{Id: gr.GatewayID, Slug: g.GatewaySlug, Name: g.GatewayName, Exists: true}}
	})
}

func (a *api) listMyOAuthGrants(w http.ResponseWriter, r *http.Request) {
	grants, err := a.OAuth.ListGrants(r.Context(), a.actor(r), a.actor(r).UserID)
	a.writeGrants(w, r, grants, err)
}

func (a *api) revokeMyOAuthGrant(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "grantId")
	if !ok {
		return
	}
	writeOK(w, r, a.OAuth.RevokeGrant(r.Context(), a.actor(r), a.actor(r).UserID, id))
}

func (a *api) adminListUserOAuthGrants(w http.ResponseWriter, r *http.Request) {
	userID, ok := pathUUID(w, r, "userId")
	if !ok {
		return
	}
	grants, err := a.OAuth.ListGrants(r.Context(), a.actor(r), userID)
	a.writeGrants(w, r, grants, err)
}

func (a *api) adminRevokeUserOAuthGrant(w http.ResponseWriter, r *http.Request) {
	var userID, id uuid.UUID
	var ok bool
	if userID, ok = pathUUID(w, r, "userId"); !ok {
		return
	}
	if id, ok = pathUUID(w, r, "grantId"); !ok {
		return
	}
	writeOK(w, r, a.OAuth.RevokeGrant(r.Context(), a.actor(r), userID, id))
}

func toAPITrustedClients(t oauth.TrustedClients) apitypes.TrustedClients {
	out := apitypes.TrustedClients{Clients: make([]apitypes.TrustedClient, len(t.Clients)), OpenRegistration: t.OpenRegistration,
		Revision: t.Revision, UpdatedAt: t.UpdatedAt}
	for i, c := range t.Clients {
		out.Clients[i] = apitypes.TrustedClient{ClientId: c.ClientID, Label: nonEmpty(c.Label)}
	}
	return out
}

func (a *api) adminGetTrustedClients(w http.ResponseWriter, r *http.Request) {
	t, err := a.OAuth.GetTrustedClients(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, t.Revision, toAPITrustedClients(t))
}

func (a *api) adminUpdateTrustedClients(w http.ResponseWriter, r *http.Request) {
	in, rev, ok := decodeRevised[apitypes.TrustedClientsUpdate](w, r)
	if !ok {
		return
	}
	clients := make([]oauth.TrustedClient, len(in.Clients))
	for i, c := range in.Clients {
		clients[i] = oauth.TrustedClient{ClientID: c.ClientId}
		setIf(&clients[i].Label, c.Label)
	}
	t, err := a.OAuth.UpdateTrustedClients(r.Context(), a.actor(r), clients, in.OpenRegistration, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, t.Revision, toAPITrustedClients(t))
}
