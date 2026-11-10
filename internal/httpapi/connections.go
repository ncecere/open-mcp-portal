package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

func (a *api) listMyConnections(w http.ResponseWriter, r *http.Request) {
	cs, err := a.Providers.ListMyConnections(r.Context(), a.actor(r))
	writeList(w, r, cs, err, toAPIConnection)
}

func (a *api) revokeMyConnection(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "connectionId")
	if !ok {
		return
	}
	writeOK(w, r, a.Providers.RevokeMine(r.Context(), a.actor(r), id))
}

// connectLimited counts one attempt of a connect operation against the
// person's limit; it answers 429 slow_down and returns false when it is
// used up.
func (a *api) connectLimited(w http.ResponseWriter, r *http.Request, key string, limit int, message string) bool {
	id, _ := auth.FromContext(r.Context())
	ok, wait, err := ratelimit.Allow(r.Context(), a.limiter, key+":"+id.User.ID.String(), limit)
	if failed(w, r, err) {
		return false
	}
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(ratelimit.RetryAfter(wait)))
		httpx.Error(w, http.StatusTooManyRequests, "slow_down", message)
		return false
	}
	return true
}

func (a *api) listAllowableServers(w http.ResponseWriter, r *http.Request) {
	connID, ok := pathUUID(w, r, "connectionId")
	if !ok || !a.browserOnly(w, r) {
		return
	}
	vs, err := a.Providers.ListAllowable(r.Context(), a.actor(r), connID)
	writeList(w, r, vs, err, func(v providers.Allowable) apitypes.AllowableServer {
		return apitypes.AllowableServer{Server: toAPIConnectServer(v.Server), Origin: v.Origin, Scopes: nonNilStrings(v.Scopes),
			Covered: v.Covered, Allowed: v.Allowed}
	})
}

// browserOnly answers 403 session_required unless the call is the web
// app's (a browser session): allowing a server is a person's own decision,
// never an API key's, an automation token's or an agent's.
func (a *api) browserOnly(w http.ResponseWriter, r *http.Request) bool {
	if id, _ := auth.FromContext(r.Context()); id.SessionID == "" {
		httpx.Error(w, http.StatusForbidden, "session_required", "Do this from the web app")
		return false
	}
	return true
}

func (a *api) allowConnectionServer(w http.ResponseWriter, r *http.Request) {
	connID, ok := pathUUID(w, r, "connectionId")
	if !ok || !a.browserOnly(w, r) {
		return
	}
	if !a.connectLimited(w, r, "connect-allow", connectAllowsPerMinute, "Too many attempts to allow servers. Try again shortly.") {
		return
	}
	var in apitypes.AllowServerRequest
	if !httpx.Decode(w, r, &in) {
		return
	}
	c, err := a.Providers.AllowServer(r.Context(), a.actor(r), connID, providers.AllowInput{ServerID: in.ServerId, Origin: in.Origin, Scopes: in.Scopes})
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, apitypes.ConnectConfirmed{Provider: toAPIProviderRef(c.Provider), Server: toAPIConnectServer(c.Server),
		Scopes: nonNilStrings(c.Scopes)})
}

func (a *api) revokeAllowedServer(w http.ResponseWriter, r *http.Request) {
	connID, ok := pathUUID(w, r, "connectionId")
	if !ok {
		return
	}
	serverID, ok := pathUUID(w, r, "serverId")
	if !ok || !a.browserOnly(w, r) {
		return
	}
	if !a.connectLimited(w, r, "connect-allow", connectAllowsPerMinute, "Too many attempts to change allowed servers. Try again shortly.") {
		return
	}
	writeOK(w, r, a.Providers.RevokeServer(r.Context(), a.actor(r), connID, serverID))
}

func (a *api) startMyConnection(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !a.connectLimited(w, r, "connect-start", connectStartsPerMinute, "Too many attempts to connect. Try again shortly.") {
		return
	}
	var in apitypes.ConnectStart
	if !httpx.Decode(w, r, &in) {
		return
	}
	// An oauth server's own sign-in without a consent link: only for people
	// who can use one of the server's capabilities through a gateway now.
	allowed := false
	if in.RequestId == nil {
		if p, err := a.q.GetAuthProvider(r.Context(), in.ProviderId); err == nil && p.ServerID.Valid {
			if allowed, err = a.Gateways.UsesServer(r.Context(), id.User, p.ServerID.UUID); failed(w, r, err) {
				return
			}
		}
	}
	st, err := a.Providers.Start(r.Context(), a.actor(r), providers.StartInput{
		ProviderID: in.ProviderId, RequestID: in.RequestId, ReturnTo: in.ReturnTo, Scopes: in.Scopes, SessionID: id.SessionID,
		ServerBoundAllowed: allowed,
	})
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, apitypes.ConnectStarted{AuthorizeUrl: st.AuthorizeURL, Scopes: st.Scopes, ExpiresAt: st.ExpiresAt})
}

func (a *api) confirmConnectRequest(w http.ResponseWriter, r *http.Request) {
	if id, _ := auth.FromContext(r.Context()); id.SessionID == "" {
		httpx.Error(w, http.StatusForbidden, "session_required", "Confirm from the web app")
		return
	}
	c, err := a.Providers.ConfirmRequest(r.Context(), a.actor(r), r.PathValue("requestId"))
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, apitypes.ConnectConfirmed{Provider: toAPIProviderRef(c.Provider), Server: toAPIConnectServer(c.Server),
		Scopes: nonNilStrings(c.Scopes)})
}

func (a *api) getConnectRequest(w http.ResponseWriter, r *http.Request) {
	v, err := a.Providers.GetRequest(r.Context(), a.actor(r), r.PathValue("requestId"))
	if failed(w, r, err) {
		return
	}
	req := v.Request
	var server *apitypes.ConnectServer
	if v.Server != nil {
		sv := toAPIConnectServer(*v.Server)
		server = &sv
	}
	httpx.JSON(w, http.StatusOK, apitypes.ConnectRequest{Server: server,
		Id: v.ID, Provider: toAPIProviderRef(v.Provider), Reason: apitypes.ConnectRequestReason(v.Reason),
		RequiredScopes: nonNilStrings(req.RequiredScopes), RequestScopes: v.RequestScopes, GrantedScopes: v.Granted,
		AccountLabel: v.AccountLabel, Gateway: apitypes.CallRef{Id: req.GatewayID, Slug: v.GatewaySlug, Name: v.GatewayName, Exists: v.GatewayExists},
		Capability: apitypes.ConnectRequestCapability{Kind: apitypes.GatewayCapabilityKind(req.CapabilityKind), ExposedName: req.ExposedName,
			Title: req.CapabilityTitle},
		CreatedAt: req.CreatedAt, ExpiresAt: req.ExpiresAt, AuthorizationServerHost: optStr(v.AuthorizationServerHost),
	})
}

func (a *api) setTeamMcpCapabilityRequirement(w http.ResponseWriter, r *http.Request) {
	serverID, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	capID, ok := pathUUID(w, r, "capabilityId")
	if !ok {
		return
	}
	in, rev, ok := decodeRevised[apitypes.CapabilityRequirementOverride](w, r)
	if !ok {
		return
	}
	c, revision, err := a.Registry.SetCapabilityRequirement(r.Context(), a.actor(r), r.PathValue("team"), serverID, capID,
		registry.OverrideInput{Mode: string(in.Mode), Scopes: in.Scopes}, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, revision, toAPICapability(c))
}

// connectCallback is where providers send the browser back. It always
// answers 303 to a same-origin path: the return path of the request, or the
// web app's /connect/done with the result. Never a token or the provider's
// own words.
func (a *api) connectCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if len(r.URL.RawQuery) > 8000 {
		http.Redirect(w, r, providers.DonePath+"?result="+providers.ResultExpired, http.StatusSeeOther)
		return
	}
	q := r.URL.Query()
	in := providers.CallbackInput{State: q.Get("state"), Code: q.Get("code"), Error: q.Get("error"), Iss: q.Get("iss"),
		RequestID: httpx.RequestID(r.Context()), ClientIP: httpx.ClientIP(r, a.Config.TrustedProxies)}
	id, ok, err := a.Auth.SessionIdentity(r)
	if err != nil {
		a.Log.ErrorContext(r.Context(), "connect callback session", "err", err, "request_id", in.RequestID)
	} else if ok {
		in.SessionID, in.User = id.SessionID, id.User
	}
	to, err := a.Providers.Callback(r.Context(), in)
	if err != nil {
		if !errors.Is(err, r.Context().Err()) {
			a.Log.ErrorContext(r.Context(), "connect callback", "err", err, "request_id", in.RequestID)
		}
		to = providers.DonePath + "?result=" + providers.ResultError
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}
