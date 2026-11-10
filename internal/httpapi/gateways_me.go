package httpapi

import (
	"net/http"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/apikeys"
	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
)

func (a *api) listMyGateways(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	mine, err := a.Gateways.ListMine(r.Context(), id.User)
	writeList(w, r, mine, err, a.toAPIMyGateway)
}

func (a *api) getMyGateway(w http.ResponseWriter, r *http.Request) {
	gid, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	id, _ := auth.FromContext(r.Context())
	m, offers, err := a.Gateways.GetMine(r.Context(), id.User, gid)
	if failed(w, r, err) {
		return
	}
	ready, err := a.Providers.ReadyFor(r.Context(), id.User.ID)
	if failed(w, r, err) {
		return
	}
	out := apitypes.MyGatewayDetail{Gateway: a.toAPIMyGateway(m), Capabilities: make([]apitypes.GatewayCapability, len(offers))}
	for i, o := range offers {
		out.Capabilities[i] = toAPIGatewayCapability(o.Selected)
		// My gateways is the model-facing view, not the policy editor. Keep
		// the edited indicator but don't reveal hidden fixed values here.
		out.Capabilities[i].OriginalDefinition = nil
		if o.Curation != nil {
			out.Capabilities[i].Curation = []byte(`{}`)
		}
		if req := o.Requires; req != nil {
			// Connected: a call would carry the token now (the person also
			// allowed this capability's server, at its current address).
			connected := ready(req, o.Server)
			out.Capabilities[i].Requires = toAPIRequirement(req, &connected)
		}
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (a *api) listMyApiKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := a.APIKeys.List(r.Context(), a.actor(r))
	now := time.Now()
	writeList(w, r, keys, err, func(k apikeys.View) apitypes.ApiKey { return toAPIKey(k, now) })
}

func (a *api) createMyApiKey(w http.ResponseWriter, r *http.Request) {
	var in apitypes.ApiKeyCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	days := int32(0)
	setIf(&days, in.ExpiresInDays)
	if in.ExpiresInDays != nil && days == 0 {
		days = -1 // explicit 0 is invalid, not the default
	}
	ci := apikeys.CreateInput{Name: in.Name, Days: days, ToolScope: fromAPIToolScope(in.ToolScope)}
	if in.GatewayIds != nil {
		ci.GatewayIDs = *in.GatewayIds
	}
	c, err := a.APIKeys.Create(r.Context(), a.actor(r), ci)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusCreated, apitypes.ApiKeyCreated{Key: toAPIKey(c.View, time.Now()), Secret: c.Secret})
}

func (a *api) revokeMyApiKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "keyId")
	if !ok {
		return
	}
	writeOK(w, r, a.APIKeys.Revoke(r.Context(), a.actor(r), id))
}
