package httpapi

import (
	"net/http"

	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
)

func (a *api) adminListGateways(w http.ResponseWriter, r *http.Request) {
	p, limit, ok := gatewayListParams(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	switch v := q.Get("ownerKind"); v {
	case "":
	case gateways.OwnerTeam, gateways.OwnerPlatform:
		p.OwnerKind = &v
	default:
		httpx.Error(w, http.StatusBadRequest, "invalid_owner_kind", "ownerKind must be team or platform")
		return
	}
	if v := q.Get("team"); v != "" {
		if len(v) > 100 {
			httpx.Error(w, http.StatusBadRequest, "invalid_team", "team must be a team slug or ID")
			return
		}
		p.Team = v
	}
	rows, err := a.Gateways.AdminList(r.Context(), a.actor(r), p)
	a.writeGatewayPage(w, r, rows, err, limit)
}

func (a *api) adminCreateGateway(w http.ResponseWriter, r *http.Request) {
	var in apitypes.GatewayCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	v, err := a.Gateways.AdminCreate(r.Context(), a.actor(r), createInput(in))
	a.writeGateway(w, r, http.StatusCreated, v, err)
}

func (a *api) adminGetGateway(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	v, err := a.Gateways.AdminGet(r.Context(), a.actor(r), id)
	a.writeGateway(w, r, http.StatusOK, v, err)
}

func (a *api) adminUpdateGateway(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	in, rev, ok := decodeGatewayUpdate(w, r)
	if !ok {
		return
	}
	v, err := a.Gateways.AdminUpdate(r.Context(), a.actor(r), id, in, rev)
	a.writeGateway(w, r, http.StatusOK, v, err)
}

func (a *api) adminDeleteGateway(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	writeOK(w, r, a.Gateways.AdminDelete(r.Context(), a.actor(r), id))
}

func (a *api) adminListGatewayCapabilities(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	s, err := a.Gateways.AdminSelection(r.Context(), a.actor(r), id)
	a.writeSelection(w, r, s, err)
}

func (a *api) adminSetGatewayCapabilities(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	in, rev, ok := decodeRevised[apitypes.GatewayCapabilitiesUpdate](w, r)
	if !ok {
		return
	}
	s, err := a.Gateways.AdminSetSelection(r.Context(), a.actor(r), id, selectionInput(in), rev)
	a.writeSelection(w, r, s, err)
}

func (a *api) adminListGatewayOptions(w http.ResponseWriter, r *http.Request) {
	p, limit, ok := optionParams(w, r)
	if !ok {
		return
	}
	opts, err := a.Gateways.AdminOptions(r.Context(), a.actor(r), p)
	writeOptionPage(w, r, opts, err, limit)
}

func (a *api) adminListGatewayGrants(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	grants, err := a.Gateways.Grants(r.Context(), a.actor(r), id)
	writeList(w, r, grants, err, toAPIGrant)
}

func (a *api) adminAddGatewayGrant(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	var in apitypes.GatewayGrantCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	g, err := a.Gateways.AddGrant(r.Context(), a.actor(r), id, gateways.GrantInput{
		Kind: string(in.SubjectKind), Team: in.Team, UserEmail: in.UserEmail, Group: in.Group, ToolScope: fromAPIToolScope(in.ToolScope), ExpiresInDays: in.ExpiresInDays,
	})
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusCreated, toAPIGrant(g))
}

func (a *api) adminRemoveGatewayGrant(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	grantID, ok := pathUUID(w, r, "grantId")
	if !ok {
		return
	}
	writeOK(w, r, a.Gateways.RemoveGrant(r.Context(), a.actor(r), id, grantID))
}
