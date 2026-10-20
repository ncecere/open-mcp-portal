package httpapi

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/serviceaccounts"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Service accounts and their keys (api/openapi.yaml, tag service-accounts;
// docs/phase4-client-auth.md). internal/serviceaccounts authorizes every
// call; a key's secret is only ever returned by create.

// serviceAccountRoutes: a team's service accounts and their keys.
func (a *api) serviceAccountRoutes() []route {
	const base = "/v1/teams/{team}/service-accounts"
	const one = base + "/{serviceAccountId}"
	return []route{
		{"GET", base, a.session(a.listServiceAccounts)},
		{"POST", base, a.session(a.createServiceAccount)},
		{"GET", one, a.session(a.getServiceAccount)},
		{"PATCH", one, a.session(a.updateServiceAccount)},
		{"DELETE", one, a.session(a.deleteServiceAccount)},
		{"GET", one + "/gateways", a.session(a.listServiceAccountGateways)},
		{"GET", one + "/keys", a.session(a.listServiceAccountKeys)},
		{"POST", one + "/keys", a.session(a.createServiceAccountKey)},
		{"DELETE", one + "/keys/{keyId}", a.session(a.revokeServiceAccountKey)},
	}
}

// serviceAccountAdminRoutes: every team's service accounts (platform staff).
func (a *api) serviceAccountAdminRoutes() []route {
	return []route{{"GET", "/v1/admin/service-accounts", a.admin(a.adminListServiceAccounts)}}
}

func toAPIServiceAccount(v serviceaccounts.View) apitypes.ServiceAccount {
	sa := v.Account
	return apitypes.ServiceAccount{
		RelayPlatform: relayPlatform(sa, v.RelayPlatformName),
		Id:            sa.ID, TeamId: sa.TeamID, TeamSlug: v.TeamSlug, Name: sa.Name, Description: sa.Description,
		Role: apitypes.ServiceAccountRole(sa.Role), Enabled: sa.Enabled, ActiveKeyCount: v.ActiveKeys, LastUsedAt: sa.LastUsedAt,
		CreatedByName: v.CreatedByName, Revision: sa.Revision, CreatedAt: sa.CreatedAt, UpdatedAt: sa.UpdatedAt,
	}
}

// relayPlatform is the agent platform a service account relays for (nil: none).
func relayPlatform(sa dbgen.ServiceAccount, name string) *apitypes.ServiceAccountRelayPlatform {
	if !sa.RelayPlatformID.Valid {
		return nil
	}
	return &apitypes.ServiceAccountRelayPlatform{Id: sa.RelayPlatformID.UUID, Name: name}
}

func toAPIServiceAccountKey(v serviceaccounts.KeyView, now time.Time) apitypes.ServiceAccountKey {
	k := v.Key
	out := apitypes.ServiceAccountKey{
		Id: k.ID, Name: k.Name, Prefix: k.Prefix, Status: apitypes.ServiceAccountKeyStatus(serviceaccounts.KeyStatus(k, now)),
		CreatedAt: k.CreatedAt, CreatedByName: v.CreatedByName, ExpiresAt: k.ExpiresAt, LastUsedAt: k.LastUsedAt,
		RevokedAt: k.RevokedAt, Gateways: make([]apitypes.ApiKeyGateway, len(v.Gateways)),
	}
	for i, g := range v.Gateways {
		out.Gateways[i] = apitypes.ApiKeyGateway{Id: g.ID, Slug: g.Slug, Name: g.Name, Exists: g.Exists}
	}
	return out
}

func (a *api) writeServiceAccount(w http.ResponseWriter, r *http.Request, status int, v serviceaccounts.View, err error) {
	if failed(w, r, err) {
		return
	}
	writeRevised(w, status, v.Account.Revision, toAPIServiceAccount(v))
}

func (a *api) listServiceAccounts(w http.ResponseWriter, r *http.Request) {
	rows, err := a.ServiceAccounts.List(r.Context(), a.actor(r), r.PathValue("team"))
	writeList(w, r, rows, err, toAPIServiceAccount)
}

func (a *api) createServiceAccount(w http.ResponseWriter, r *http.Request) {
	var in apitypes.ServiceAccountCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	ci := serviceaccounts.CreateInput{Name: in.Name, Enabled: true}
	setIf(&ci.Description, in.Description)
	setIf(&ci.Enabled, in.Enabled)
	if in.Role != nil {
		ci.Role = string(*in.Role)
	}
	v, err := a.ServiceAccounts.Create(r.Context(), a.actor(r), r.PathValue("team"), ci)
	a.writeServiceAccount(w, r, http.StatusCreated, v, err)
}

func (a *api) getServiceAccount(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serviceAccountId")
	if !ok {
		return
	}
	v, err := a.ServiceAccounts.Get(r.Context(), a.actor(r), r.PathValue("team"), id)
	a.writeServiceAccount(w, r, http.StatusOK, v, err)
}

func (a *api) updateServiceAccount(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serviceAccountId")
	if !ok {
		return
	}
	in, rev, ok := decodeRevised[apitypes.ServiceAccountUpdate](w, r)
	if !ok {
		return
	}
	ui := serviceaccounts.UpdateInput{Name: in.Name, Description: in.Description, Enabled: in.Enabled}
	if in.Role != nil {
		role := string(*in.Role)
		ui.Role = &role
	}
	v, err := a.ServiceAccounts.Update(r.Context(), a.actor(r), r.PathValue("team"), id, ui, rev)
	a.writeServiceAccount(w, r, http.StatusOK, v, err)
}

func (a *api) deleteServiceAccount(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serviceAccountId")
	if !ok {
		return
	}
	writeOK(w, r, a.ServiceAccounts.Delete(r.Context(), a.actor(r), r.PathValue("team"), id))
}

func (a *api) listServiceAccountGateways(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serviceAccountId")
	if !ok {
		return
	}
	mine, err := a.ServiceAccounts.Gateways(r.Context(), a.actor(r), r.PathValue("team"), id)
	writeList(w, r, mine, err, a.toAPIMyGateway)
}

// adminListServiceAccounts reads ?q=, ?team=, ?cursor= and ?limit=.
func (a *api) adminListServiceAccounts(w http.ResponseWriter, r *http.Request) {
	limit, ok := pageLimit(w, r)
	if !ok {
		return
	}
	q, ok := search(w, r)
	if !ok {
		return
	}
	keys, ok := decodeCursor(w, r, 2)
	if !ok {
		return
	}
	p := serviceaccounts.AdminListParams{Search: q, Limit: limit + 1}
	if keys != nil {
		id, err := uuid.Parse(keys[1])
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_cursor", "Invalid cursor")
			return
		}
		p.AfterName, p.AfterID = &keys[0], &id
	}
	if v := r.URL.Query().Get("team"); v != "" {
		if len(v) > 100 {
			httpx.Error(w, http.StatusBadRequest, "invalid_team", "team must be a team slug or ID")
			return
		}
		p.Team = v
	}
	rows, err := a.ServiceAccounts.AdminList(r.Context(), a.actor(r), p)
	if failed(w, r, err) {
		return
	}
	page := apitypes.ServiceAccountPage{Items: []apitypes.ServiceAccount{}}
	if len(rows) > int(limit) {
		rows = rows[:limit]
		last := rows[len(rows)-1].Account
		page.NextCursor = encodeCursor(last.Name, last.ID.String())
	}
	for _, v := range rows {
		page.Items = append(page.Items, toAPIServiceAccount(v))
	}
	httpx.JSON(w, http.StatusOK, page)
}

func (a *api) listServiceAccountKeys(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serviceAccountId")
	if !ok {
		return
	}
	keys, err := a.ServiceAccounts.ListKeys(r.Context(), a.actor(r), r.PathValue("team"), id)
	now := time.Now()
	writeList(w, r, keys, err, func(k serviceaccounts.KeyView) apitypes.ServiceAccountKey { return toAPIServiceAccountKey(k, now) })
}

func (a *api) createServiceAccountKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serviceAccountId")
	if !ok {
		return
	}
	var in apitypes.ServiceAccountKeyCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	days := int32(0)
	setIf(&days, in.ExpiresInDays)
	if in.ExpiresInDays != nil && days == 0 {
		days = -1 // explicit 0 is invalid, not the default
	}
	ci := serviceaccounts.CreateKeyInput{Name: in.Name, Days: days}
	if in.GatewayIds != nil {
		ci.GatewayIDs = *in.GatewayIds
	}
	c, err := a.ServiceAccounts.CreateKey(r.Context(), a.actor(r), r.PathValue("team"), id, ci)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusCreated, apitypes.ServiceAccountKeyCreated{Key: toAPIServiceAccountKey(c.KeyView, time.Now()), Secret: c.Secret})
}

func (a *api) revokeServiceAccountKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serviceAccountId")
	if !ok {
		return
	}
	keyID, ok := pathUUID(w, r, "keyId")
	if !ok {
		return
	}
	writeOK(w, r, a.ServiceAccounts.RevokeKey(r.Context(), a.actor(r), r.PathValue("team"), id, keyID))
}
