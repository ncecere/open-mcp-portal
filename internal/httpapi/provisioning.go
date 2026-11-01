package httpapi

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/scim"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// SCIM provisioning (decision 92, docs/scim.md). The admin surface is
// browser-session only; /scim/v2 is a protocol of its own, authenticated by
// directory tokens and outside the management API's contract.
func (a *api) provisioningRoutes() []route {
	routes := []route{
		{"GET", "/v1/admin/provisioning", a.admin(a.adminGetProvisioning)},
		{"POST", "/v1/admin/provisioning", a.admin(a.adminCreateProvisioning)},
		{"PATCH", "/v1/admin/provisioning", a.admin(a.adminUpdateProvisioning)},
		{"GET", "/v1/admin/provisioning/tokens", a.admin(a.adminListProvisioningTokens)},
		{"POST", "/v1/admin/provisioning/tokens", a.admin(a.adminCreateProvisioningToken)},
		{"DELETE", "/v1/admin/provisioning/tokens/{tokenId}", a.admin(a.adminRevokeProvisioningToken)},
		{"GET", "/v1/admin/provisioning/users", a.admin(a.adminListProvisionedUsers)},
		{"POST", "/v1/admin/provisioning/users/{scimUserId}/adopt", a.admin(a.adminAdoptProvisionedUser)},
		{"POST", "/v1/admin/provisioning/people/{userId}/unlink", a.admin(a.adminUnlinkProvisionedPerson)},
		{"GET", "/v1/admin/provisioning/groups", a.admin(a.adminListProvisionedGroups)},
		{"GET", "/v1/admin/provisioning/mappings", a.admin(a.adminListProvisioningMappings)},
		{"POST", "/v1/admin/provisioning/mappings", a.admin(a.adminCreateProvisioningMapping)},
		{"DELETE", "/v1/admin/provisioning/mappings/{mappingId}", a.admin(a.adminDeleteProvisioningMapping)},
	}
	// The protocol needs a configured service; the admin routes are always
	// registered (the server always has one; contract tests list routes).
	if a.SCIM != nil {
		routes = append(routes, route{"", scim.Prefix + "/", a.SCIM.Handler(a.scimAllow)})
	}
	return routes
}

// scimAllow applies the per-credential request limit to directory tokens.
func (a *api) scimAllow(ctx context.Context, key string) (bool, time.Duration, error) {
	return ratelimit.Allow(ctx, a.limiter, key, a.Config.RequestsPerMinute)
}

func (a *api) toAPIProvisioning(d scim.Directory) apitypes.ProvisioningDirectory {
	return apitypes.ProvisioningDirectory{Id: d.Row.ID, Issuer: d.Row.Issuer, IssuerMatches: d.IssuerMatch, Enabled: d.Row.Enabled,
		Enrollment: apitypes.ProvisioningEnrollment(d.Row.Enrollment), ScimBaseUrl: a.Config.AppURL + scim.Prefix,
		Revision: d.Row.Revision, CreatedAt: d.Row.CreatedAt, UpdatedAt: d.Row.UpdatedAt}
}

func (a *api) adminGetProvisioning(w http.ResponseWriter, r *http.Request) {
	d, err := a.SCIM.GetDirectory(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, d.Row.Revision, a.toAPIProvisioning(d))
}

func (a *api) adminCreateProvisioning(w http.ResponseWriter, r *http.Request) {
	var in apitypes.ProvisioningSettings
	if !httpx.Decode(w, r, &in) {
		return
	}
	d, err := a.SCIM.SaveDirectory(r.Context(), a.actor(r), scim.DirectoryInput{Enabled: in.Enabled, Enrollment: string(in.Enrollment)}, 0)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusCreated, d.Row.Revision, a.toAPIProvisioning(d))
}

func (a *api) adminUpdateProvisioning(w http.ResponseWriter, r *http.Request) {
	in, rev, ok := decodeRevised[apitypes.ProvisioningSettings](w, r)
	if !ok {
		return
	}
	if rev == 0 {
		httpx.Fail(w, r, apperr.Stale())
		return
	}
	d, err := a.SCIM.SaveDirectory(r.Context(), a.actor(r), scim.DirectoryInput{Enabled: in.Enabled, Enrollment: string(in.Enrollment)}, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, d.Row.Revision, a.toAPIProvisioning(d))
}

func toAPIProvisioningToken(t scim.Token) apitypes.ProvisioningToken {
	return apitypes.ProvisioningToken{Id: t.Row.ID, Name: t.Row.Name, Prefix: t.Row.Prefix, Status: apitypes.ProvisioningTokenStatus(t.Status(time.Now())),
		CreatedAt: t.Row.CreatedAt, ExpiresAt: t.Row.ExpiresAt, RevokedAt: t.Row.RevokedAt, LastUsedAt: t.Row.LastUsedAt, CreatedByName: t.Row.CreatedByName}
}

func (a *api) adminListProvisioningTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := a.SCIM.ListTokens(r.Context(), a.actor(r))
	writeList(w, r, ts, err, toAPIProvisioningToken)
}

func (a *api) adminCreateProvisioningToken(w http.ResponseWriter, r *http.Request) {
	var in apitypes.ProvisioningTokenCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	var days int32
	if in.ExpiresInDays != nil {
		days = *in.ExpiresInDays
	}
	c, err := a.SCIM.CreateToken(r.Context(), a.actor(r), in.Name, days)
	if failed(w, r, err) {
		return
	}
	t := toAPIProvisioningToken(c.Token)
	httpx.JSON(w, http.StatusCreated, apitypes.ProvisioningTokenCreated{Id: t.Id, Name: t.Name, Prefix: t.Prefix,
		Status: apitypes.ProvisioningTokenCreatedStatus(t.Status), CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt,
		CreatedByName: t.CreatedByName, Secret: c.Secret})
}

func (a *api) adminRevokeProvisioningToken(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "tokenId")
	if !ok {
		return
	}
	writeOK(w, r, a.SCIM.RevokeToken(r.Context(), a.actor(r), id))
}

func (a *api) adminListProvisionedUsers(w http.ResponseWriter, r *http.Request) {
	p, err := a.SCIM.ListProvisioned(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	out := apitypes.ProvisionedUsers{Resources: make([]apitypes.ProvisionedUser, len(p.Resources)), People: make([]apitypes.ManagedPerson, len(p.People)),
		Truncated: p.Truncated}
	for i, row := range p.Resources {
		u := row.ScimUser
		v := apitypes.ProvisionedUser{Id: u.ID, UserName: u.UserName, ExternalId: u.ExternalID, Active: u.Active, DisplayName: u.DisplayName, Email: u.Email}
		if u.LinkedUserID.Valid && row.LinkedStatus != nil && row.LinkedStanding != nil {
			v.Linked = &apitypes.ProvisionedPersonRef{Id: u.LinkedUserID.UUID, Email: row.LinkedEmail.String, DisplayName: deref(row.LinkedDisplayName),
				Status: apitypes.UserStatus(*row.LinkedStatus), DirectoryStanding: apitypes.DirectoryStanding(*row.LinkedStanding)}
		}
		if row.CandidateUserID.Valid {
			adoptable, reason := scim.Adoption(row)
			c := struct {
				Adoptable bool                                     `json:"adoptable"`
				Email     string                                   `json:"email"`
				Id        uuid.UUID                                `json:"id"`
				Reason    *apitypes.ProvisionedUserCandidateReason `json:"reason,omitempty"`
			}{Adoptable: adoptable, Email: row.CandidateEmail.String, Id: row.CandidateUserID.UUID}
			if reason != "" {
				rr := apitypes.ProvisionedUserCandidateReason(reason)
				c.Reason = &rr
			}
			v.Candidate = &c
		}
		out.Resources[i] = v
	}
	for i, m := range p.People {
		out.People[i] = toAPIManagedPerson(m)
	}
	httpx.JSON(w, http.StatusOK, out)
}

func toAPIManagedPerson(m dbgen.ListDirectoryManagedUsersRow) apitypes.ManagedPerson {
	p := apitypes.ManagedPerson{Id: m.ID, Email: m.Email, DisplayName: m.DisplayName, Status: apitypes.UserStatus(m.Status),
		ManualStatus: apitypes.UserStatus(m.ManualStatus), DirectoryStanding: apitypes.DirectoryStanding(m.DirectoryStanding), CleanupPending: m.CleanupPending}
	if m.ScimUserID.Valid {
		id := m.ScimUserID.UUID
		p.ScimUserId = &id
	}
	return p
}

func (a *api) adminAdoptProvisionedUser(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "scimUserId")
	if !ok {
		return
	}
	writeOK(w, r, a.SCIM.Adopt(r.Context(), a.actor(r), id))
}

func (a *api) adminUnlinkProvisionedPerson(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "userId")
	if !ok {
		return
	}
	writeOK(w, r, a.SCIM.Unlink(r.Context(), a.actor(r), id))
}

func (a *api) adminListProvisionedGroups(w http.ResponseWriter, r *http.Request) {
	gs, err := a.SCIM.ListGroups(r.Context(), a.actor(r))
	writeList(w, r, gs, err, func(g dbgen.ListSCIMGroupsAdminRow) apitypes.ProvisionedGroup {
		return apitypes.ProvisionedGroup{Id: g.ID, DisplayName: g.DisplayName, ExternalId: g.ExternalID, MemberCount: g.MemberCount}
	})
}

func toAPIProvisioningMapping(m dbgen.ListSCIMGroupMappingsRow) apitypes.ProvisioningMapping {
	return apitypes.ProvisioningMapping{Id: m.ScimGroupMapping.ID, GroupId: m.ScimGroupMapping.GroupID, GroupName: m.GroupName,
		TeamId: m.ScimGroupMapping.TeamID, TeamSlug: m.TeamSlug, TeamName: m.TeamName, Role: apitypes.ProvisioningMappingRole(m.ScimGroupMapping.Role),
		MemberCount: m.MemberCount, CreatedAt: m.ScimGroupMapping.CreatedAt}
}

func (a *api) adminListProvisioningMappings(w http.ResponseWriter, r *http.Request) {
	ms, err := a.SCIM.ListMappings(r.Context(), a.actor(r))
	writeList(w, r, ms, err, toAPIProvisioningMapping)
}

func (a *api) adminCreateProvisioningMapping(w http.ResponseWriter, r *http.Request) {
	var in apitypes.ProvisioningMappingCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	m, err := a.SCIM.CreateMapping(r.Context(), a.actor(r), scim.MappingInput{GroupID: in.GroupId, TeamID: in.TeamId, Role: string(in.Role)})
	if failed(w, r, err) {
		return
	}
	ms, err := a.SCIM.ListMappings(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	for _, row := range ms {
		if row.ScimGroupMapping.ID == m.ID {
			httpx.JSON(w, http.StatusCreated, toAPIProvisioningMapping(row))
			return
		}
	}
	httpx.Fail(w, r, apperr.NotFound("mapping_not_found", "Mapping not found"))
}

func (a *api) adminDeleteProvisioningMapping(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "mappingId")
	if !ok {
		return
	}
	writeOK(w, r, a.SCIM.DeleteMapping(r.Context(), a.actor(r), id))
}
