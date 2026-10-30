package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

// Server governance (decision 88, docs/registry.md "Governance"): owner,
// on-call contact, sensitivity, lifecycle, transfers and the platform's
// re-review settings. The registry service authorizes; these handlers parse and
// render. Every operation but updateTeamMcpServer is browser-session only (no
// x-omp-token-scopes), and updateTeamMcpServer's governance field is refused to
// automation tokens whole.

func (a *api) governanceRoutes() []route {
	const team = "/v1/teams/{team}"
	return []route{
		{"POST", team + "/mcp-servers/{serverId}/transfer", a.session(a.requestTeamMcpServerTransfer)},
		{"GET", team + "/mcp-server-transfers", a.session(a.listTeamMcpServerTransfers)},
		{"DELETE", team + "/mcp-server-transfers/{transferId}", a.session(a.cancelMcpServerTransfer)},
		{"POST", team + "/mcp-server-transfers/{transferId}/accept", a.session(a.acceptMcpServerTransfer)},
	}
}

func (a *api) governanceAdminRoutes() []route {
	return []route{
		{"POST", "/v1/admin/mcp-servers/{serverId}/transfer", a.admin(a.adminForceTransferMcpServer)},
		{"GET", "/v1/admin/settings/governance", a.admin(a.adminGetGovernanceSettings)},
		{"PUT", "/v1/admin/settings/governance", a.admin(a.adminUpdateGovernanceSettings)},
	}
}

func apiTime(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

func toAPIReplacement(r *registry.ReplacementRef) *apitypes.ServerReplacementRef {
	if r == nil {
		return nil
	}
	return &apitypes.ServerReplacementRef{Id: r.ID, Slug: r.Slug, Name: r.Name, TeamSlug: r.TeamSlug, TeamName: r.TeamName}
}

// toAPIGovernance is a server's governance for its team and platform staff.
func toAPIGovernance(v registry.ServerView) *apitypes.McpServerGovernance {
	g := v.Governance
	confirmed := g.SensitivityConfirmed
	out := &apitypes.McpServerGovernance{Sensitivity: apitypes.Sensitivity(g.Sensitivity), SensitivityConfirmed: &confirmed, Lifecycle: apitypes.ServerLifecycle(g.Lifecycle),
		Ownerless: g.Ownerless, ReviewOverdue: g.ReviewOverdue, OncallContact: g.OncallContact, LastReviewedAt: apiTime(g.LastReviewedAt),
		ReviewDueAt: apiTime(g.ReviewDueAt), DeprecatedAt: apiTime(g.DeprecatedAt), SunsetAt: apiTime(g.SunsetAt),
		Replacement: toAPIReplacement(g.Replacement.Visible(v.Server.TeamID))}
	if g.OwnerUserID.Valid {
		id := g.OwnerUserID.UUID
		out.OwnerUserId = &id
		out.OwnerName = nonEmpty(g.OwnerName)
	}
	if t := g.PendingTransfer; t != nil {
		out.PendingTransfer = &apitypes.ServerTransferRef{Id: t.ID, ToTeamSlug: t.ToTeamSlug, ToTeamName: t.ToTeamName, RequestedAt: t.RequestedAt, Revision: t.Revision}
	}
	return out
}

// toAPICatalogGovernance is what the catalog shows of it: never the owner or
// the on-call contact, and only a published replacement.
func toAPICatalogGovernance(v registry.ServerView) *apitypes.CatalogServerGovernance {
	g := v.Governance
	return &apitypes.CatalogServerGovernance{Sensitivity: apitypes.Sensitivity(g.Sensitivity), Lifecycle: apitypes.ServerLifecycle(g.Lifecycle),
		DeprecatedAt: apiTime(g.DeprecatedAt), SunsetAt: apiTime(g.SunsetAt), Replacement: toAPIReplacement(g.Replacement.Visible(uuid.Nil))}
}

// governanceInput reads the governance object of an update; sent says whether
// it was in the body. Fields are told apart from null by the object's own keys.
func governanceInput(w http.ResponseWriter, in apitypes.McpServerUpdate, keys map[string]json.RawMessage) (*registry.GovernanceInput, bool) {
	raw, ok := keys["governance"]
	if !ok {
		return nil, true
	}
	if isNullRaw(raw) || in.Governance == nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_governance", "governance must be an object")
		return nil, false
	}
	inner := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &inner); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_governance", "governance must be an object")
		return nil, false
	}
	g := in.Governance
	out := &registry.GovernanceInput{}
	if _, ok := inner["ownerUserId"]; ok {
		out.SetOwner, out.OwnerUserID = true, g.OwnerUserId
	}
	if _, ok := inner["oncallContact"]; ok {
		out.SetOncall, out.OncallContact = true, g.OncallContact
	}
	if g.Sensitivity != nil {
		v := string(*g.Sensitivity)
		out.Sensitivity = &v
	}
	if g.Lifecycle != nil {
		v := string(*g.Lifecycle)
		out.Lifecycle = &v
	}
	if _, ok := inner["sunsetAt"]; ok {
		out.SetSunsetAt = true
		if g.SunsetAt != nil {
			t := g.SunsetAt.UTC()
			out.SunsetAt = &t
		}
	}
	if _, ok := inner["replacementServerId"]; ok {
		out.SetReplacement, out.ReplacementServerID = true, g.ReplacementServerId
	}
	return out, true
}

func isNullRaw(raw json.RawMessage) bool { return string(raw) == "null" }

func toAPITransfer(t registry.TransferView) apitypes.ServerTransfer {
	x := t.Transfer
	return apitypes.ServerTransfer{Id: x.ID, ServerId: x.ServerID, ServerSlug: t.ServerSlug, ServerName: t.ServerName,
		FromTeamSlug: t.FromTeamSlug, FromTeamName: t.FromTeamName, ToTeamSlug: t.ToTeamSlug, ToTeamName: t.ToTeamName,
		State: apitypes.ServerTransferState(x.State), Note: x.Note, RequestedByName: nonEmpty(t.RequestedByName), RequestedAt: x.RequestedAt,
		DecidedAt: apiTime(x.DecidedAt), Revision: x.Revision}
}

func (a *api) writeTransfer(w http.ResponseWriter, r *http.Request, status int, t registry.TransferView, err error) {
	if failed(w, r, err) {
		return
	}
	writeRevised(w, status, t.Transfer.Revision, toAPITransfer(t))
}

func (a *api) requestTeamMcpServerTransfer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	var in apitypes.ServerTransferRequest
	if !httpx.Decode(w, r, &in) {
		return
	}
	t, err := a.Registry.RequestTransfer(r.Context(), a.actor(r), r.PathValue("team"), id, in.ToTeam, in.Note)
	a.writeTransfer(w, r, http.StatusCreated, t, err)
}

func (a *api) listTeamMcpServerTransfers(w http.ResponseWriter, r *http.Request) {
	pending := r.URL.Query().Get("pendingOnly") == "true"
	rows, err := a.Registry.ListTransfers(r.Context(), a.actor(r), r.PathValue("team"), pending)
	writeList(w, r, rows, err, toAPITransfer)
}

func (a *api) acceptMcpServerTransfer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "transferId")
	if !ok {
		return
	}
	rev, ok := ifMatch(w, r)
	if !ok {
		return
	}
	t, err := a.Registry.AcceptTransfer(r.Context(), a.actor(r), r.PathValue("team"), id, rev)
	a.writeTransfer(w, r, http.StatusOK, t, err)
}

func (a *api) cancelMcpServerTransfer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "transferId")
	if !ok {
		return
	}
	rev, ok := ifMatch(w, r)
	if !ok {
		return
	}
	t, err := a.Registry.CancelTransfer(r.Context(), a.actor(r), r.PathValue("team"), id, rev)
	a.writeTransfer(w, r, http.StatusOK, t, err)
}

func (a *api) adminForceTransferMcpServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	rev, ok := ifMatch(w, r)
	if !ok {
		return
	}
	var in apitypes.ServerTransferForce
	if !httpx.Decode(w, r, &in) {
		return
	}
	v, err := a.Registry.ForceTransfer(r.Context(), a.actor(r), id, in.ToTeam, in.Note, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, v.Server.Revision, a.toAPIServer(v))
}

func toAPIGovernanceSettings(s registry.Settings) apitypes.GovernanceSettings {
	out := apitypes.GovernanceSettings{ReturnOverdueToReview: s.GovernanceReturnOverdue, Revision: s.GovernanceRevision, UpdatedAt: s.GovernanceUpdatedAt}
	out.ReviewIntervalDays.Public, out.ReviewIntervalDays.Internal = s.ReviewIntervalDaysPublic, s.ReviewIntervalDaysInternal
	out.ReviewIntervalDays.Confidential, out.ReviewIntervalDays.Restricted = s.ReviewIntervalDaysConfidential, s.ReviewIntervalDaysRestricted
	return out
}

func (a *api) adminGetGovernanceSettings(w http.ResponseWriter, r *http.Request) {
	s, err := a.Registry.GetSettings(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, s.GovernanceRevision, toAPIGovernanceSettings(s))
}

func (a *api) adminUpdateGovernanceSettings(w http.ResponseWriter, r *http.Request) {
	rev, ok := ifMatch(w, r)
	if !ok {
		return
	}
	var in apitypes.GovernanceSettingsUpdate
	if !httpx.Decode(w, r, &in) {
		return
	}
	gi := registry.GovernanceSettingsInput{ReturnOverdue: in.ReturnOverdueToReview}
	if d := in.ReviewIntervalDays; d != nil {
		gi.Public, gi.Internal, gi.Confidential, gi.Restricted = d.Public, d.Internal, d.Confidential, d.Restricted
	}
	s, err := a.Registry.UpdateGovernanceSettings(r.Context(), a.actor(r), gi, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, s.GovernanceRevision, toAPIGovernanceSettings(s))
}
