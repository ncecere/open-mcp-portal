// Per-person secrets (api/openapi.yaml, tags me, connections and admin;
// docs/person-secrets.md, decision 72): a person enters their own key for a
// server in person_secret mode, and platform admins can take anyone's away.
// Entering and removing a key are a person's own decision, so they are browser
// session only (never an automation token, a service account or an agent), and
// none of these operations has an x-omp-token-scopes entry (decision 58).
// The key is never in any response.

package httpapi

import (
	"net/http"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/personsecrets"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

// secretChangesPerMinute bounds entering and removing keys per person.
const secretChangesPerMinute = 20

func (a *api) personSecretRoutes() []route {
	return []route{
		{"GET", "/v1/me/server-secrets", a.session(a.listMyServerSecrets)},
		{"PUT", "/v1/me/server-secrets/{serverId}", a.session(a.setMyServerSecret)},
		{"DELETE", "/v1/me/server-secrets/{serverId}", a.session(a.revokeMyServerSecret)},
		{"GET", "/v1/connect/secret-requests/{requestId}", a.session(a.getSecretRequest)},
		{"GET", "/v1/admin/users/{userId}/server-secrets", a.admin(a.adminListUserServerSecrets)},
		{"DELETE", "/v1/admin/users/{userId}/server-secrets/{serverId}", a.admin(a.adminRevokeUserServerSecret)},
	}
}

func toAPIPersonSecretInput(c registry.PersonSecretInput) apitypes.PersonSecretInput {
	return apitypes.PersonSecretInput{Placement: apitypes.PersonSecretPlacement(c.Placement), Name: nonEmpty(c.Name), Prefix: &c.Prefix,
		Label: &c.Label, Help: &c.Help}
}

func fromAPIPersonSecretInput(in *apitypes.PersonSecretInput) *registry.PersonSecretInput {
	if in == nil {
		return nil
	}
	out := &registry.PersonSecretInput{Placement: string(in.Placement)}
	setIf(&out.Name, in.Name)
	setIf(&out.Prefix, in.Prefix)
	setIf(&out.Label, in.Label)
	setIf(&out.Help, in.Help)
	return out
}

// toAPIPersonSecretSettings is a server's person secret settings (nil for
// other modes): never a key.
func toAPIPersonSecretSettings(v *registry.PersonSecretView) *apitypes.PersonSecretSettings {
	if v == nil {
		return nil
	}
	out := &apitypes.PersonSecretSettings{Placement: apitypes.PersonSecretPlacement(v.Placement), Name: nonEmpty(v.Name), Prefix: v.Prefix,
		Label: v.Label, Help: v.Help, People: v.People, Rejected: v.Rejected,
		Setup: apitypes.PersonSecretSetup{Status: apitypes.PersonSecretSetupStatus(v.Setup.Status), PersonName: v.Setup.PersonName, At: v.Setup.At}}
	if v.Setup.PersonID.Valid {
		id := v.Setup.PersonID.UUID
		out.Setup.PersonId = &id
	}
	return out
}

func toAPIServerSecret(m personsecrets.Mine) apitypes.ServerSecret {
	out := apitypes.ServerSecret{
		Server: apitypes.ConnectServer{Id: m.Server.ID, Slug: m.Server.Slug, Name: m.Server.Name, TeamSlug: m.Server.TeamSlug, TeamName: m.Server.TeamName},
		Config: toAPIPersonSecretInput(m.Config), Origin: m.Origin, HasSecret: m.Has, AllowAgents: m.AllowAgents,
		Reachable: m.Reachable, CanSetup: m.CanSetup, IsSetup: m.IsSetup,
	}
	if m.Has {
		status := apitypes.ServerSecretStatus(m.Status)
		out.Hint, out.Status = &m.Hint, &status
		created := m.CreatedAt
		out.CreatedAt, out.RotatedAt, out.RejectedAt, out.LastUsedAt = &created, m.RotatedAt, m.RejectedAt, m.LastUsedAt
	}
	return out
}

func (a *api) listMyServerSecrets(w http.ResponseWriter, r *http.Request) {
	ms, err := a.PersonSecrets.ListMine(r.Context(), a.actor(r))
	writeList(w, r, ms, err, toAPIServerSecret)
}

func (a *api) setMyServerSecret(w http.ResponseWriter, r *http.Request) {
	serverID, ok := pathUUID(w, r, "serverId")
	if !ok || !a.browserOnly(w, r) {
		return
	}
	if !a.connectLimited(w, r, "person-secret", secretChangesPerMinute, "Too many changes to your keys. Try again shortly.") {
		return
	}
	var in apitypes.SetServerSecret
	if !httpx.Decode(w, r, &in) {
		return
	}
	m, err := a.PersonSecrets.Set(r.Context(), a.actor(r), serverID, personsecrets.SetInput{Value: in.Value, Origin: in.Origin,
		AllowAgents: in.AllowAgents, UseForSetup: in.UseForSetup != nil && *in.UseForSetup})
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPIServerSecret(m))
}

func (a *api) revokeMyServerSecret(w http.ResponseWriter, r *http.Request) {
	serverID, ok := pathUUID(w, r, "serverId")
	if !ok || !a.browserOnly(w, r) {
		return
	}
	if !a.connectLimited(w, r, "person-secret", secretChangesPerMinute, "Too many changes to your keys. Try again shortly.") {
		return
	}
	writeOK(w, r, a.PersonSecrets.Revoke(r.Context(), a.actor(r), serverID))
}

func (a *api) getSecretRequest(w http.ResponseWriter, r *http.Request) {
	v, err := a.PersonSecrets.GetRequest(r.Context(), a.actor(r), r.PathValue("requestId"))
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, apitypes.SecretRequest{
		Id: v.ID, Reason: apitypes.SecretRequestReason(v.Reason),
		Server: apitypes.ConnectServer{Id: v.Server.ID, Slug: v.Server.Slug, Name: v.Server.Name, TeamSlug: v.Server.TeamSlug, TeamName: v.Server.TeamName},
		Config: toAPIPersonSecretInput(v.Config), Origin: v.Origin,
		Gateway:    apitypes.CallRef{Id: v.GatewayID, Slug: v.GatewaySlug, Name: v.GatewayName, Exists: v.GatewayExists},
		Capability: apitypes.ConnectRequestCapability{Kind: apitypes.GatewayCapabilityKind(v.CapabilityKind), ExposedName: v.ExposedName, Title: v.Title},
		Secret:     toAPIServerSecret(v.Mine),
	})
}

func (a *api) adminListUserServerSecrets(w http.ResponseWriter, r *http.Request) {
	userID, ok := pathUUID(w, r, "userId")
	if !ok {
		return
	}
	ms, err := a.PersonSecrets.AdminList(r.Context(), a.actor(r), userID)
	writeList(w, r, ms, err, toAPIServerSecret)
}

func (a *api) adminRevokeUserServerSecret(w http.ResponseWriter, r *http.Request) {
	userID, ok := pathUUID(w, r, "userId")
	if !ok {
		return
	}
	serverID, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	writeOK(w, r, a.PersonSecrets.AdminRevoke(r.Context(), a.actor(r), userID, serverID))
}
