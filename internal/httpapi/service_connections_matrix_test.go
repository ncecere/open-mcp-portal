package httpapi_test

import "fmt"

func (c *mctx) serviceConnection() string {
	return c.e.exec(`INSERT INTO service_connections(team_id,provider_id,name,connected_by) VALUES($1,$2,$3,$4) RETURNING id::text`, c.tf.id, c.e.provider, fmt.Sprintf("shared-%d", c.e.next()), c.e.userIDs[cOwner])
}
func init() {
	matrixPolicies["listTeamServiceConnections"] = policy{scope: scopeTeam, own: members, build: func(c *mctx) request { return get(c.team("/service-connections")) }}
	matrixPolicies["adminListServiceConnections"] = policy{own: platform, build: func(c *mctx) request { return get("/v1/admin/service-connections?limit=5") }}
	matrixPolicies["startTeamServiceConnection"] = policy{scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return post(c.team("/service-connections"), map[string]any{"providerId": c.e.provider, "name": fmt.Sprintf("new-shared-%d", c.e.next())})
	}}
	matrixPolicies["updateTeamServiceConnection"] = policy{scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return request{method: "PUT", path: c.team("/service-connections/" + c.serviceConnection()), body: map[string]any{"accounts": []string{}, "servers": []any{}}, headers: rev1}
	}}
	matrixPolicies["revokeTeamServiceConnection"] = policy{scope: scopeTeam, own: admins, build: func(c *mctx) request { return del(c.team("/service-connections/" + c.serviceConnection())) }}
	matrixPolicies["reconnectTeamServiceConnection"] = policy{scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return post(c.team("/service-connections/"+c.serviceConnection()+"/reconnect"), nil).h(rev1)
	}}
	matrixPolicies["listServiceConnectionAllowableServers"] = policy{scope: scopeTeam, own: members, build: func(c *mctx) request {
		return get(c.team("/service-connections/" + c.serviceConnection() + "/allowable-servers"))
	}}
}
