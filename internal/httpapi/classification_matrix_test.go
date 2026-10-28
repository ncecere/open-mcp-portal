package httpapi_test

// Classification changes trust, so only team owners/admins may set it.
// Neither platform roles alone nor automation tokens may classify.
func init() {
	for _, bulk := range []bool{false, true} {
		op := "setTeamMcpCapabilityClass"
		if bulk {
			op = "setTeamMcpCapabilityClasses"
		}
		matrixPolicies[op] = policy{scope: scopeTeam, own: admins, build: func(c *mctx) request {
			srv, capID := c.serverCapability()
			path := c.team("/mcp-servers/" + srv + "/capabilities/" + capID + "/class")
			body := map[string]any{"toolClass": "destructive"}
			if bulk {
				path = c.team("/mcp-servers/" + srv + "/capabilities/classes")
				body = map[string]any{"items": []any{map[string]any{"capabilityId": capID, "toolClass": "destructive"}}}
			}
			return request{method: "PUT", path: path, body: body, headers: rev1}
		}}
	}
}
