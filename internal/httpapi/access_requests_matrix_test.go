package httpapi_test

import "fmt"

func (c *mctx) requestableGateway() string {
	id := c.e.newGateway("")
	c.e.run(`UPDATE gateways SET access_requests_enabled=true WHERE id=$1`, id)
	return id
}

func (c *mctx) accessRequest(own bool) string {
	user := c.e.spareUser
	if own && c.who != cAnon {
		user = c.e.userIDs[c.who]
	}
	return c.e.exec(`INSERT INTO access_requests(gateway_id,requester_user_id,subject_kind,reason)
		VALUES ($1,$2,'user','Matrix request') RETURNING id::text`, c.requestableGateway(), user)
}

func init() {
	matrixPolicies["listRequestableGateways"] = policy{own: signedIn, build: func(*mctx) request { return get("/v1/gateways/requestable") }}
	matrixPolicies["listMyAccessRequests"] = policy{own: signedIn, build: func(*mctx) request { return get("/v1/me/access-requests") }}
	matrixPolicies["createAccessRequest"] = policy{own: signedIn, build: func(c *mctx) request {
		return post("/v1/me/access-requests", map[string]any{"gatewayId": c.requestableGateway(), "reason": "Matrix access"})
	}}
	matrixPolicies["getAccessRequest"] = policy{own: signedIn, build: func(c *mctx) request {
		return get("/v1/access-requests/" + c.accessRequest(c.allowed))
	}}
	matrixPolicies["withdrawAccessRequest"] = policy{own: signedIn, build: func(c *mctx) request {
		return post("/v1/access-requests/"+c.accessRequest(c.allowed)+"/withdraw", nil)
	}}
	matrixPolicies["decideAccessRequest"] = policy{own: padmin, build: func(c *mctx) request {
		return post("/v1/access-requests/"+c.accessRequest(false)+"/decision", map[string]any{"decision": "approve"})
	}}
	matrixPolicies["adminGetGatewayAccessSettings"] = policy{own: platform, build: func(c *mctx) request {
		return get(fmt.Sprintf("/v1/admin/gateways/%s/access-settings", c.platformGateway()))
	}}
	matrixPolicies["adminSetGatewayAccessSettings"] = policy{own: padmin, build: func(c *mctx) request {
		return request{method: "PUT", path: fmt.Sprintf("/v1/admin/gateways/%s/access-settings", c.platformGateway()),
			body: map[string]any{"enabled": true, "stewardIds": []string{}}, headers: rev1}
	}}
}
