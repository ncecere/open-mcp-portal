package httpapi_test

import (
	"fmt"

	"github.com/ncecere/open-mcp-portal/internal/registry"
)

// The authorization matrix's classification of every operation in
// api/openapi.yaml (SPEC.md §4, §9): who may call it on their own team (team
// B) or at all (global routes), and who may call it on another team (team
// A). Platform admins and auditors read any team's metadata; only platform
// admins change platform objects; team owners and admins manage members;
// editors and above read the team's audit log.

// caller is a kind of credential.
type caller int

const (
	cAnon caller = iota
	cMember
	cEditor
	cTeamAdmin
	cOwner
	cPlatformAdmin
	cAuditor
	numCallers
)

var callerNames = [numCallers]string{"anonymous", "member", "editor", "team-admin", "owner", "platform-admin", "auditor"}

func (c caller) String() string { return callerNames[c] }

// callers is a set of callers.
type callers uint32

func of(cs ...caller) callers {
	var s callers
	for _, c := range cs {
		s |= 1 << c
	}
	return s
}

func (s callers) has(c caller) bool { return s&(1<<c) != 0 }

var (
	everyone = callers(1<<numCallers - 1)
	members  = of(cMember, cEditor, cTeamAdmin, cOwner)
	editors  = of(cEditor, cTeamAdmin, cOwner)
	admins   = of(cTeamAdmin, cOwner)
	platform = of(cPlatformAdmin, cAuditor)
	padmin   = of(cPlatformAdmin)
	signedIn = members | platform
)

// scope says how an operation is exercised.
type scope int

const (
	// scopeGlobal: no team in the path; every caller calls it once.
	scopeGlobal scope = iota
	// scopeTeam: the path names a team; team B's callers call it on team B,
	// and every caller on team A.
	scopeTeam
)

// policy is one operation's classification.
type policy struct {
	scope scope
	// own: callers allowed on their own team (or at all, for scopeGlobal).
	own callers
	// foreign: callers allowed on team A.
	foreign callers
	// anyStatus: the status is not checked (sign-in plumbing), only that the
	// call didn't fail on the server.
	anyStatus bool
	build     func(c *mctx) request
}

// request is one call.
type request struct {
	method, path string
	body         any
	headers      map[string]string
	// anon: send without the caller's session (sign-in endpoints would
	// replace it).
	anon bool
	// ownSession: call with a new session of the caller's user (logout
	// would end the shared one).
	ownSession bool
}

func get(p string) request                       { return request{method: "GET", path: p} }
func post(p string, body any) request            { return request{method: "POST", path: p, body: body} }
func patch(p string, body any) request           { return request{method: "PATCH", path: p, body: body} }
func del(p string) request                       { return request{method: "DELETE", path: p} }
func (r request) h(hs map[string]string) request { r.headers = hs; return r }

var rev1 = map[string]string{"If-Match": `"1"`}

var matrixPolicies = map[string]policy{
	// Operations and sign-in.
	"getHealthz":    {own: everyone, build: func(*mctx) request { return get("/healthz") }},
	"getReadyz":     {own: everyone, build: func(*mctx) request { return get("/readyz") }},
	"getAuthConfig": {own: everyone, build: func(*mctx) request { return get("/v1/auth/config") }},
	"startLogin":    {anyStatus: true, build: func(*mctx) request { r := get("/auth/login"); r.anon = true; return r }},
	"completeLogin": {anyStatus: true, build: func(*mctx) request { r := get("/auth/callback?state=x"); r.anon = true; return r }},
	"devLogin": {anyStatus: true, build: func(*mctx) request {
		r := post("/auth/dev", map[string]string{"account": "casey"})
		r.anon = true
		return r
	}},
	"logout":      {own: signedIn, build: func(*mctx) request { r := post("/auth/logout", nil); r.ownSession = true; return r }},
	"getMe":       {own: signedIn, build: func(*mctx) request { return get("/v1/me") }},
	"listMyTeams": {own: signedIn, build: func(*mctx) request { return get("/v1/teams") }},

	// Sensitive-call approvals are session-only; human reviewer eligibility is
	// independent of a person's team role. Fresh bound receipts isolate writes.
	"listMyApprovals": {own: signedIn, build: func(*mctx) request { return get("/v1/me/approvals") }},
	"getApproval": {own: signedIn, build: func(c *mctx) request {
		r := approvalMatrixReceipt(c, "get")
		return get("/v1/approvals/" + r.ID.String())
	}},
	"decideApproval": {own: signedIn, build: func(c *mctx) request {
		r := approvalMatrixReceipt(c, "decision")
		return post("/v1/approvals/"+r.ID.String()+"/decision", map[string]any{"decision": "approve", "expectedArgsDigest": r.ArgsDigest, "expectedReviewRevision": r.ReviewRevision})
	}},
	"cancelApproval": {own: signedIn, build: func(c *mctx) request {
		r := approvalMatrixReceipt(c, "cancel")
		return post("/v1/approvals/"+r.ID.String()+"/cancel", map[string]any{"expectedReviewRevision": r.ReviewRevision})
	}},
	"renewApproval": {own: signedIn, build: func(c *mctx) request {
		r := approvalMatrixReceipt(c, "renew")
		return post("/v1/approvals/"+r.ID.String()+"/renew", map[string]any{"expectedReviewRevision": r.ReviewRevision})
	}},
	"listTeamApprovalRules": {scope: scopeTeam, own: admins, foreign: platform, build: func(c *mctx) request { return get(c.team("/approval-rules")) }},
	"createTeamApprovalRule": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		r := approvalMatrixRule(c, false, false)
		return post(c.team("/approval-rules"), r.RuleInput)
	}},
	"replaceTeamApprovalRule": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		r := approvalMatrixRule(c, false, true)
		return request{method: "PUT", path: c.team("/approval-rules/" + r.ID.String()), body: r.RuleInput, headers: rev1}
	}},
	"deleteTeamApprovalRule": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		r := approvalMatrixRule(c, false, true)
		return del(c.team("/approval-rules/" + r.ID.String())).h(rev1)
	}},
	"adminListApprovalRules": {own: platform, build: func(*mctx) request { return get("/v1/admin/approval-rules") }},
	"adminCreateApprovalRule": {own: padmin, build: func(c *mctx) request {
		r := approvalMatrixRule(c, true, false)
		return post("/v1/admin/approval-rules", r.RuleInput)
	}},
	"adminReplaceApprovalRule": {own: padmin, build: func(c *mctx) request {
		r := approvalMatrixRule(c, true, true)
		return request{method: "PUT", path: "/v1/admin/approval-rules/" + r.ID.String(), body: r.RuleInput, headers: rev1}
	}},
	"adminDeleteApprovalRule": {own: padmin, build: func(c *mctx) request {
		r := approvalMatrixRule(c, true, true)
		return del("/v1/admin/approval-rules/" + r.ID.String()).h(rev1)
	}},

	// Teams, members, invites and the team audit log.
	"getTeam":     {scope: scopeTeam, own: members, foreign: platform, build: func(c *mctx) request { return get(c.team("")) }},
	"listMembers": {scope: scopeTeam, own: members, foreign: platform, build: func(c *mctx) request { return get(c.team("/members")) }},
	"addMember": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return post(c.team("/members"), map[string]any{"email": fmt.Sprintf("added-%d@example.com", c.e.next()), "role": "member"})
	}},
	"updateMember": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return patch(c.team("/members/"+c.member()), map[string]any{"role": "editor"}).h(rev1)
	}},
	"removeMember": {scope: scopeTeam, own: admins, build: func(c *mctx) request { return del(c.team("/members/" + c.member())) }},
	"listInvites":  {scope: scopeTeam, own: admins, foreign: platform, build: func(c *mctx) request { return get(c.team("/invites")) }},
	"revokeInvite": {scope: scopeTeam, own: admins, foreign: padmin, build: func(c *mctx) request {
		return del(c.team("/invites/" + c.invite()))
	}},
	"listTeamAudit": {scope: scopeTeam, own: editors, foreign: platform, build: func(c *mctx) request { return get(c.team("/audit")) }},
	"getTeamAuditEntry": {scope: scopeTeam, own: editors, foreign: platform, build: func(c *mctx) request {
		return get(c.team("/audit/" + c.tf.auditID))
	}},

	// Platform administration.
	"adminListUsers": {own: platform, build: func(*mctx) request { return get("/v1/admin/users") }},
	"adminGetUser":   {own: platform, build: func(c *mctx) request { return get("/v1/admin/users/" + c.e.spareUser) }},
	"adminUpdateUser": {own: padmin, build: func(c *mctx) request {
		return patch("/v1/admin/users/"+c.user(), map[string]any{"platformRole": "platform_auditor"}).h(rev1)
	}},
	"adminListTeams": {own: platform, build: func(*mctx) request { return get("/v1/admin/teams") }},
	"adminCreateTeam": {own: padmin, build: func(c *mctx) request {
		n := c.e.next()
		return post("/v1/admin/teams", map[string]any{"slug": fmt.Sprintf("new-%d", n), "name": "New", "ownerEmail": fmt.Sprintf("o-%d@example.com", n)})
	}},
	"adminGetTeam": {own: platform, build: func(c *mctx) request { return get("/v1/admin/teams/" + c.e.b.slug) }},
	"adminUpdateTeam": {own: padmin, build: func(c *mctx) request {
		return patch("/v1/admin/teams/"+c.spareTeam(), map[string]any{"description": "updated by the matrix"}).h(rev1)
	}},
	"adminAssignOwner": {own: padmin, build: func(c *mctx) request {
		return post("/v1/admin/teams/"+c.spareTeam()+"/owners", map[string]any{"email": fmt.Sprintf("owner-%d@example.com", c.e.next())})
	}},
	"adminListAudit":     {own: platform, build: func(*mctx) request { return get("/v1/admin/audit") }},
	"adminGetAuditEntry": {own: platform, build: func(c *mctx) request { return get("/v1/admin/audit/" + c.e.b.auditID) }},

	// MCP servers (team B's policy is self_publish, so its owners and admins
	// approve changed capabilities). Allowed writes get fresh servers.
	"listTeamMcpServers": {scope: scopeTeam, own: members, foreign: platform, build: func(c *mctx) request { return get(c.team("/mcp-servers")) }},
	"createTeamMcpServer": {scope: scopeTeam, own: editors, build: func(c *mctx) request {
		return post(c.team("/mcp-servers"), map[string]any{"slug": fmt.Sprintf("new-srv-%d", c.e.next()), "name": "New", "url": c.e.fakeURL})
	}},
	"getTeamMcpServer": {scope: scopeTeam, own: members, foreign: platform, build: func(c *mctx) request {
		return get(c.team("/mcp-servers/" + c.tf.server))
	}},
	"updateTeamMcpServer": {scope: scopeTeam, own: editors, build: func(c *mctx) request {
		return patch(c.team("/mcp-servers/"+c.server("private")), map[string]any{"description": "updated by the matrix"}).h(rev1)
	}},
	"deleteTeamMcpServer": {scope: scopeTeam, own: admins, build: func(c *mctx) request { return del(c.team("/mcp-servers/" + c.server("private"))) }},
	"testTeamMcpServer": {scope: scopeTeam, own: editors, build: func(c *mctx) request {
		return post(c.team("/mcp-servers/"+c.server("private")+"/test"), nil)
	}},
	"refreshTeamMcpServer": {scope: scopeTeam, own: editors, build: func(c *mctx) request {
		return post(c.team("/mcp-servers/"+c.server("private")+"/refresh"), nil)
	}},
	"listTeamMcpCapabilities": {scope: scopeTeam, own: members, foreign: platform, build: func(c *mctx) request {
		return get(c.team("/mcp-servers/" + c.tf.server + "/capabilities"))
	}},
	"approveTeamMcpCapability": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		srv, capID := c.changedCapability()
		return request{method: "PUT", path: c.team("/mcp-servers/" + srv + "/capabilities/" + capID + "/approval"),
			body: map[string]any{"expectedFingerprint": c.e.fingerprint(capID)}}
	}},
	"listTeamMcpHealthChecks": {scope: scopeTeam, own: members, foreign: platform, build: func(c *mctx) request {
		return get(c.team("/mcp-servers/" + c.tf.server + "/health-checks"))
	}},
	"publishTeamMcpServer": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return post(c.team("/mcp-servers/"+c.server("private")+"/publish"), map[string]any{"note": "please"})
	}},
	"unpublishTeamMcpServer": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return post(c.team("/mcp-servers/"+c.server("published")+"/unpublish"), nil)
	}},
	// Upstream OAuth (Phase 7): editors detect and sign in for setup.
	"detectTeamMcpServerAuth": {scope: scopeTeam, own: editors, build: func(c *mctx) request {
		return post(c.team("/mcp-servers/detect-auth"), map[string]any{"url": c.e.fakeURL})
	}},
	"getTeamMcpServerIdentityDefault": {scope: scopeTeam, own: editors, build: func(c *mctx) request {
		return post(c.team("/mcp-servers/identity-default"), map[string]any{"url": c.e.fakeURL})
	}},
	"authorizeTeamMcpServerSetup": {scope: scopeTeam, own: editors, build: func(c *mctx) request {
		return post(c.team("/mcp-servers/"+c.tf.oauthServer+"/oauth/authorize-setup"), map[string]any{"returnTo": "/settings"})
	}},
	"getTeamPublishing": {scope: scopeTeam, own: members, foreign: platform, build: func(c *mctx) request { return get(c.team("/publishing")) }},

	// The catalog: anyone signed in.
	"listCatalogServers": {own: signedIn, build: func(*mctx) request { return get("/v1/catalog/servers") }},
	"getCatalogServer":   {own: signedIn, build: func(c *mctx) request { return get("/v1/catalog/servers/" + c.e.b.server) }},

	// Registry administration.
	"adminListMcpServers":      {own: platform, build: func(*mctx) request { return get("/v1/admin/mcp-servers?changes=true") }},
	"adminGetMcpServer":        {own: platform, build: func(c *mctx) request { return get("/v1/admin/mcp-servers/" + c.e.b.server) }},
	"adminListMcpCapabilities": {own: platform, build: func(c *mctx) request { return get("/v1/admin/mcp-servers/" + c.e.b.server + "/capabilities") }},
	"adminListMcpHealthChecks": {own: platform, build: func(c *mctx) request { return get("/v1/admin/mcp-servers/" + c.e.b.server + "/health-checks") }},
	"adminReviewMcpServer": {own: padmin, build: func(c *mctx) request {
		srv := c.server("pending")
		return post("/v1/admin/mcp-servers/"+srv+"/review", map[string]any{"decision": "approve", "note": "ok", "expectedDigest": c.e.digest(srv)})
	}},
	"adminApproveMcpCapability": {own: padmin, build: func(c *mctx) request {
		srv, capID := c.changedCapability()
		return request{method: "PUT", path: "/v1/admin/mcp-servers/" + srv + "/capabilities/" + capID + "/approval",
			body: map[string]any{"expectedFingerprint": c.e.fingerprint(capID)}}
	}},
	"adminGetPublishingSettings": {own: platform, build: func(*mctx) request { return get("/v1/admin/settings/publishing") }},
	"adminUpdatePublishingSettings": {own: padmin, build: func(c *mctx) request {
		rev := c.e.exec(`SELECT revision::text FROM platform_settings`)
		return request{method: "PUT", path: "/v1/admin/settings/publishing", body: map[string]any{"defaultPolicy": "approval_required"},
			headers: map[string]string{"If-Match": `"` + rev + `"`}}
	}},
	"adminGetNetworkSettings": {own: platform, build: func(*mctx) request { return get("/v1/admin/settings/network") }},
	"adminUpdateNetworkSettings": {own: padmin, build: func(c *mctx) request {
		rev := c.e.exec(`SELECT revision::text FROM network_settings`)
		return request{method: "PUT", path: "/v1/admin/settings/network",
			body:    map[string]any{"entries": []any{map[string]any{"kind": "cidr", "value": "10.20.0.0/16", "allowHttp": false}}},
			headers: map[string]string{"If-Match": `"` + rev + `"`}}
	}},
	// A literal address: the check never needs DNS here.
	"adminCheckNetworkUrl": {own: platform, build: func(*mctx) request {
		return post("/v1/admin/settings/network/check", map[string]any{"url": "https://10.20.0.5/mcp"})
	}},
	"adminGetTeamPublishing": {own: platform, build: func(c *mctx) request { return get("/v1/admin/teams/" + c.e.b.slug + "/publishing") }},
	"adminUpdateTeamPublishing": {own: padmin, build: func(c *mctx) request {
		return request{method: "PUT", path: "/v1/admin/teams/" + c.spareTeam() + "/publishing", body: map[string]any{"override": "self_publish"},
			headers: rev1}
	}},

	// Team gateways (owners and admins write; members and platform staff
	// read). Allowed writes get fresh gateways.
	"listTeamGateways": {scope: scopeTeam, own: members, foreign: platform, build: func(c *mctx) request { return get(c.team("/gateways")) }},
	"createTeamGateway": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return post(c.team("/gateways"), map[string]any{"slug": fmt.Sprintf("new-gw-%d", c.e.next()), "name": "New"})
	}},
	"getTeamGateway": {scope: scopeTeam, own: members, foreign: platform, build: func(c *mctx) request {
		return get(c.team("/gateways/" + c.tf.gateway))
	}},
	"updateTeamGateway": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return patch(c.team("/gateways/"+c.gateway()), map[string]any{"description": "updated by the matrix"}).h(rev1)
	}},
	"deleteTeamGateway": {scope: scopeTeam, own: admins, build: func(c *mctx) request { return del(c.team("/gateways/" + c.gateway())) }},
	"listTeamGatewayCapabilities": {scope: scopeTeam, own: members, foreign: platform, build: func(c *mctx) request {
		return get(c.team("/gateways/" + c.tf.gateway + "/capabilities"))
	}},
	"setTeamGatewayCapabilities": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return request{method: "PUT", path: c.team("/gateways/" + c.gateway() + "/capabilities"), body: map[string]any{"items": []any{}}, headers: rev1}
	}},
	"listTeamGatewayOptions": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return get(c.team("/gateway-options?kind=resource&limit=5&server=" + c.tf.server))
	}},
	"listTeamCalls": {scope: scopeTeam, own: admins, foreign: platform, build: func(c *mctx) request { return get(c.team("/calls")) }},

	// Gateway administration.
	"adminListGateways": {own: platform, build: func(*mctx) request { return get("/v1/admin/gateways?ownerKind=platform") }},
	"adminCreateGateway": {own: padmin, build: func(c *mctx) request {
		return post("/v1/admin/gateways", map[string]any{"slug": fmt.Sprintf("platform-gw-%d", c.e.next()), "name": "Platform"})
	}},
	"adminGetGateway": {own: platform, build: func(c *mctx) request { return get("/v1/admin/gateways/" + c.e.platformGateway) }},
	"adminUpdateGateway": {own: padmin, build: func(c *mctx) request {
		return patch("/v1/admin/gateways/"+c.platformGateway(), map[string]any{"description": "updated by the matrix"}).h(rev1)
	}},
	"adminDeleteGateway": {own: padmin, build: func(c *mctx) request { return del("/v1/admin/gateways/" + c.platformGateway()) }},
	"adminListGatewayCapabilities": {own: platform, build: func(c *mctx) request {
		return get("/v1/admin/gateways/" + c.e.platformGateway + "/capabilities")
	}},
	"adminSetGatewayCapabilities": {own: padmin, build: func(c *mctx) request {
		return request{method: "PUT", path: "/v1/admin/gateways/" + c.platformGateway() + "/capabilities", body: map[string]any{"items": []any{}}, headers: rev1}
	}},
	"adminListGatewayOptions": {own: platform, build: func(*mctx) request { return get("/v1/admin/gateway-options?limit=500") }},
	"adminListGatewayGrants": {own: platform, build: func(c *mctx) request {
		return get("/v1/admin/gateways/" + c.e.platformGateway + "/grants")
	}},
	"adminAddGatewayGrant": {own: padmin, build: func(c *mctx) request {
		return post("/v1/admin/gateways/"+c.platformGateway()+"/grants", map[string]any{"subjectKind": "group", "group": "matrix-group"})
	}},
	"adminRemoveGatewayGrant": {own: padmin, build: func(c *mctx) request {
		gw, grant := c.grant()
		return del("/v1/admin/gateways/" + gw + "/grants/" + grant)
	}},
	"adminListCalls": {own: platform, build: func(*mctx) request { return get("/v1/admin/calls") }},

	// The caller's gateways (the fixture platform gateway is granted to
	// every matrix caller) and API keys.
	"listMyGateways": {own: signedIn, build: func(*mctx) request { return get("/v1/me/gateways") }},
	"getMyGateway":   {own: signedIn, build: func(c *mctx) request { return get("/v1/me/gateways/" + c.e.platformGateway) }},
	"listMyApiKeys":  {own: signedIn, build: func(*mctx) request { return get("/v1/me/api-keys") }},
	// Keys limited to the fixture platform gateway, which every signed-in
	// matrix caller may use.
	"createMyApiKey": {own: signedIn, build: func(c *mctx) request {
		return post("/v1/me/api-keys", map[string]any{"name": "matrix key", "gatewayIds": []string{c.e.platformGateway}})
	}},
	"revokeMyApiKey": {own: signedIn, build: func(c *mctx) request { return del("/v1/me/api-keys/" + c.apiKey()) }},

	// OAuth: the consent page (an authorization request of a registered
	// client for the fixture platform gateway, which every signed-in matrix
	// caller may use), connected apps and trusted clients.
	"getOAuthConsent": {own: signedIn, build: func(c *mctx) request { return get("/v1/oauth/consent?" + c.e.consentQuery()) }},
	"decideOAuthConsent": {own: signedIn, build: func(c *mctx) request {
		return post("/v1/oauth/consent", map[string]any{"query": c.e.consentQuery(), "decision": "allow"})
	}},
	"listMySessions": {own: signedIn, build: func(*mctx) request { return get("/v1/me/sessions") }},
	"revokeMySession": {own: signedIn, build: func(c *mctx) request {
		user := c.e.userIDs[c.who]
		if user == "" {
			user = c.e.spareUser
		}
		id := c.e.exec(`INSERT INTO sessions (user_id, token_digest, csrf_token, expires_at) VALUES ($1, $2, 'csrf', now() + interval '1 hour') RETURNING id::text`, user, fmt.Sprintf("matrix-session-%d", c.e.next()))
		return del("/v1/me/sessions/" + id)
	}},
	"signOutEverywhere":       {own: signedIn, build: func(*mctx) request { return post("/v1/me/sessions/revoke-all", map[string]any{"keepCurrent": true}) }},
	"adminListUserSessions":   {own: padmin, build: func(c *mctx) request { return get("/v1/admin/users/" + c.e.spareUser + "/sessions") }},
	"adminRevokeUserSessions": {own: padmin, build: func(c *mctx) request { return del("/v1/admin/users/" + c.e.spareUser + "/sessions") }},
	"listMyOAuthGrants":       {own: signedIn, build: func(*mctx) request { return get("/v1/me/oauth-grants") }},
	"revokeMyOAuthGrant":      {own: signedIn, build: func(c *mctx) request { return del("/v1/me/oauth-grants/" + c.oauthGrant(true)) }},
	"adminListUserOAuthGrants": {own: platform, build: func(c *mctx) request {
		return get("/v1/admin/users/" + c.e.spareUser + "/oauth-grants")
	}},
	"adminRevokeUserOAuthGrant": {own: padmin, build: func(c *mctx) request {
		return del("/v1/admin/users/" + c.e.spareUser + "/oauth-grants/" + c.oauthGrant(false))
	}},
	"adminGetTrustedClients": {own: platform, build: func(*mctx) request { return get("/v1/admin/settings/oauth-clients") }},
	"adminUpdateTrustedClients": {own: padmin, build: func(c *mctx) request {
		rev := c.e.exec(`SELECT revision::text FROM oauth_settings`)
		return request{method: "PUT", path: "/v1/admin/settings/oauth-clients",
			body:    map[string]any{"clients": []any{map[string]any{"clientId": "https://claude.ai/oauth/claude-code-client-metadata", "label": "Claude Code"}}},
			headers: map[string]string{"If-Match": `"` + rev + `"`}}
	}},

	// Service accounts (owners and admins manage them and their keys;
	// members and platform staff see them and the gateways they can use;
	// platform staff see keys and every team's accounts).
	"listServiceAccounts": {scope: scopeTeam, own: members, foreign: platform, build: func(c *mctx) request { return get(c.team("/service-accounts")) }},
	"createServiceAccount": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return post(c.team("/service-accounts"), map[string]any{"name": fmt.Sprintf("bot-%d", c.e.next()), "role": "editor"})
	}},
	"getServiceAccount": {scope: scopeTeam, own: members, foreign: platform, build: func(c *mctx) request {
		return get(c.team("/service-accounts/" + c.tf.serviceAccount))
	}},
	"updateServiceAccount": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return patch(c.team("/service-accounts/"+c.serviceAccount()), map[string]any{"description": "updated by the matrix"}).h(rev1)
	}},
	"deleteServiceAccount": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return del(c.team("/service-accounts/" + c.serviceAccount()))
	}},
	"listServiceAccountGateways": {scope: scopeTeam, own: members, foreign: platform, build: func(c *mctx) request {
		return get(c.team("/service-accounts/" + c.tf.serviceAccount + "/gateways"))
	}},
	"adminListServiceAccounts": {own: platform, build: func(*mctx) request { return get("/v1/admin/service-accounts?q=sa-&limit=5") }},
	"listServiceAccountKeys": {scope: scopeTeam, own: admins, foreign: platform, build: func(c *mctx) request {
		return get(c.team("/service-accounts/" + c.tf.serviceAccount + "/keys"))
	}},
	"createServiceAccountKey": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return post(c.team("/service-accounts/"+c.serviceAccount()+"/keys"), map[string]any{"name": "matrix key", "expiresInDays": 30})
	}},
	"revokeServiceAccountKey": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		sa, key := c.serviceAccountKey()
		return del(c.team("/service-accounts/" + sa + "/keys/" + key))
	}},

	// Delegated credentials: auth providers (platform admins write,
	// auditors read, anyone signed in picks one), connections (people
	// their own; platform staff read anyone's, admins revoke), consent
	// links (only their person) and requirement overrides (team editors).
	"listAuthProviders":      {own: signedIn, build: func(*mctx) request { return get("/v1/auth-providers") }},
	"adminListAuthProviders": {own: platform, build: func(*mctx) request { return get("/v1/admin/auth-providers") }},
	"adminCreateAuthProvider": {own: padmin, build: func(c *mctx) request {
		return post("/v1/admin/auth-providers", map[string]any{"slug": fmt.Sprintf("new-prov-%d", c.e.next()), "name": "New",
			"clientId": "client", "clientSecret": "secret-value-1234", "authorizationUrl": "https://auth.example.com/authorize",
			"tokenUrl": "https://auth.example.com/token", "defaultScopes": []string{"read"}})
	}},
	"adminGetAuthProvider": {own: platform, build: func(c *mctx) request { return get("/v1/admin/auth-providers/" + c.e.provider) }},
	"adminUpdateAuthProvider": {own: padmin, build: func(c *mctx) request {
		return patch("/v1/admin/auth-providers/"+c.authProvider(), map[string]any{"name": "Renamed"}).h(rev1)
	}},
	"adminGetAuthProviderAccess": {own: platform, build: func(c *mctx) request {
		return get("/v1/admin/auth-providers/" + c.e.provider + "/access")
	}},
	"adminSetAuthProviderAccess": {own: padmin, build: func(c *mctx) request {
		return put("/v1/admin/auth-providers/"+c.authProvider()+"/access",
			map[string]any{"accessMode": "open", "teamIds": []string{}, "serverIds": []string{}}).h(rev1)
	}},
	"adminDeleteAuthProvider":      {own: padmin, build: func(c *mctx) request { return del("/v1/admin/auth-providers/" + c.authProvider()) }},
	"adminListAuthProviderPresets": {own: platform, build: func(*mctx) request { return get("/v1/admin/auth-provider-presets") }},
	"adminListUserConnections": {own: platform, build: func(c *mctx) request {
		return get("/v1/admin/users/" + c.e.spareUser + "/connections")
	}},
	"adminRevokeUserConnection": {own: padmin, build: func(c *mctx) request {
		return del("/v1/admin/users/" + c.e.spareUser + "/connections/" + c.connection(false))
	}},
	"listMyConnections": {own: signedIn, build: func(*mctx) request { return get("/v1/me/connections") }},
	"startMyConnection": {own: signedIn, build: func(c *mctx) request {
		return post("/v1/me/connections/start", map[string]any{"providerId": c.e.provider, "returnTo": "/settings/connections"})
	}},
	"revokeMyConnection": {own: signedIn, build: func(c *mctx) request { return del("/v1/me/connections/" + c.connection(true)) }},
	"listAllowableServers": {own: signedIn, build: func(c *mctx) request {
		return get("/v1/me/connections/" + c.allowTarget(false) + "/allowable-servers")
	}},
	"allowConnectionServer": {own: signedIn, build: func(c *mctx) request {
		return post("/v1/me/connections/"+c.allowTarget(false)+"/allow-server",
			map[string]any{"serverId": c.e.allowableServer, "origin": registry.OriginOf(c.e.fakeURL), "scopes": []string{"repo"}})
	}},
	"revokeAllowedServer": {own: signedIn, build: func(c *mctx) request {
		return del("/v1/me/connections/" + c.allowTarget(true) + "/allowed-servers/" + c.e.allowableServer)
	}},
	"getConnectRequest": {own: signedIn, build: func(c *mctx) request { return get("/v1/connect/requests/" + c.connectRequest()) }},
	"confirmConnectRequest": {own: signedIn, build: func(c *mctx) request {
		return post("/v1/connect/requests/"+c.confirmableRequest()+"/confirm", nil)
	}},
	// Operations (Phase 6): rate limits and retention (platform admins
	// write; members read their team's; platform staff read any), call
	// detail (as the call list), payloads (owners and admins of the team
	// whose switch captured it; platform staff only through the admin route)
	// and usage (owners, admins and editors; platform staff).
	"getTeamLimits":    {scope: scopeTeam, own: members, foreign: platform, build: func(c *mctx) request { return get(c.team("/limits")) }},
	"getTeamRetention": {scope: scopeTeam, own: members, foreign: platform, build: func(c *mctx) request { return get(c.team("/retention")) }},
	"getTeamCall":      {scope: scopeTeam, own: admins, foreign: platform, build: func(c *mctx) request { return get(c.team("/calls/" + c.tf.call)) }},
	"getTeamCallPayload": {scope: scopeTeam, own: admins, build: func(c *mctx) request {
		return get(c.team("/calls/" + c.tf.call + "/payload"))
	}},
	"getTeamUsage": {scope: scopeTeam, own: editors, foreign: platform, build: func(c *mctx) request {
		return get(c.team("/usage?groupBy=gateway&series=true"))
	}},
	"adminGetLimitSettings": {own: platform, build: func(*mctx) request { return get("/v1/admin/settings/limits") }},
	"adminUpdateLimitSettings": {own: padmin, build: func(c *mctx) request {
		rev := c.e.exec(`SELECT revision::text FROM limit_settings`)
		return request{method: "PUT", path: "/v1/admin/settings/limits",
			body:    map[string]any{"items": []any{map[string]any{"key": "person_per_minute", "default": 100000, "ceiling": nil}}},
			headers: map[string]string{"If-Match": `"` + rev + `"`}}
	}},
	"adminGetTeamLimits": {own: platform, build: func(c *mctx) request { return get("/v1/admin/teams/" + c.e.b.slug + "/limits") }},
	"adminUpdateTeamLimits": {own: padmin, build: func(c *mctx) request {
		return request{method: "PUT", path: "/v1/admin/teams/" + c.spareTeam() + "/limits",
			body: map[string]any{"items": []any{map[string]any{"key": "gateway_per_minute", "value": 5000}}}, headers: rev1}
	}},
	"adminGetCaptureSettings": {own: platform, build: func(*mctx) request { return get("/v1/admin/settings/capture") }},
	"adminUpdateCaptureSettings": {own: padmin, build: func(c *mctx) request {
		rev := c.e.exec(`SELECT revision::text FROM capture_settings`)
		return request{method: "PUT", path: "/v1/admin/settings/capture",
			body:    map[string]any{"patterns": []any{map[string]any{"pattern": "EMP-[0-9]{6}", "note": "employee IDs"}}},
			headers: map[string]string{"If-Match": `"` + rev + `"`}}
	}},
	"adminTestRedaction": {own: platform, build: func(*mctx) request {
		return post("/v1/admin/settings/capture/test", map[string]any{"sample": `{"password":"x","note":"EMP-123456"}`})
	}},
	"adminGetRetentionSettings": {own: platform, build: func(*mctx) request { return get("/v1/admin/settings/retention") }},
	"adminUpdateRetentionSettings": {own: padmin, build: func(c *mctx) request {
		rev := c.e.exec(`SELECT revision::text FROM retention_settings`)
		return request{method: "PUT", path: "/v1/admin/settings/retention",
			body: map[string]any{"periods": []any{map[string]any{"kind": "call_metadata", "days": 120}}}, headers: map[string]string{"If-Match": `"` + rev + `"`}}
	}},
	"adminGetTeamRetention": {own: platform, build: func(c *mctx) request { return get("/v1/admin/teams/" + c.e.b.slug + "/retention") }},
	"adminUpdateTeamRetention": {own: padmin, build: func(c *mctx) request {
		return request{method: "PUT", path: "/v1/admin/teams/" + c.spareTeam() + "/retention",
			body: map[string]any{"periods": []any{map[string]any{"kind": "captured_payloads", "days": 7}}}, headers: rev1}
	}},
	"adminGetCall":        {own: platform, build: func(c *mctx) request { return get("/v1/admin/calls/" + c.e.b.call) }},
	"adminGetCallPayload": {own: platform, build: func(c *mctx) request { return get("/v1/admin/calls/" + c.e.b.call + "/payload") }},
	"adminGetUsage":       {own: platform, build: func(*mctx) request { return get("/v1/admin/usage?groupBy=team") }},

	"setTeamMcpCapabilityRequirement": {scope: scopeTeam, own: editors, build: func(c *mctx) request {
		srv, capID := c.serverCapability()
		return request{method: "PUT", path: c.team("/mcp-servers/" + srv + "/capabilities/" + capID + "/requirement"),
			body: map[string]any{"mode": "none"}, headers: rev1}
	}},
}
