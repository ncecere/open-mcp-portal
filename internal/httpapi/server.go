// Package httpapi assembles the HTTP surface: the route table, middleware,
// operational endpoints and the /v1 handlers.
//
// Every route is declared in a table (apiRoutes, grouped by area) so tests
// can verify that the served surface matches api/openapi.yaml exactly.
package httpapi

import (
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apikeys"
	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/automation"
	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/capture"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/identity"
	"github.com/ncecere/open-mcp-portal/internal/limits"
	"github.com/ncecere/open-mcp-portal/internal/notify"
	"github.com/ncecere/open-mcp-portal/internal/oauth"
	"github.com/ncecere/open-mcp-portal/internal/overview"
	"github.com/ncecere/open-mcp-portal/internal/personsecrets"
	"github.com/ncecere/open-mcp-portal/internal/platform"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/retention"
	"github.com/ncecere/open-mcp-portal/internal/serviceaccounts"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
	"github.com/ncecere/open-mcp-portal/internal/usage"
)

// Deps are the dependencies shared by handlers.
type Deps struct {
	Config   config.Config
	Pool     *pgxpool.Pool
	Auth     *auth.Service
	Teams    *teams.Service
	Platform *platform.Service
	Registry *registry.Service
	Gateways *gateways.Service
	APIKeys  *apikeys.Service
	Identity *identity.Service
	Calls    *calls.Service
	// OAuth is the authorization server for MCP clients (internal/oauth).
	OAuth *oauth.Service
	// ServiceAccounts manages team service accounts and their keys.
	ServiceAccounts *serviceaccounts.Service
	// Approvals governs sensitive-call review through session-only routes.
	Approvals ApprovalService
	// Providers is delegated credentials: auth providers, connections and
	// consent links (internal/providers).
	Providers *providers.Service
	// PersonSecrets is per-person secrets for servers in person_secret mode
	// (internal/personsecrets).
	PersonSecrets *personsecrets.Service
	// Automation manages and authenticates automation tokens
	// (docs/automation-tokens.md); Notify is the notification service
	// (docs/notifications.md); Overview computes the admin overview and team
	// attention (docs/admin-overview.md).
	Automation *automation.Service
	Notify     *notify.Service
	Overview   *overview.Service
	// MCP serves /mcp/{slug} (internal/mcpgw).
	MCP http.Handler
	// Limits, Capture, Retention and Usage are Phase 6's operations
	// (docs/phase6-operations.md).
	Limits    *limits.Service
	Capture   *capture.Service
	Retention *retention.Service
	Usage     *usage.Service
	// RateStore counts the OAuth endpoints', connect start's and other
	// per-minute limits (nil: in memory, for tests).
	RateStore ratelimit.Store

	// Web is the built single-page app; WebBuilt is false when only the
	// placeholder is embedded.
	Web      fs.FS
	WebBuilt bool
	Health   *Health
	Log      *slog.Logger
}

type api struct {
	Deps
	q *dbgen.Queries
	// limiter counts the OAuth endpoints' requests per address and connect
	// starts per person (Deps.RateStore).
	limiter ratelimit.Store
}

// route is one entry in the served surface.
type route struct {
	Method  string
	Path    string
	Handler http.Handler
}

func (r route) pattern() string {
	if r.Method == "" {
		return r.Path
	}
	return r.Method + " " + r.Path
}

func opsRoutes(d Deps) []route {
	return []route{
		{"GET", "/healthz", http.HandlerFunc(d.Health.Live)},
		{"GET", "/readyz", http.HandlerFunc(d.Health.Ready)},
	}
}

// apiRoutes is the full served surface, grouped by area.
func apiRoutes(d Deps) []route {
	a := &api{Deps: d, limiter: d.RateStore}
	if a.limiter == nil {
		a.limiter = ratelimit.New()
	}
	if d.Pool != nil {
		a.q = dbgen.New(d.Pool)
	}
	routes := opsRoutes(d)
	for _, group := range [][]route{a.authRoutes(), a.teamRoutes(), a.platformAdminRoutes(), a.mcpServerRoutes(), a.mcpAdminRoutes(),
		a.gatewayRoutes(), a.gatewayAdminRoutes(), a.meGatewayRoutes(), a.mcpRoutes(), a.oauthRoutes(), a.oauthRESTRoutes(),
		a.serviceAccountRoutes(), a.serviceAccountAdminRoutes(), a.serviceConnectionRoutes(), a.providerRoutes(), a.operationsRoutes(), a.operationsAdminRoutes(),
		a.upstreamOAuthRoutes(), a.v02Routes(), a.classificationRoutes(), a.personSecretRoutes(), a.sessionRoutes(), a.approvalRoutes(), a.accessRequestRoutes()} {
		routes = append(routes, group...)
	}
	return routes
}

// admin requires a session, then a platform admin or auditor. Write
// operations additionally require platform_admin inside the service.
func (a *api) admin(h http.HandlerFunc) http.Handler { return a.session(a.requirePlatformRead(h)) }

// authRoutes: sign-in and the caller's own identity.
func (a *api) authRoutes() []route {
	return []route{
		{"GET", "/auth/login", http.HandlerFunc(a.Auth.Login)},
		{"GET", "/auth/callback", http.HandlerFunc(a.Auth.Callback)},
		{"POST", "/auth/dev", http.HandlerFunc(a.Auth.DevLogin)},
		{"POST", "/auth/logout", a.session(a.Auth.Logout)},
		{"GET", "/v1/auth/config", http.HandlerFunc(a.Auth.AuthConfig)},
		{"GET", "/v1/me", a.meRoute()},
	}
}

// teamRoutes: teams, members, invites and the team audit log.
func (a *api) teamRoutes() []route {
	return []route{
		{"GET", "/v1/teams", a.session(a.listMyTeams)},
		{"GET", "/v1/teams/{team}", a.session(a.getTeam)},
		{"GET", "/v1/teams/{team}/members", a.session(a.listMembers)},
		{"POST", "/v1/teams/{team}/members", a.session(a.addMember)},
		{"PATCH", "/v1/teams/{team}/members/{userId}", a.session(a.updateMember)},
		{"DELETE", "/v1/teams/{team}/members/{userId}", a.session(a.removeMember)},
		{"GET", "/v1/teams/{team}/invites", a.session(a.listInvites)},
		{"DELETE", "/v1/teams/{team}/invites/{inviteId}", a.session(a.revokeInvite)},
		{"GET", "/v1/teams/{team}/audit", a.session(a.listTeamAudit)},
		{"GET", "/v1/teams/{team}/audit/{entryId}", a.session(a.getTeamAuditEntry)},
	}
}

// platformAdminRoutes: users, teams and the audit log across the platform.
func (a *api) platformAdminRoutes() []route {
	return []route{
		{"GET", "/v1/admin/users", a.admin(a.adminListUsers)},
		{"GET", "/v1/admin/users/{userId}", a.admin(a.adminGetUser)},
		{"PATCH", "/v1/admin/users/{userId}", a.admin(a.adminUpdateUser)},
		{"GET", "/v1/admin/teams", a.admin(a.adminListTeams)},
		{"POST", "/v1/admin/teams", a.admin(a.adminCreateTeam)},
		{"GET", "/v1/admin/teams/{team}", a.admin(a.adminGetTeam)},
		{"PATCH", "/v1/admin/teams/{team}", a.admin(a.adminUpdateTeam)},
		{"POST", "/v1/admin/teams/{team}/owners", a.admin(a.adminAssignOwner)},
		{"GET", "/v1/admin/audit", a.admin(a.adminListAudit)},
		{"GET", "/v1/admin/audit/{entryId}", a.admin(a.adminGetAuditEntry)},
	}
}

func build(d Deps, routes []route, fallback http.Handler) http.Handler {
	mux := http.NewServeMux()
	for _, rt := range routes {
		mux.Handle(rt.pattern(), rt.Handler)
	}
	mux.Handle("/", fallback)
	return chain(mux, d)
}

var notFound = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	httpx.Error(w, http.StatusNotFound, "not_found", "Not found")
})

// spaOptions personalise the app's index.html and its CSP.
func (d Deps) spaOptions() spaOptions {
	in := d.Config.Instance
	return spaOptions{Title: in.Name, Theme: in.Theme, LogoOrigin: in.LogoOrigin()}
}

// NewAPIHandler serves the full application surface and the web app.
func NewAPIHandler(d Deps) http.Handler {
	var fallback http.Handler = notFound
	if d.Web != nil {
		fallback = spaHandler(d.Web, d.WebBuilt, d.spaOptions())
	}
	return build(d, apiRoutes(d), fallback)
}
