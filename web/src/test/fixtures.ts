/* API fixtures for the page tests, typed from the generated contract (schema.gen.ts), so they break when it changes. */
import type { Schemas } from "../api/client";

type PlatformRole = Schemas["PlatformRole"];
type TeamRole = Schemas["TeamRole"];

export const instance: Schemas["InstanceInfo"] = { name: "Open MCP Portal", orgName: "", theme: "neutral", logoUrl: null, supportUrl: null };

export const authConfig = (extra: Partial<Schemas["AuthConfig"]> = {}): Schemas["AuthConfig"] => ({
  instance,
  oidcEnabled: false,
  devAuthEnabled: true,
  loginUrl: "/auth/login",
  teamRequestUrl: null,
  devAccounts: [
    { id: "admin", name: "Ada Admin", email: "admin@example.com", platformRole: "platform_admin" },
    { id: "auditor", name: "Avery Auditor", email: "auditor@example.com", platformRole: "platform_auditor" },
    { id: "alex", name: "Alex Owner", email: "alex@example.com", platformRole: "none" },
  ],
  ...extra,
});

export const team: Schemas["Team"] = {
  id: "11111111-1111-4111-8111-111111111111",
  slug: "platform-tools",
  name: "Platform Tools",
  description: "Internal MCP servers for developer tooling.",
  status: "active",
  revision: 3,
  createdAt: "2026-09-01T10:00:00Z",
  updatedAt: "2026-09-01T10:00:00Z",
  archivedAt: null,
};

export const myTeam = (role: TeamRole = "owner", extra: Partial<Schemas["MyTeam"]> = {}): Schemas["MyTeam"] => ({
  id: team.id,
  slug: team.slug,
  name: team.name,
  status: "active",
  role,
  ...extra,
});

export const user = (extra: Partial<Schemas["User"]> = {}): Schemas["User"] => ({
  id: "22222222-2222-4222-8222-222222222222",
  email: "una@example.com",
  displayName: "Una User",
  platformRole: "none",
  status: "active",
  revision: 1,
  createdAt: "2026-09-01T09:00:00Z",
  lastLoginAt: "2026-10-15T09:00:00Z",
  ...extra,
});

/** The signed-in user: a platform role and their teams (one team with `teamRole`, or none with null). */
export const meFor = (platformRole: PlatformRole = "none", teamRole: TeamRole | null = "owner"): Schemas["Me"] => ({
  user: user({ platformRole }),
  teams: teamRole ? [myTeam(teamRole)] : [],
  groups: ["everyone", "engineering"],
  csrfToken: "csrf-123",
  capabilities: { platformAdmin: platformRole === "platform_admin", platformAuditor: platformRole === "platform_auditor" },
});

export const member = (role: TeamRole, extra: Partial<Schemas["MemberUser"]> = {}, revision = 1): Schemas["Member"] => ({
  user: { id: user().id, email: user().email, displayName: user().displayName, status: "active", ...extra },
  role,
  revision,
  createdAt: "2026-09-02T10:00:00Z",
});

export const members: Schemas["Member"][] = [
  member("owner"),
  member("admin", { id: "33333333-3333-4333-8333-333333333333", email: "blair@example.com", displayName: "Blair Admin" }),
  member("editor", { id: "44444444-4444-4444-8444-444444444444", email: "casey@example.com", displayName: "Casey Editor" }),
  member("member", { id: "55555555-5555-4555-8555-555555555555", email: "drew@example.com", displayName: "Drew Member" }),
];

export const invite = (extra: Partial<Schemas["Invite"]> = {}): Schemas["Invite"] => ({
  id: "66666666-6666-4666-8666-666666666666",
  email: "new.person@example.com",
  role: "editor",
  invitedBy: user().id,
  createdAt: "2026-10-10T10:00:00Z",
  expiresAt: "2026-11-09T10:00:00Z",
  ...extra,
});

export const teamSummary = (extra: Partial<Schemas["TeamSummary"]> = {}): Schemas["TeamSummary"] => ({
  team,
  memberCount: 4,
  ownerCount: 1,
  ownerInvites: 0,
  ...extra,
});

export const auditEntry = (extra: Partial<Schemas["AuditEntry"]> = {}): Schemas["AuditEntry"] => ({
  id: 101,
  occurredAt: "2026-10-15T12:00:00Z",
  actorKind: "user",
  actorUserId: user().id,
  teamId: team.id,
  teamName: team.name,
  teamSlug: team.slug,
  action: "team.member_role_change",
  actor: { kind: "user", userId: user().id, displayName: "Una User", email: "una@example.com" },
  targetType: "user",
  targetId: "44444444-4444-4444-8444-444444444444",
  targetLabel: "Casey Editor",
  targetExists: true,
  before: { role: "member" },
  after: { role: "editor" },
  metadata: {},
  requestId: "req-1",
  via: { kind: "session" },
  clientIp: null,
  ...extra,
});

export const page = <T>(items: T[], nextCursor: string | null = null) => ({ items, nextCursor });

/* ---------------- the registry (MCP servers, capabilities, catalog) ---------------- */

export const serverId = "99999999-9999-4999-8999-999999999999";

export const counts = (extra: Partial<Schemas["CapabilityCounts"]> = {}): Schemas["CapabilityCounts"] => ({ tools: 2, resources: 1, resourceTemplates: 0, prompts: 1, ...extra });

export const mcpServer = (extra: Partial<Schemas["McpServer"]> = {}): Schemas["McpServer"] => ({
  id: serverId,
  teamId: team.id,
  teamSlug: team.slug,
  teamName: team.name,
  slug: "service-status",
  name: "Service status",
  description: "Read the status of internal services.",
  url: "https://status.example.com/mcp",
  transport: "streamable_http",
  authHeaderName: "Authorization",
  hasAuth: true,
  authValueHint: "x9Kz",
  credentials: [{ kind: "header", name: "Authorization", hint: "x9Kz" }],
  timeoutSeconds: 30,
  enabled: true,
  publishState: "private",
  effectivePublishPolicy: "approval_required",
  publishRequestedAt: null,
  publishRequestNote: null,
  publishReviewedAt: null,
  publishReviewedByName: null,
  publishReviewNote: null,
  counts: counts(),
  pendingChanges: 0,
  health: { status: "healthy", checkedAt: "2026-10-16T07:55:00Z", statusSince: "2026-10-15T08:00:00Z", latencyMs: 42 },
  refreshedAt: "2026-10-16T07:00:00Z",
  lastRefreshError: null,
  reviewDigest: "d".repeat(64),
  revision: 4,
  createdAt: "2026-10-01T10:00:00Z",
  updatedAt: "2026-10-16T07:00:00Z",
  ...extra,
});

export const capability = (extra: Partial<Schemas["McpCapability"]> = {}): Schemas["McpCapability"] => ({
  id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  serverId,
  kind: "tool",
  name: "get_status",
  title: "Get status",
  description: "Returns the status of a service.",
  definition: { name: "get_status", inputSchema: { type: "object", properties: { service: { type: "string" } } }, annotations: { readOnlyHint: true } },
  fingerprint: "a".repeat(64),
  approved: false,
  changed: false,
  approvedAt: null,
  approvedByName: null,
  firstSeenAt: "2026-10-01T10:00:00Z",
  lastSeenAt: "2026-10-16T07:00:00Z",
  goneAt: null,
  requirementOverride: { mode: "inherit" },
  requires: null,
  ...extra,
});

export const capabilities: Schemas["McpCapability"][] = [
  capability(),
  capability({ id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", name: "restart", title: "", description: "Restarts a service.", definition: { name: "restart", annotations: { destructiveHint: true } } }),
  capability({ id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", kind: "resource", name: "status://all", title: "All services", description: "Every service's status.", definition: { uri: "status://all", mimeType: "application/json" } }),
  capability({ id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd", kind: "prompt", name: "incident_summary", title: "Incident summary", description: "Summarise an incident.", definition: { name: "incident_summary" } }),
];

export const healthCheck = (extra: Partial<Schemas["McpHealthCheck"]> = {}): Schemas["McpHealthCheck"] => ({
  checkedAt: "2026-10-16T07:55:00Z",
  ok: true,
  latencyMs: 42,
  trigger: "scheduled",
  ...extra,
});

export const teamPublishing = (extra: Partial<Schemas["TeamPublishing"]> = {}): Schemas["TeamPublishing"] => ({
  override: null,
  effective: "approval_required",
  defaultPolicy: "approval_required",
  revision: team.revision,
  ...extra,
});

export const catalogServer = (extra: Partial<Schemas["CatalogServer"]> = {}): Schemas["CatalogServer"] => ({
  id: serverId,
  slug: "service-status",
  name: "Service status",
  description: "Read the status of internal services.",
  teamSlug: team.slug,
  teamName: team.name,
  counts: counts(),
  health: { status: "healthy", checkedAt: "2026-10-16T07:55:00Z", statusSince: "2026-10-15T08:00:00Z", latencyMs: 42 },
  publishedAt: "2026-10-10T10:00:00Z",
  ...extra,
});

/* ---------------- gateways, grants, calls and API keys ---------------- */

export const gatewayId = "77777777-7777-4777-8777-777777777777";

export const gateway = (extra: Partial<Schemas["Gateway"]> = {}): Schemas["Gateway"] => ({
  id: gatewayId,
  slug: "support-tools",
  name: "Support tools",
  description: "What the support desk uses.",
  ownerKind: "team",
  teamId: team.id,
  teamSlug: team.slug,
  teamName: team.name,
  enabled: true,
  url: "https://mcp.example.com/mcp/support-tools",
  capabilityCount: 2,
  unavailableCount: 0,
  grantCount: 0,
  revision: 7,
  createdAt: "2026-10-12T10:00:00Z",
  updatedAt: "2026-10-15T10:00:00Z",
  ...extra,
});

/** A platform gateway (no team, granted to people). */
export const platformGateway = (extra: Partial<Schemas["Gateway"]> = {}): Schemas["Gateway"] =>
  gateway({ ownerKind: "platform", teamId: undefined, teamSlug: undefined, teamName: undefined, slug: "company-tools", name: "Company tools", url: "https://mcp.example.com/mcp/company-tools", grantCount: 2, ...extra });

export const gatewayCapability = (extra: Partial<Schemas["GatewayCapability"]> = {}): Schemas["GatewayCapability"] => ({
  capabilityId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  serverId,
  serverSlug: "service-status",
  serverName: "Service status",
  teamSlug: team.slug,
  kind: "tool",
  name: "get_status",
  exposedName: "service-status__get_status",
  title: "Get status",
  description: "Returns the status of a service.",
  minRole: null,
  available: true,
  requires: null,
  ...extra,
});

export const gatewayCapabilities = (items: Schemas["GatewayCapability"][] = [gatewayCapability()], revision = 7): Schemas["GatewayCapabilities"] => ({ revision, items });

export const catalogServerId = "88888888-8888-4888-8888-888888888888";

export const gatewayOption = (extra: Partial<Schemas["GatewayOption"]> = {}): Schemas["GatewayOption"] => ({
  capabilityId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  serverId,
  serverSlug: "service-status",
  serverName: "Service status",
  teamSlug: team.slug,
  teamName: team.name,
  source: "team",
  kind: "tool",
  name: "get_status",
  exposedName: "service-status__get_status",
  title: "Get status",
  description: "Returns the status of a service.",
  requires: null,
  ...extra,
});

export const gatewayOptions: Schemas["GatewayOption"][] = [
  gatewayOption(),
  gatewayOption({ capabilityId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", name: "restart", exposedName: "service-status__restart", title: "", description: "Restarts a service." }),
  gatewayOption({
    capabilityId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    kind: "prompt",
    name: "incident_summary",
    exposedName: "service-status__incident_summary",
    title: "Incident summary",
    description: "Summarise an incident.",
  }),
  gatewayOption({
    capabilityId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
    serverId: catalogServerId,
    serverSlug: "wiki",
    serverName: "Company wiki",
    teamSlug: "docs-team",
    teamName: "Docs Team",
    source: "catalog",
    name: "search",
    exposedName: "wiki__search",
    title: "Search the wiki",
    description: "Full-text search.",
  }),
];

export const grant = (extra: Partial<Schemas["GatewayGrant"]> = {}): Schemas["GatewayGrant"] => ({
  id: "12121212-1212-4121-8121-121212121212",
  subjectKind: "team",
  team: { id: team.id, slug: team.slug, name: team.name },
  createdAt: "2026-10-13T10:00:00Z",
  addedByName: "Ada Admin",
  ...extra,
});

export const myGateway = (extra: Partial<Schemas["MyGateway"]> = {}): Schemas["MyGateway"] => ({
  id: gatewayId,
  slug: "support-tools",
  name: "Support tools",
  description: "What the support desk uses.",
  ownerKind: "team",
  teamSlug: team.slug,
  teamName: team.name,
  url: "https://mcp.example.com/mcp/support-tools",
  access: ["team_member"],
  capabilityCount: 1,
  ...extra,
});

export const apiKey = (extra: Partial<Schemas["ApiKey"]> = {}): Schemas["ApiKey"] => ({
  id: "13131313-1313-4131-8131-131313131313",
  name: "Claude Code on my laptop",
  prefix: "omp_ab12cd34",
  status: "active",
  createdAt: "2026-10-01T10:00:00Z",
  expiresAt: "2026-12-30T10:00:00Z",
  lastUsedAt: "2026-10-15T10:00:00Z",
  revokedAt: null,
  gateways: [],
  ...extra,
});

export const mcpCall = (extra: Partial<Schemas["McpCall"]> = {}): Schemas["McpCall"] => ({
  id: 501,
  occurredAt: "2026-10-16T07:00:00Z",
  method: "tools/call",
  exposedName: "service-status__get_status",
  gateway: { id: gatewayId, slug: "support-tools", name: "Support tools", exists: true },
  server: { id: serverId, slug: "service-status", name: "Service status", exists: true },
  principal: { kind: "api_key", userId: user().id, displayName: "Una User", email: "una@example.com", apiKeyName: "Claude Code on my laptop" },
  clientName: "claude-code",
  outcome: "ok",
  latencyMs: 120,
  requestBytes: 210,
  responseBytes: 1800,
  requestId: "req-call-1",
  ...extra,
});

/**
 * gateway-options as the server answers it: searched (q), filtered (kind, server) and paged (limit, cursor:
 * the index to continue from), in the order given.
 */
export function optionsPage(options: Schemas["GatewayOption"][], search: URLSearchParams): Schemas["GatewayOptionPage"] {
  const q = (search.get("q") ?? "").toLowerCase();
  const kind = search.get("kind");
  const server = search.get("server");
  const matching = options.filter(
    (o) =>
      (!kind || o.kind === kind) &&
      (!server || o.serverId === server) &&
      (!q || [o.name, o.title, o.serverName, o.serverSlug].some((v) => v.toLowerCase().includes(q))),
  );
  const start = Number(search.get("cursor") ?? 0);
  const limit = Number(search.get("limit") ?? 100);
  const items = matching.slice(start, start + limit);
  return { items, nextCursor: start + limit < matching.length ? String(start + limit) : null };
}

/* ---------------- OAuth sign-in (consent, connected apps, trusted clients) and service accounts ---------------- */

export const oauthClient = (extra: Partial<Schemas["OAuthClientInfo"]> = {}): Schemas["OAuthClientInfo"] => ({
  id: "https://claude.ai/oauth/claude-code-client-metadata",
  kind: "metadata",
  name: "Claude Code",
  host: "claude.ai",
  uri: "https://claude.ai",
  logoUrl: null,
  trusted: false,
  ...extra,
});

/** A client that registered itself (dynamic registration): its name is its own claim. */
export const registeredClient = (extra: Partial<Schemas["OAuthClientInfo"]> = {}): Schemas["OAuthClientInfo"] =>
  oauthClient({ id: "ompcl_3f9a1c", kind: "registered", name: "Handy MCP Helper", host: "helper.example.net", uri: "https://helper.example.net", ...extra });

export const oauthConsent = (extra: Partial<Schemas["OAuthConsent"]> = {}): Schemas["OAuthConsent"] => ({
  client: oauthClient(),
  gateway: myGateway({ capabilityCount: 3 }),
  redirectUri: "http://127.0.0.1:53211/callback",
  redirectHost: "127.0.0.1:53211",
  remembered: false,
  notice: false,
  ...extra,
});

export const oauthGrant = (extra: Partial<Schemas["OAuthGrant"]> = {}): Schemas["OAuthGrant"] => ({
  id: "14141414-1414-4141-8141-141414141414",
  client: oauthClient(),
  gateway: { id: gatewayId, slug: "support-tools", name: "Support tools", exists: true },
  createdAt: "2026-10-10T10:00:00Z",
  lastUsedAt: "2026-10-16T07:00:00Z",
  expiresAt: "2027-04-08T10:00:00Z",
  ...extra,
});

export const trustedClients = (extra: Partial<Schemas["TrustedClients"]> = {}): Schemas["TrustedClients"] => ({
  clients: [
    { clientId: "https://claude.ai/oauth/claude-code-client-metadata", label: "Claude Code" },
    { clientId: "https://vscode.dev/oauth/client-metadata.json", label: "VS Code" },
  ],
  openRegistration: true,
  revision: 2,
  updatedAt: "2026-10-15T10:00:00Z",
  ...extra,
});

export const serviceAccountId = "15151515-1515-4151-8151-151515151515";

export const serviceAccount = (extra: Partial<Schemas["ServiceAccount"]> = {}): Schemas["ServiceAccount"] => ({
  id: serviceAccountId,
  teamId: team.id,
  teamSlug: team.slug,
  name: "ci-release-bot",
  description: "Runs the release workflow's smoke checks.",
  role: "member",
  enabled: true,
  activeKeyCount: 1,
  lastUsedAt: "2026-10-16T06:00:00Z",
  createdByName: "Una User",
  revision: 5,
  createdAt: "2026-10-01T10:00:00Z",
  updatedAt: "2026-10-12T10:00:00Z",
  ...extra,
});

export const serviceAccountKey = (extra: Partial<Schemas["ServiceAccountKey"]> = {}): Schemas["ServiceAccountKey"] => ({
  id: "16161616-1616-4161-8161-161616161616",
  name: "GitHub Actions",
  prefix: "omp_sa_ab12cd34",
  status: "active",
  createdAt: "2026-10-01T10:00:00Z",
  createdByName: "Una User",
  expiresAt: "2026-12-30T10:00:00Z",
  lastUsedAt: "2026-10-16T06:00:00Z",
  revokedAt: null,
  gateways: [],
  ...extra,
});
