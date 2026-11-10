/* Fixtures for gateways, grants, calls and API keys. */
import type { Schemas } from "../api/client";
import { team, user } from "./fixtures-core";
import { serverId } from "./fixtures-registry";

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
