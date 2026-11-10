/* Fixtures for the registry: MCP servers, capabilities, health checks, publishing and the catalog. */
import type { Schemas } from "../api/client";
import { team } from "./fixtures-core";

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
  toolClass: null,
  suggestedClass: extra.kind && extra.kind !== "tool" ? null : "read",
  classDrift: false,
  ...extra,
});

export const capabilities: Schemas["McpCapability"][] = [
  capability(),
  capability({ id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", name: "restart", title: "", description: "Restarts a service.", definition: { name: "restart", annotations: { destructiveHint: true } }, suggestedClass: "destructive" }),
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
