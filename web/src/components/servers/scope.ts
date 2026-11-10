/*
 * Where a server record is shown, and what the viewer may do there: a team's
 * page (/teams/$team/servers/$serverId, the team API) or Admin
 * (/admin/servers/$serverId, the admin API). The record's tabs are the same;
 * the queries, the mutations' API paths and the abilities differ.
 *
 * The abilities mirror the server's rules (api/openapi.yaml); the server
 * still decides. Members and platform staff read; editors and above test,
 * refresh and edit; owners and admins delete, publish and unpublish, and
 * approve changed capabilities only under self_publish; platform admins
 * review. Archived teams are read-only.
 */
import { type QueryClient, queryOptions } from "@tanstack/react-query";
import { api, unwrap } from "../../api/client";
import { adminServerQuery, adminServersKey, catalogKey, teamServerQuery, teamServersKey } from "../../api/queries";
import type { McpServer } from "./labels";

export type ServerScope = { kind: "team"; team: string } | { kind: "admin" };

export type ServerAbilities = {
  /** Test, refresh and change settings. */
  canEdit: boolean;
  /** Delete, publish, withdraw and unpublish. */
  canManage: boolean;
  /** Approve a published server's changed capabilities. */
  canApproveChanges: boolean;
  /** Approve or reject a publish request, or take a server off the catalog (platform admins). */
  canReview: boolean;
};

export const readOnly: ServerAbilities = { canEdit: false, canManage: false, canApproveChanges: false, canReview: false };

/** A team member's abilities on one of the team's servers. */
export function teamAbilities(t: { canEdit: boolean; isManager: boolean; archived: boolean }, server?: Pick<McpServer, "effectivePublishPolicy">): ServerAbilities {
  const manager = t.isManager && !t.archived;
  return { canEdit: t.canEdit, canManage: manager, canApproveChanges: manager && server?.effectivePublishPolicy === "self_publish", canReview: false };
}

/** Platform admins review and approve changes in Admin; auditors read. Settings are the team's. */
export const adminAbilities = (platformAdmin: boolean): ServerAbilities => ({ ...readOnly, canApproveChanges: platformAdmin, canReview: platformAdmin });

const baseKey = (scope: ServerScope) => (scope.kind === "team" ? teamServersKey(scope.team) : adminServersKey);

export const capabilitiesQuery = (scope: ServerScope, id: string) =>
  queryOptions({
    queryKey: [...baseKey(scope), id, "capabilities"],
    queryFn: async () =>
      scope.kind === "team"
        ? unwrap(await api.GET("/v1/teams/{team}/mcp-servers/{serverId}/capabilities", { params: { path: { team: scope.team, serverId: id } } }))
        : unwrap(await api.GET("/v1/admin/mcp-servers/{serverId}/capabilities", { params: { path: { serverId: id } } })),
  });

/** The recent health checks, from the team's API or Admin's. */
export const healthChecksQuery = (scope: ServerScope, id: string) =>
  queryOptions({
    queryKey: [...baseKey(scope), id, "health"],
    queryFn: async () =>
      scope.kind === "team"
        ? unwrap(await api.GET("/v1/teams/{team}/mcp-servers/{serverId}/health-checks", { params: { path: { team: scope.team, serverId: id } } }))
        : unwrap(await api.GET("/v1/admin/mcp-servers/{serverId}/health-checks", { params: { path: { serverId: id } } })),
  });

/** The team's publishing policy (with whether it's the platform default). */
export const teamPublishingQuery = (team: string) =>
  queryOptions({
    queryKey: ["team", team, "publishing"],
    queryFn: async () => unwrap(await api.GET("/v1/teams/{team}/publishing", { params: { path: { team } } })),
  });

/** After a change to a server: its team's lists and records, Admin's and the catalog load again. */
export function invalidateServer(qc: QueryClient, server: Pick<McpServer, "teamSlug">) {
  void qc.invalidateQueries({ queryKey: teamServersKey(server.teamSlug) });
  void qc.invalidateQueries({ queryKey: adminServersKey });
  void qc.invalidateQueries({ queryKey: catalogKey });
}

/** A changed server from a mutation's reply, in both records' caches, so the page shows it at once. */
export function storeServer(qc: QueryClient, server: McpServer) {
  qc.setQueryData(teamServerQuery(server.teamSlug, server.id).queryKey, server);
  qc.setQueryData(adminServerQuery(server.id).queryKey, server);
  invalidateServer(qc, server);
}

/** The first discovery after creating a server, kept for its record page to show once. */
export const firstDiscoveryKey = (id: string) => ["first-discovery", id];
