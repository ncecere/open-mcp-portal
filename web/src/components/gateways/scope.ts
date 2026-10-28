/*
 * Where a gateway record is shown, and what the viewer may do there: a team's
 * page (/teams/$team/gateways/$gatewayId, the team API) or Admin
 * (/admin/gateways/$gatewayId, the admin API). The record's tabs are the
 * same; the queries, the mutations' API paths and the abilities differ.
 *
 * The abilities mirror the server's rules (api/openapi.yaml); the server
 * still decides. Team gateways: owners and admins of an active team create,
 * edit and delete them; members and platform staff read; the calls are for
 * owners, admins and platform staff. Platform gateways: platform admins
 * edit them and their grants; auditors read. In Admin a team gateway is
 * read-only except its switch (platform admins).
 */
import { infiniteQueryOptions, type QueryClient, queryOptions } from "@tanstack/react-query";
import { api, ifMatch, unwrap, type Schemas } from "../../api/client";
import { adminGatewayQuery, adminGatewaysKey, myGatewaysKey, teamGatewayQuery, teamGatewaysKey } from "../../api/queries";
import type { Gateway, GatewayKind, TeamRole } from "./labels";

export type GatewayScope = { kind: "team"; team: string } | { kind: "admin" };

export type GatewayAbilities = {
  /** Change the name, description and switch, and delete. */
  canEdit: boolean;
  /** Only switch it on or off (platform admins on a team gateway in Admin). */
  canToggle: boolean;
  /** Read the calls through it. */
  canReadCalls: boolean;
  /** Add and remove grants (platform gateways in Admin). */
  canManageGrants: boolean;
};

export const readOnly: GatewayAbilities = { canEdit: false, canToggle: false, canReadCalls: false, canManageGrants: false };

/** A team's viewer: owners and admins of an active team edit; owners, admins and platform staff read the calls. */
export function teamGatewayAbilities(t: { isManager: boolean; archived: boolean; staff: boolean }): GatewayAbilities {
  return { ...readOnly, canEdit: t.isManager && !t.archived, canReadCalls: t.isManager || t.staff };
}

/** Admin: platform admins edit platform gateways and switch team gateways; auditors read. */
export function adminGatewayAbilities(platformAdmin: boolean, gateway: Pick<Gateway, "ownerKind">): GatewayAbilities {
  const platform = gateway.ownerKind === "platform";
  return { canEdit: platformAdmin && platform, canToggle: platformAdmin && !platform, canReadCalls: true, canManageGrants: platformAdmin && platform };
}

/** The team whose API path holds a team gateway. */
const teamOf = (scope: GatewayScope, gateway: Pick<Gateway, "teamSlug">) => gateway.teamSlug ?? (scope.kind === "team" ? scope.team : "");

/** The record's query. */
export const gatewayQuery = (scope: GatewayScope, id: string) => (scope.kind === "team" ? teamGatewayQuery(scope.team, id) : adminGatewayQuery(id));

const baseKey = (scope: GatewayScope) => (scope.kind === "team" ? teamGatewaysKey(scope.team) : adminGatewaysKey);

export const gatewayCapabilitiesQuery = (scope: GatewayScope, id: string) =>
  queryOptions({
    queryKey: [...baseKey(scope), id, "capabilities"],
    queryFn: async () =>
      scope.kind === "team"
        ? unwrap(await api.GET("/v1/teams/{team}/gateways/{gatewayId}/capabilities", { params: { path: { team: scope.team, gatewayId: id } } }))
        : unwrap(await api.GET("/v1/admin/gateways/{gatewayId}/capabilities", { params: { path: { gatewayId: id } } })),
  });

/** Server-side filters of gateway-options ("" = any). */
export type OptionFilters = { q: string; kind: GatewayKind | ""; server: string };

/** The page size the picker asks for. */
export const optionPageSize = 100;

/** What a gateway may select, a page at a time (ordered by server, then name), searched and filtered by the server. */
export const gatewayOptionsQuery = (scope: GatewayScope, f: OptionFilters) =>
  infiniteQueryOptions({
    queryKey: [...baseKey(scope), "options", f],
    queryFn: async ({ pageParam }) => {
      const query = { q: f.q || undefined, kind: f.kind || undefined, server: f.server || undefined, cursor: pageParam, limit: optionPageSize };
      return scope.kind === "team"
        ? unwrap(await api.GET("/v1/teams/{team}/gateway-options", { params: { path: { team: scope.team }, query } }))
        : unwrap(await api.GET("/v1/admin/gateway-options", { params: { query } }));
    },
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
  });

export const grantsQuery = (id: string) =>
  queryOptions({
    queryKey: [...adminGatewaysKey, id, "grants"],
    queryFn: async () => unwrap(await api.GET("/v1/admin/gateways/{gatewayId}/grants", { params: { path: { gatewayId: id } } })),
  });

/** After a change to a gateway: its team's lists, Admin's and My gateways load again. */
export function invalidateGateway(qc: QueryClient, gateway: Pick<Gateway, "teamSlug">) {
  if (gateway.teamSlug) void qc.invalidateQueries({ queryKey: teamGatewaysKey(gateway.teamSlug) });
  void qc.invalidateQueries({ queryKey: adminGatewaysKey });
  void qc.invalidateQueries({ queryKey: myGatewaysKey });
}

/** A changed gateway from a mutation's reply, in both records' caches, so the page shows it at once. */
export function storeGateway(qc: QueryClient, gateway: Gateway) {
  if (gateway.teamSlug) qc.setQueryData(teamGatewayQuery(gateway.teamSlug, gateway.id).queryKey, gateway);
  qc.setQueryData(adminGatewayQuery(gateway.id).queryKey, gateway);
  invalidateGateway(qc, gateway);
}

export type GatewayChange = { name?: string; description?: string; enabled?: boolean; capturePayloads?: boolean; rateLimitPerMinute?: number | null };

/** PATCH with If-Match on the gateway's revision, through the scope's API. */
export async function updateGateway(scope: GatewayScope, gateway: Gateway, body: GatewayChange, revision = gateway.revision) {
  const header = ifMatch(revision);
  return scope.kind === "team"
    ? unwrap(await api.PATCH("/v1/teams/{team}/gateways/{gatewayId}", { params: { path: { team: teamOf(scope, gateway), gatewayId: gateway.id }, header }, body }))
    : unwrap(await api.PATCH("/v1/admin/gateways/{gatewayId}", { params: { path: { gatewayId: gateway.id }, header }, body }));
}

export async function deleteGateway(scope: GatewayScope, gateway: Gateway) {
  return scope.kind === "team"
    ? unwrap(await api.DELETE("/v1/teams/{team}/gateways/{gatewayId}", { params: { path: { team: teamOf(scope, gateway), gatewayId: gateway.id } } }))
    : unwrap(await api.DELETE("/v1/admin/gateways/{gatewayId}", { params: { path: { gatewayId: gateway.id } } }));
}

export type Selection = { capabilityId: string; minRole?: TeamRole; curation?: Schemas["GatewayToolCuration"] | null; expectedFingerprint?: string };

/** Replaces the selection (If-Match: the gateway's revision). */
export async function setCapabilities(scope: GatewayScope, gateway: Gateway, items: Selection[], revision: number) {
  const header = ifMatch(revision);
  const body = { items };
  return scope.kind === "team"
    ? unwrap(await api.PUT("/v1/teams/{team}/gateways/{gatewayId}/capabilities", { params: { path: { team: teamOf(scope, gateway), gatewayId: gateway.id }, header }, body }))
    : unwrap(await api.PUT("/v1/admin/gateways/{gatewayId}/capabilities", { params: { path: { gatewayId: gateway.id }, header }, body }));
}

/** The list page a gateway's record returns to. */
export const listPath = (scope: GatewayScope) => (scope.kind === "team" ? ({ to: "/teams/$team/gateways", params: { team: scope.team } } as const) : ({ to: "/admin/gateways" } as const));
