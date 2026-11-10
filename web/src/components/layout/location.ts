import { useRouterState } from "@tanstack/react-router";
import { useMemo } from "react";
import { type Me } from "../../session";

/* Route awareness for the shell: which route matched, and what the user may see. */

export type Location = { routeId: string; params: Record<string, string> };

/** The deepest matched route and its params. */
export function useLocationInfo(): Location {
  const routeId: string = useRouterState({ select: (s): string => String(s.matches[s.matches.length - 1]?.routeId ?? "") });
  const paramsKey = useRouterState({ select: (s) => JSON.stringify(s.matches[s.matches.length - 1]?.params ?? {}) });
  const params = useMemo(() => JSON.parse(paramsKey) as Record<string, string>, [paramsKey]);
  return { routeId, params };
}

export const isTeamRoute = (routeId: string) => routeId.startsWith("/app/teams/$team");

export const isAdminRoute = (routeId: string) => routeId.startsWith("/app/admin");

export function useCapabilities(me: Me) {
  const canAdmin = me.capabilities.platformAdmin || me.capabilities.platformAuditor;
  const readOnlyAdmin = me.capabilities.platformAuditor && !me.capabilities.platformAdmin;
  return { canAdmin, readOnlyAdmin };
}
