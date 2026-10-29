/*
 * The tabs of each page with sections, in order (the first is the default).
 * Kept here so the router can validate ?tab= without loading page chunks.
 */

/** Admin → Teams › one team (Limits & retention: the team's overrides). */
export const adminTeamTabs = ["overview", "members", "limits", "settings"] as const;
export type AdminTeamTab = (typeof adminTeamTabs)[number];

/** An MCP server's record (the team's and the admin's): Overview · Capabilities · Health · Settings. */
export const serverTabs = ["overview", "capabilities", "health", "settings"] as const;
export type ServerTab = (typeof serverTabs)[number];

/**
 * A gateway's record (the team's and the admin's): Overview · Capabilities · Access · Activity · Settings. Access
 * (grants) shows only for platform gateways in Admin.
 */
export const gatewayTabs = ["overview", "capabilities", "access", "requests", "activity", "settings"] as const;
export type GatewayTab = (typeof gatewayTabs)[number];

/** A team's service account: Overview (role and access) · Keys · Settings. */
export const serviceAccountTabs = ["overview", "keys", "connections", "settings"] as const;
export type ServiceAccountTab = (typeof serviceAccountTabs)[number];

/** Admin → Auth providers › one provider: Overview (redirect URI, endpoints, use) · Access (who may use it) · Settings. */
export const authProviderTabs = ["overview", "access", "settings"] as const;
export type AuthProviderTab = (typeof authProviderTabs)[number];

/**
 * Team settings: Members (with open invites) · Audit log · Limits & retention (read-only) · Notifications
 * (webhooks) · Automation tokens (CI) · General.
 */
export const teamSettingsTabs = ["members", "audit", "limits", "notifications", "automation-tokens", "general"] as const;
export type TeamSettingsTab = (typeof teamSettingsTabs)[number];

/**
 * validateSearch for a route with tabs: keeps ?tab= when it names a tab other
 * than the first. With `passthrough`, other parameters (list filters, ?record=,
 * date ranges) are kept too.
 */
export function tabSearch<T extends string>(tabs: readonly T[], opts: { passthrough?: boolean } = {}) {
  return (s: Record<string, unknown>): { tab?: T } => {
    const tab = tabs.includes(s.tab as T) && s.tab !== tabs[0] ? { tab: s.tab as T } : {};
    if (!opts.passthrough) return tab;
    const { tab: _drop, ...rest } = s;
    return { ...rest, ...tab };
  };
}
