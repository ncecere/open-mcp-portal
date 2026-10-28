/*
 * Where an item's LinkTarget leads (docs/admin-overview.md, "Link targets"). The overview's and the team's attention
 * items and the inbox's notifications carry the same LinkTarget, so one table resolves both. The web app routes on
 * `type` (+ `id`, `teamSlug`); a type the table doesn't know, or one missing what it needs (a team slug, an id),
 * resolves to nothing and the item shows without a link. A Vitest test fails when a type has no route.
 */
import { Link } from "@tanstack/react-router";
import { type ReactElement } from "react";
import type { Schemas } from "../api/client";
import { type Me } from "../session";

export type LinkTarget = Schemas["LinkTarget"];
export type LinkType = LinkTarget["type"];

/** What resolving a link needs to know about the viewer. */
export type LinkViewer = Pick<Me, "teams">;

type Resolver = {
  /** The route pattern the link opens (router.tsx), for the test that every type has a route. */
  route: string;
  /** The router link, or null when the target lacks what it needs. */
  element: (link: LinkTarget, viewer: LinkViewer) => ReactElement | null;
};

const server: Resolver = {
  route: "/teams/$team/servers/$serverId",
  element: ({ id, teamSlug }, viewer) => {
    if (!id) return null;
    // Members open the team's page; platform staff who aren't members open the admin page.
    if (teamSlug && viewer.teams.some((t) => t.slug === teamSlug)) return <Link to="/teams/$team/servers/$serverId" params={{ team: teamSlug, serverId: id }} />;
    return <Link to="/admin/servers/$serverId" params={{ serverId: id }} />;
  },
};

/** One entry per LinkType: the compiler fails here when the contract gains a type. */
export const linkTargets: Record<LinkType, Resolver> = {
  server,
  servers: {
    route: "/teams/$team/servers",
    element: ({ teamSlug }) => (teamSlug ? <Link to="/teams/$team/servers" params={{ team: teamSlug }} search={{ publishState: "pending" }} /> : null),
  },
  review_queue: { route: "/admin/publishing", element: () => <Link to="/admin/publishing" /> },
  gateways: { route: "/admin/gateways", element: () => <Link to="/admin/gateways" /> },
  service_account: {
    route: "/teams/$team/service-accounts/$serviceAccountId",
    element: ({ id, teamSlug }) =>
      id && teamSlug ? <Link to="/teams/$team/service-accounts/$serviceAccountId" params={{ team: teamSlug, serviceAccountId: id }} /> : null,
  },
  service_accounts: {
    route: "/teams/$team/service-accounts",
    element: ({ teamSlug }) => (teamSlug ? <Link to="/teams/$team/service-accounts" params={{ team: teamSlug }} /> : null),
  },
  service_connections: {
    route: "/teams/$team/service-accounts",
    element: ({ teamSlug }) => (teamSlug ? <Link to="/teams/$team/service-accounts" params={{ team: teamSlug }} search={{ tab: "connections" }} /> : null),
  },
  automation_tokens: { route: "/admin/automation-tokens", element: () => <Link to="/admin/automation-tokens" /> },
  team_automation_tokens: {
    route: "/teams/$team/settings",
    element: ({ teamSlug }) => (teamSlug ? <Link to="/teams/$team/settings" params={{ team: teamSlug }} search={{ tab: "automation-tokens" }} /> : null),
  },
  auth_providers: { route: "/admin/auth-providers", element: () => <Link to="/admin/auth-providers" /> },
  usage: { route: "/admin/usage", element: () => <Link to="/admin/usage" /> },
  notification_settings: { route: "/admin/notifications", element: () => <Link to="/admin/notifications" /> },
  team_notification_settings: {
    route: "/teams/$team/settings",
    element: ({ teamSlug }) => (teamSlug ? <Link to="/teams/$team/settings" params={{ team: teamSlug }} search={{ tab: "notifications" }} /> : null),
  },
  account_connections: { route: "/settings/connections", element: () => <Link to="/settings/connections" /> },
  account_api_keys: { route: "/settings/api-keys", element: () => <Link to="/settings/api-keys" /> },
};

/** The router link for a target (use as `render={…}` on a Button or TextLink), or null when there is nowhere to go. */
export function linkElement(link: LinkTarget | null | undefined, viewer: LinkViewer): ReactElement | null {
  if (!link) return null;
  const resolver = (linkTargets as Partial<Record<string, Resolver>>)[link.type];
  return resolver ? resolver.element(link, viewer) : null;
}
