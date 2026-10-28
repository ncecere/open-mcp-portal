import { useQuery } from "@tanstack/react-query";
import { Link, useRouter } from "@tanstack/react-router";
import { Bell, Boxes, Home, Inbox, KeyRound, Library, Link2, Network, Plug, Shield, User } from "lucide-react";
import {
  adminAuthProviderQuery,
  adminGatewayQuery,
  adminServerQuery,
  adminTeamQuery,
  adminUserQuery,
  catalogServerQuery,
  myGatewayQuery,
  serviceAccountQuery,
  teamGatewayQuery,
  teamQuery,
  teamServerQuery,
} from "../../api/queries";
import { terms } from "../../lib/terms";
import { type BreadcrumbItem } from "@/components/ui/breadcrumbs/breadcrumbs";
import { VisuallyHidden } from "@/components/ui/visually-hidden/visually-hidden";
import { isNotFound } from "../not-found";
import { type PageCrumb, useCurrentCrumbTail, useCurrentPageCrumbs } from "./crumb-tail";
import { isAdminRoute, isTeamRoute, type Location } from "./location";
import { adminNav, icon, teamNavFor } from "./nav";
import { useCurrentUser } from "../../session";

/** Labels for the current route, using data the pages have already loaded, plus the page's tail (its active tab). */
export function useBreadcrumbs(loc: Location, canAdmin: boolean): BreadcrumbItem[] {
  const trail = useTrail(loc, canAdmin);
  const tail = useCurrentCrumbTail();
  const pages = useCurrentPageCrumbs();
  const router = useRouter();
  let crumbs = trail;
  if (tail) {
    // The last crumb becomes a link back to the page's first tab.
    const last = trail[trail.length - 1];
    const linked = last && !last.render ? { ...last, render: <Link to="." search={{}} /> } : last;
    crumbs = [...trail.slice(0, -1), ...(linked ? [linked] : []), { label: tail }];
  }
  if (pages.length === 0) return crumbs;
  // Record and form pages are open on top (bottom first). The crumb under the
  // top page closes it (Back); lower ones go straight to their page.
  const top = pages.length - 1;
  const linkTo = (item: BreadcrumbItem, above: PageCrumb, underTop: boolean): BreadcrumbItem => ({
    ...item,
    render: (
      <a
        href={above.href}
        onClick={(e) => {
          if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
          e.preventDefault();
          if (underTop) above.close();
          else router.history.push(above.href);
        }}
      />
    ),
  });
  const under = crumbs[crumbs.length - 1];
  const out: BreadcrumbItem[] = crumbs.slice(0, -1);
  if (under) out.push(linkTo(under, pages[0]!, top === 0));
  pages.forEach((p, i) => out.push(i < top ? linkTo({ label: p.label }, pages[i + 1]!, i + 1 === top) : { label: p.label }));
  return out;
}

function useTrail({ routeId, params }: Location, canAdmin: boolean): BreadcrumbItem[] {
  const me = useCurrentUser();
  const slug = isTeamRoute(routeId) ? params.team : undefined;
  const team = useQuery({ ...teamQuery(slug ?? ""), enabled: !!slug });
  const userId = routeId === "/app/admin/users/$userId" ? params.userId : undefined;
  const user = useQuery({ ...adminUserQuery(userId ?? ""), enabled: canAdmin && !!userId });
  const adminTeamSlug = routeId === "/app/admin/teams/$team" ? params.team : undefined;
  const adminTeam = useQuery({ ...adminTeamQuery(adminTeamSlug ?? ""), enabled: canAdmin && !!adminTeamSlug });
  // A server's name, from the record page's own query (already loaded, or loading with it).
  const serverId = routeId.endsWith("/servers/$serverId") || routeId === "/app/catalog/$serverId" ? params.serverId : undefined;
  const teamServer = useQuery({ ...teamServerQuery(slug ?? "", serverId ?? ""), enabled: !!slug && !!serverId });
  const adminServer = useQuery({ ...adminServerQuery(serverId ?? ""), enabled: canAdmin && !!serverId && routeId === "/app/admin/servers/$serverId" });
  const catalogServer = useQuery({ ...catalogServerQuery(serverId ?? ""), enabled: !!serverId && routeId === "/app/catalog/$serverId" });
  // A gateway's name, likewise.
  const gatewayId = routeId.endsWith("/gateways/$gatewayId") ? params.gatewayId : undefined;
  const teamGateway = useQuery({ ...teamGatewayQuery(slug ?? "", gatewayId ?? ""), enabled: !!slug && !!gatewayId });
  const adminGateway = useQuery({ ...adminGatewayQuery(gatewayId ?? ""), enabled: canAdmin && !!gatewayId && routeId === "/app/admin/gateways/$gatewayId" });
  const myGateway = useQuery({ ...myGatewayQuery(gatewayId ?? ""), enabled: !!gatewayId && routeId === "/app/gateways/$gatewayId" });
  // A service account's name, likewise.
  const serviceAccountId = routeId === "/app/teams/$team/service-accounts/$serviceAccountId" ? params.serviceAccountId : undefined;
  const serviceAccount = useQuery({ ...serviceAccountQuery(slug ?? "", serviceAccountId ?? ""), enabled: !!slug && !!serviceAccountId });
  // An auth provider's name, likewise.
  const providerId = routeId === "/app/admin/auth-providers/$providerId" ? params.providerId : undefined;
  const provider = useQuery({ ...adminAuthProviderQuery(providerId ?? ""), enabled: canAdmin && !!providerId });

  if (routeId === "/app/") return [{ label: terms.home, icon: icon(Home) }];
  // From the account menu: the page itself, not "Home".
  if (routeId === "/app/settings/sessions") return [{ label: "Sessions", icon: icon(User) }];
  if (routeId === "/app/settings/profile") return [{ label: "Profile", icon: icon(User) }];
  if (routeId === "/app/settings/api-keys") return [{ label: terms.apiKeys, icon: icon(KeyRound) }];
  if (routeId === "/app/settings/connected-apps") return [{ label: terms.connectedApps, icon: icon(Plug) }];
  if (routeId === "/app/settings/connections") return [{ label: terms.myConnections, icon: icon(Link2) }];
  if (routeId === "/app/settings/notifications") return [{ label: terms.notifications, icon: icon(Bell) }];
  if (routeId === "/app/notifications") return [{ label: terms.inbox, icon: icon(Inbox) }];
  if (routeId === "/app/gateways") return [{ label: terms.myGateways, icon: icon(Network) }];
  if (routeId === "/app/gateways/$gatewayId") {
    return [
      { label: terms.myGateways, icon: icon(Network), render: <Link to="/gateways" /> },
      ...(isNotFound(myGateway.error) ? [] : [{ label: myGateway.data?.gateway.name ?? <VisuallyHidden>Gateway</VisuallyHidden> }]),
    ];
  }
  if (routeId === "/app/catalog") return [{ label: terms.catalog, icon: icon(Library) }];
  if (routeId === "/app/catalog/$serverId") {
    return [
      { label: terms.catalog, icon: icon(Library), render: <Link to="/catalog" /> },
      ...(isNotFound(catalogServer.error) ? [] : [{ label: catalogServer.data?.server.name ?? <VisuallyHidden>Server</VisuallyHidden> }]),
    ];
  }

  if (slug && isNotFound(team.error)) return [{ label: terms.home, icon: icon(Home), render: <Link to="/" /> }];
  if (slug) {
    const crumbs: BreadcrumbItem[] = [
      // Until the team loads, its crumb has no visible text and stays out of the document title (not "… · Team · …").
      { label: team.data?.team.name ?? <VisuallyHidden>Team</VisuallyHidden>, icon: icon(Boxes), render: <Link to="/teams/$team" params={{ team: slug }} /> },
    ];
    const sub = routeId.slice("/app/teams/$team".length);
    if (sub === "/servers/$serverId") {
      crumbs.push({ label: terms.mcpServers, render: <Link to="/teams/$team/servers" params={{ team: slug }} /> });
      if (!isNotFound(teamServer.error)) crumbs.push({ label: teamServer.data?.name ?? <VisuallyHidden>Server</VisuallyHidden> });
      return crumbs;
    }
    if (sub === "/gateways/$gatewayId") {
      crumbs.push({ label: terms.gateways, render: <Link to="/teams/$team/gateways" params={{ team: slug }} /> });
      if (!isNotFound(teamGateway.error)) crumbs.push({ label: teamGateway.data?.name ?? <VisuallyHidden>Gateway</VisuallyHidden> });
      return crumbs;
    }
    if (sub === "/calls/$callId") {
      crumbs.push({ label: `Call ${params.callId ?? ""}`.trim() });
      return crumbs;
    }
    if (sub === "/service-accounts/$serviceAccountId") {
      crumbs.push({ label: terms.serviceAccounts, render: <Link to="/teams/$team/service-accounts" params={{ team: slug }} /> });
      if (!isNotFound(serviceAccount.error)) crumbs.push({ label: serviceAccount.data?.name ?? <VisuallyHidden>Service account</VisuallyHidden> });
      return crumbs;
    }
    // The team page's own label from the navigation ("Overview", "Team settings"); an unknown page adds nothing (the not-found tail follows).
    const page = teamNavFor(me, slug).find((n) => n.to.slice("/teams/$team".length) === (sub === "/" ? "" : sub));
    if (page) crumbs.push({ label: page.label });
    return crumbs;
  }

  // Not an admin: the admin pages show the no-access page under Home.
  if (isAdminRoute(routeId) && !canAdmin) return [{ label: terms.home, icon: icon(Home), render: <Link to="/" /> }];
  if (isAdminRoute(routeId)) {
    const crumbs: BreadcrumbItem[] = [{ label: "Admin", icon: icon(Shield), render: <Link to="/admin" /> }];
    if (userId) {
      crumbs.push({ label: "Users", render: <Link to="/admin/users" /> }, ...(isNotFound(user.error) ? [] : [{ label: user.data?.user.displayName ?? "User" }]));
    } else if (routeId === "/app/admin/servers/$serverId") {
      crumbs.push(
        { label: terms.mcpServers, render: <Link to="/admin/servers" /> },
        ...(isNotFound(adminServer.error) ? [] : [{ label: adminServer.data?.name ?? <VisuallyHidden>Server</VisuallyHidden> }]),
      );
    } else if (routeId === "/app/admin/gateways/$gatewayId") {
      crumbs.push(
        { label: terms.gateways, render: <Link to="/admin/gateways" /> },
        ...(isNotFound(adminGateway.error) ? [] : [{ label: adminGateway.data?.name ?? <VisuallyHidden>Gateway</VisuallyHidden> }]),
      );
    } else if (routeId === "/app/admin/calls/$callId") {
      crumbs.push({ label: terms.calls, render: <Link to="/admin/calls" /> }, { label: `Call ${params.callId ?? ""}`.trim() });
    } else if (providerId) {
      crumbs.push(
        { label: terms.authProviders, render: <Link to="/admin/auth-providers" /> },
        ...(isNotFound(provider.error) ? [] : [{ label: provider.data?.name ?? <VisuallyHidden>Provider</VisuallyHidden> }]),
      );
    } else if (adminTeamSlug) {
      crumbs.push({ label: "Teams", render: <Link to="/admin/teams" /> }, ...(isNotFound(adminTeam.error) ? [] : [{ label: adminTeam.data?.team.name ?? adminTeamSlug }]));
    } else {
      // Only the admin layout matched (an unknown admin address): the not-found page adds its own tail.
      const page = adminNav.find((n) => routeId === "/app" + n.to || routeId === "/app" + n.to + "/");
      if (page || routeId !== "/app/admin") crumbs.push({ label: page?.label ?? "Administration" });
    }
    return crumbs;
  }

  // An unknown address: NotFoundState adds "Page not found" as the tail.
  return [{ label: terms.home, icon: icon(Home), render: <Link to="/" /> }];
}

/** "Team settings · Platform Tools · <instance>": the last two crumbs, most specific first. */
export function documentTitle(crumbs: BreadcrumbItem[], instanceName: string) {
  const all = crumbs.filter((c) => !c.collapsed).map((c) => (typeof c.label === "string" ? c.label : "")).filter(Boolean);
  // "Home" names a page only on its own: under another page ("Page not found") it's the way back, not a place.
  const labels = all.length > 1 ? all.filter((l) => l !== terms.home) : all;
  return [...labels.slice(-2).reverse(), instanceName].join(" · ");
}

/**
 * The trail as shown: on a phone (below 600px), a trail of more than two
 * crumbs keeps the first and the last and collapses the ones between into
 * "…", a menu of them in order, so every trail stays on one line. Wider,
 * every crumb shows. The document title and the back links read the full trail.
 */
export function fitCrumbs(trail: BreadcrumbItem[], narrow: boolean): BreadcrumbItem[] {
  // A crumb without text (a tab whose name is still loading) never shows as an empty step.
  const crumbs = trail.some((c) => c.label === "") ? trail.filter((c) => c.label !== "") : trail;
  if (!narrow || crumbs.length <= 2) return crumbs;
  const middle = crumbs.slice(1, -1);
  const labels = middle.map((c) => (typeof c.label === "string" ? c.label : "")).filter(Boolean);
  return [crumbs[0]!, { label: labels.length ? labels.join(", ") : "More pages", collapsed: middle }, crumbs[crumbs.length - 1]!];
}
