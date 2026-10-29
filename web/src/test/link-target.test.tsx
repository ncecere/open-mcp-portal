/* LinkTarget routing: every contract type has a route, and each resolves like docs/admin-overview.md says. */
import { screen } from "@testing-library/react";
import { linkElement, linkTargets, type LinkTarget } from "../components/link-target";
import { router } from "../router";
import { meFor, serverId, team } from "./fixtures";
import { renderBare } from "./harness";

const routePaths = () => Object.keys(router.routesByPath).map((p) => (p.length > 1 ? p.replace(/\/$/, "") : p));
const member = meFor("none", "member");
const staff = meFor("platform_auditor", null);

async function hrefOf(link: LinkTarget, me = member): Promise<string | null> {
  const el = linkElement(link, me);
  if (!el) return null;
  const { unmount } = renderBare(<div data-testid="host">{el}</div>, me);
  const a = (await screen.findByTestId("host")).querySelector("a");
  const href = a?.getAttribute("href") ?? null;
  unmount();
  return href;
}

describe("link targets", () => {
  it("have a registered route for every type the contract lists", () => {
    const paths = routePaths();
    for (const [type, resolver] of Object.entries(linkTargets)) expect(paths, `${type} → ${resolver.route}`).toContain(resolver.route);
  });

  it("resolve to the routes the design lists", async () => {
    const t = team.slug;
    const cases: [LinkTarget, string][] = [
      [{ type: "server", id: serverId, teamSlug: t }, `/teams/${t}/servers/${serverId}`],
      [{ type: "servers", teamSlug: t }, `/teams/${t}/servers?publishState=pending`],
      [{ type: "review_queue" }, "/admin/publishing"],
      [{ type: "approval", id: "receipt1" }, "/approvals/receipt1"],
      [{ type: "access_request", id: "access1" }, "/access-requests/access1"],
      [{ type: "access_requests" }, "/access-requests"],
      [{ type: "gateways" }, "/admin/gateways"],
      [{ type: "service_account", id: "sa1", teamSlug: t }, `/teams/${t}/service-accounts/sa1`],
      [{ type: "service_accounts", teamSlug: t }, `/teams/${t}/service-accounts`],
      [{ type: "service_connections", teamSlug: t }, `/teams/${t}/service-accounts?tab=connections`],
      [{ type: "automation_tokens" }, "/admin/automation-tokens"],
      [{ type: "team_automation_tokens", teamSlug: t }, `/teams/${t}/settings?tab=automation-tokens`],
      [{ type: "auth_providers" }, "/admin/auth-providers"],
      [{ type: "usage" }, "/admin/usage"],
      [{ type: "notification_settings" }, "/admin/notifications"],
      [{ type: "team_notification_settings", teamSlug: t }, `/teams/${t}/settings?tab=notifications`],
      [{ type: "account_connections" }, "/settings/connections"],
      [{ type: "account_api_keys" }, "/settings/api-keys"],
    ];
    expect(cases.map(([l]) => l.type).sort()).toEqual(Object.keys(linkTargets).sort());
    for (const [link, href] of cases) expect(await hrefOf(link), link.type).toBe(href);
  });

  it("send platform staff who aren't on the team to the admin page of a server", async () => {
    expect(await hrefOf({ type: "server", id: serverId, teamSlug: team.slug }, staff)).toBe(`/admin/servers/${serverId}`);
  });

  it("resolve to nothing without what a type needs, or for a type the app doesn't know", () => {
    expect(linkElement({ type: "server" }, member)).toBeNull();
    expect(linkElement({ type: "approval" }, member)).toBeNull();
    expect(linkElement({ type: "access_request" }, member)).toBeNull();
    expect(linkElement({ type: "servers" }, member)).toBeNull();
    expect(linkElement({ type: "team_notification_settings" }, member)).toBeNull();
    expect(linkElement({ type: "service_account", teamSlug: team.slug }, member)).toBeNull();
    expect(linkElement({ type: "from_the_future" } as unknown as LinkTarget, member)).toBeNull();
    expect(linkElement(null, member)).toBeNull();
  });
});
