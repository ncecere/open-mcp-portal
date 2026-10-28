/* The navigation lists (nav.tsx): only real pages, the right ones per role, and the breadcrumb helpers. */
import { screen, waitFor, within } from "@testing-library/react";
import { currentGroups } from "../components/layout/admin-groups";
import { documentTitle, fitCrumbs } from "../components/layout/breadcrumbs";
import { activeAdminGroup, adminNav, adminSections, teamAccess, teamNavFor, workspaceNav } from "../components/layout/nav";
import { router } from "../router";
import { meFor, myTeam, team } from "./fixtures";
import { mockApi, renderApp, shellRoutes } from "./harness";

const routePaths = () => Object.keys(router.routesByPath).map((p) => (p.length > 1 ? p.replace(/\/$/, "") : p));

describe("navigation lists", () => {
  it("point only at registered routes (no placeholders or dead links)", () => {
    const paths = routePaths();
    const all = [...workspaceNav.map((n) => n.to), ...teamNavFor(meFor("none", "owner"), team.slug).map((n) => n.to), ...adminNav.map((n) => n.to)];
    for (const to of all) expect(paths, to).toContain(to);
  });

  it("have the registry's, the gateways' and the operations' sections", () => {
    expect(workspaceNav.map((n) => [n.label, n.to])).toEqual([
      ["Home", "/"],
      ["Catalog", "/catalog"],
      ["My gateways", "/gateways"],
    ]);
    expect(teamNavFor(meFor("none", "member"), team.slug).find((n) => n.label === "MCP servers")?.to).toBe("/teams/$team/servers");
    expect(teamNavFor(meFor("none", "member"), team.slug).find((n) => n.label === "Gateways")?.to).toBe("/teams/$team/gateways");
    expect(teamNavFor(meFor("none", "member"), team.slug).find((n) => n.label === "Service accounts")?.to).toBe("/teams/$team/service-accounts");
    expect(adminNav.map((n) => n.to)).toEqual([
      "/admin",
      "/admin/users",
      "/admin/teams",
      "/admin/servers",
      "/admin/publishing",
      "/admin/networks",
      "/admin/gateways",
      "/admin/trusted-clients",
      "/admin/auth-providers",
      "/admin/automation-tokens",
      "/admin/audit",
      "/admin/calls",
      "/admin/usage",
      "/admin/limits",
      "/admin/retention",
      "/admin/capture",
      "/admin/notifications",
    ]);
    expect(teamNavFor(meFor("none", "editor"), team.slug).find((n) => n.label === "Usage")?.to).toBe("/teams/$team/usage");
    const labels = [...workspaceNav, ...teamNavFor(meFor("none", "owner"), team.slug), ...adminNav].map((n) => n.label);
    expect(labels).not.toContain("Connect");
  });

  it("resolve the record routes the lists link to (a server, a catalog entry, gateways, API keys, connected apps, service accounts, consent, connections, auth providers, connect)", () => {
    const paths = routePaths();
    const records = [
      "/teams/$team/servers/$serverId",
      "/catalog/$serverId",
      "/admin/servers/$serverId",
      "/teams/$team/gateways/$gatewayId",
      "/admin/gateways/$gatewayId",
      "/gateways/$gatewayId",
      "/settings/api-keys",
      "/settings/connected-apps",
      "/teams/$team/service-accounts/$serviceAccountId",
      "/oauth/consent",
      "/settings/connections",
      "/admin/auth-providers/$providerId",
      "/connect/$provider",
      "/connect/done",
      "/teams/$team/calls/$callId",
      "/admin/calls/$callId",
    ];
    for (const to of records) expect(paths, to).toContain(to);
  });

  it("give every team role the overview, the MCP servers, the gateways, the service accounts and settings, editors and above usage, and platform staff who aren't members the same", () => {
    const all = ["Overview", "MCP servers", "Gateways", "Service accounts", "Usage", "Team settings"];
    for (const role of ["owner", "admin", "editor"] as const) {
      expect(teamNavFor(meFor("none", role), team.slug).map((n) => n.label)).toEqual(all);
    }
    expect(teamNavFor(meFor("none", "member"), team.slug).map((n) => n.label)).toEqual(all.filter((l) => l !== "Usage"));
    expect(teamNavFor(meFor("platform_auditor", null), team.slug).map((n) => n.label)).toEqual(all);
    // Neither a member nor staff: nothing (the team page says "Team not found").
    expect(teamNavFor(meFor("none", null), team.slug)).toEqual([]);
  });

  it("works out team access like the server: managers, editors, an archived team and staff", () => {
    const me = meFor("none", "owner");
    expect(teamAccess(me, myTeam("owner"))).toEqual({ member: true, canEdit: true, isManager: true, staff: false, canReadUsage: true });
    expect(teamAccess(me, myTeam("editor"))).toMatchObject({ canEdit: true, isManager: false });
    expect(teamAccess(me, myTeam("member"))).toMatchObject({ canEdit: false, isManager: false });
    expect(teamAccess(me, myTeam("member"))).toMatchObject({ canReadUsage: false });
    expect(teamAccess(me, myTeam("admin", { status: "archived" }))).toMatchObject({ canEdit: false, isManager: false, canReadUsage: true });
    expect(teamAccess(meFor("platform_admin", null), undefined)).toEqual({ member: false, canEdit: false, isManager: false, staff: true, canReadUsage: false });
  });

  it("groups the admin pages and finds the current page's group", () => {
    // Overview is first and has no group.
    expect(adminSections.map((s) => s.label)).toEqual([undefined, "People", "Catalog", "Access", "Records", "Operations"]);
    expect(activeAdminGroup("/admin/automation-tokens")).toBe("Access");
    expect(activeAdminGroup("/admin/notifications")).toBe("Operations");
    expect(activeAdminGroup("/admin/usage")).toBe("Records");
    expect(activeAdminGroup("/admin/calls/501")).toBe("Records");
    expect(activeAdminGroup("/admin/limits")).toBe("Operations");
    expect(activeAdminGroup("/admin/retention")).toBe("Operations");
    expect(activeAdminGroup("/admin/capture")).toBe("Operations");
    expect(activeAdminGroup("/admin/gateways/abc")).toBe("Access");
    expect(activeAdminGroup("/admin/trusted-clients")).toBe("Access");
    expect(activeAdminGroup("/admin/auth-providers/abc")).toBe("Access");
    expect(activeAdminGroup("/admin/calls")).toBe("Records");
    expect(activeAdminGroup("/admin/users/abc")).toBe("People");
    expect(activeAdminGroup("/admin/servers/abc")).toBe("Catalog");
    expect(activeAdminGroup("/admin/publishing")).toBe("Catalog");
    expect(activeAdminGroup("/admin/audit")).toBe("Records");
    expect(activeAdminGroup("/admin")).toBeUndefined();
    expect(activeAdminGroup("/admin/")).toBeUndefined();
    expect(currentGroups(["Records", "Safety", "Records"])).toEqual(["Records"]);
  });
});

describe("breadcrumb helpers", () => {
  it("titles the page with the last two crumbs, most specific first", () => {
    // Home is the way back, not the page: a not-found page is titled by itself.
    expect(documentTitle([{ label: "Home" }, { label: "Page not found" }], "Open MCP Portal")).toBe("Page not found \u00b7 Open MCP Portal");
    expect(documentTitle([{ label: "Platform Tools" }, { label: "Team settings" }, { label: "Members" }], "Open MCP Portal")).toBe("Members · Team settings · Open MCP Portal");
    expect(documentTitle([{ label: "Home" }], "Open MCP Portal")).toBe("Home · Open MCP Portal");
  });

  it("collapses the middle of a long trail on a phone", () => {
    const trail = [{ label: "Admin" }, { label: "Teams" }, { label: "Platform Tools" }];
    expect(fitCrumbs(trail, false)).toBe(trail);
    const narrow = fitCrumbs(trail, true);
    expect(narrow.map((c) => c.label)).toEqual(["Admin", "Teams", "Platform Tools"]);
    expect(narrow[1]?.collapsed).toEqual([{ label: "Teams" }]);
  });
});

describe("workspace sidebar", () => {
  it("lists the workspace's pages, then the active team's, for a plain member", async () => {
    mockApi(shellRoutes("none", "member"));
    renderApp(`/teams/${team.slug}`);
    const nav = await screen.findByRole("navigation", { name: "Main" });
    await waitFor(() => expect(within(nav).getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page"));
    expect(within(nav).getAllByRole("link").map((l) => l.textContent)).toEqual(["Home", "Catalog", "My gateways", "Overview", "MCP servers", "Gateways", "Service accounts", "Team settings"]);
    expect(within(nav).getByRole("link", { name: "Service accounts" })).toHaveAttribute("href", `/teams/${team.slug}/service-accounts`);
    expect(within(nav).getByRole("link", { name: "Gateways" })).toHaveAttribute("href", `/teams/${team.slug}/gateways`);
    expect(within(nav).getByRole("link", { name: "MCP servers" })).toHaveAttribute("href", `/teams/${team.slug}/servers`);
    expect(within(nav).getByRole("link", { name: "Team settings" })).toHaveAttribute("href", `/teams/${team.slug}/settings`);
  });

  it("remembers the last team for the sidebar on other pages", async () => {
    mockApi({ ...shellRoutes(), "GET /v1/me": () => ({ ...meFor(), teams: [myTeam("member", { slug: "alpha", name: "Alpha", id: "a" }), myTeam("owner")] }) });
    const { router } = renderApp(`/teams/${team.slug}`);
    await screen.findByRole("heading", { level: 1, name: team.name });
    await router.navigate({ to: "/" });
    await screen.findByRole("heading", { level: 1, name: "Welcome, Una" });
    expect(screen.getByRole("button", { name: /Current workspace:\s*Platform Tools/ })).toBeInTheDocument();
    expect(localStorage.getItem("omp.lastTeam")).toBe(team.slug);
  });
});
