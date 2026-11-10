/* The app shell: landmarks, the team switcher, the workspace/admin portal switch, breadcrumbs and the command palette. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { authConfig, meFor, page, team, teamSummary, user } from "./fixtures";
import { mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const adminRoutes = {
  "GET /v1/admin/users": () => page([user()]),
  "GET /v1/admin/teams": () => page([teamSummary()]),
  "GET /v1/admin/audit": () => page([]),
};

describe("app shell", () => {
  it("has landmarks, a skip link, the team switcher and the portal switch, and no axe violations", async () => {
    mockApi(shellRoutes("platform_admin"));
    const { container } = renderApp("/");

    expect(await screen.findByRole("heading", { level: 1, name: "Welcome, Una" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Skip to content" })).toHaveAttribute("href", "#main");
    expect(screen.getByRole("main")).toHaveAttribute("id", "main");
    expect(screen.getByRole("navigation", { name: "Breadcrumb" }).closest("header")).not.toBeNull();
    expect(screen.getByRole("button", { name: "Collapse sidebar" })).toHaveAttribute("aria-expanded", "true");

    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Home" })).toHaveAttribute("aria-current", "page");
    // Workspace mode is the plain user experience: no admin pages in the sidebar.
    expect(within(nav).queryByRole("link", { name: "Users" })).toBeNull();
    const portal = screen.getByRole("navigation", { name: "Portal" });
    expect(within(portal).getByRole("link", { name: "Workspace" })).toHaveAttribute("aria-current", "page");
    expect(within(portal).getByRole("link", { name: "Admin" })).not.toHaveAttribute("aria-current");
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toHaveTextContent("Home");
    expect(screen.getByRole("button", { name: /Current workspace:\s*Platform Tools/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Account:\s*Una User/ })).toBeInTheDocument();
    expect(document.title).toBe("Home · Open MCP Portal");

    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows the instance's name from the auth config", async () => {
    mockApi({ ...shellRoutes(), "GET /v1/auth/config": () => authConfig({ instance: { name: "Acme Tools Hub", orgName: "Acme", theme: "neutral", logoUrl: null, supportUrl: null } }) });
    renderApp("/");
    await screen.findByRole("heading", { level: 1, name: "Welcome, Una" });
    await waitFor(() => expect(document.title).toBe("Home · Acme Tools Hub"));
    expect(screen.getByText(/Acme Tools Hub is where your teams register/)).toBeInTheDocument();
  });

  it("gives someone without a team a friendly explanation, their own initials and a team request only when configured", async () => {
    mockApi(shellRoutes("none", null));
    const first = renderApp("/");
    expect(await screen.findByRole("heading", { level: 1, name: "Welcome, Una" })).toBeInTheDocument();
    expect(screen.getByText("You aren't on a team yet.")).toBeInTheDocument();
    expect(screen.getByText(/Teams own the MCP servers and gateways people connect to/)).toBeInTheDocument();
    // Without a request form or help link: ask a platform admin.
    expect(screen.getByText(/To join a team, ask one of its owners to add you\. Not sure who\? Ask a platform admin\./)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Request a new team" })).toBeNull();
    const switcher = screen.getByRole("button", { name: /Current workspace:\s*Una User/ });
    expect(switcher).toHaveTextContent("UU");
    expect(switcher).toHaveTextContent("No team yet");
    // No team section in the sidebar, and no admin card.
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).queryByRole("link", { name: "Overview" })).toBeNull();
    expect(screen.queryByText("Platform administration")).toBeNull();
    expect(await axe(first.container)).toHaveNoViolations();
    first.unmount();

    mockApi({ ...shellRoutes("none", null), "GET /v1/auth/config": () => authConfig({ teamRequestUrl: "https://help.example.com/new-team" }) });
    renderApp("/");
    expect(await screen.findByRole("link", { name: "Request a new team" })).toHaveAttribute("href", "https://help.example.com/new-team");
  });

  it("hides the portal switch and admin pages from people without a platform role, and refuses the admin portal", async () => {
    mockApi(shellRoutes("none"));
    const { router } = renderApp("/");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(within(nav).queryByRole("link", { name: "Users" })).toBeNull();
    expect(screen.queryByRole("navigation", { name: "Portal" })).toBeNull();
    await router.navigate({ href: "/admin/users" });
    expect(await screen.findByRole("heading", { level: 1, name: "No access" })).toBeInTheDocument();
  });

  it("switches platform admins between the workspace and admin portals, returning to the last page in each", async () => {
    const u = userEvent.setup();
    mockApi({ ...shellRoutes("platform_admin"), ...adminRoutes });
    const { router, container } = renderApp(`/teams/${team.slug}/settings`);
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(await within(nav).findByRole("link", { name: "Team settings" })).toHaveAttribute("aria-current", "page");

    const portal = screen.getByRole("navigation", { name: "Portal" });
    await u.click(within(portal).getByRole("link", { name: "Admin" }));
    // The admin portal opens on the Overview, the first item of the sidebar (it has no group).
    await waitFor(() => expect(router.state.location.pathname).toBe("/admin"));
    await waitFor(() => expect(within(portal).getByRole("link", { name: "Admin" })).toHaveAttribute("aria-current", "page"));
    expect(await within(nav).findByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
    await u.click(within(nav).getByRole("button", { name: "People" }));
    await u.click(await within(nav).findByRole("link", { name: "Users" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/admin/users"));
    expect(await within(nav).findByRole("link", { name: "Users" })).toHaveAttribute("aria-current", "page");
    // The current page's group is open; the newer groups (Access, Records) start open; the others collapse to their headers.
    expect(within(nav).getByRole("button", { name: "People" })).toHaveAttribute("aria-expanded", "true");
    expect(within(nav).getByRole("button", { name: "Access" })).toHaveAttribute("aria-expanded", "true");
    const records = within(nav).getByRole("button", { name: "Records" });
    expect(records).toHaveAttribute("aria-expanded", "true");
    expect(within(nav).getByRole("link", { name: "Audit log" })).toBeInTheDocument();
    const catalog = within(nav).getByRole("button", { name: "Catalog" });
    expect(catalog).toHaveAttribute("aria-expanded", "false");
    await u.click(catalog);
    expect(within(nav).getByRole("link", { name: "Publishing" })).toBeInTheDocument();
    await u.click(records);
    expect(records).toHaveAttribute("aria-expanded", "false");
    expect(screen.queryByRole("button", { name: /Current workspace/ })).toBeNull();
    expect(screen.getByText("All teams and settings")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();

    await u.click(within(nav).getByRole("link", { name: "Teams" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/admin/teams"));

    await u.click(within(portal).getByRole("link", { name: "Workspace" }));
    await waitFor(() => expect(router.state.location.pathname).toBe(`/teams/${team.slug}/settings`));
    await u.click(within(portal).getByRole("link", { name: "Admin" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/admin/teams"));
    // Only groups opened or closed by hand are remembered.
    expect(JSON.parse(localStorage.getItem("omp.adminNavOpen") ?? "[]")).toEqual(["People", "Catalog"]);
    expect(JSON.parse(localStorage.getItem("omp.adminNavClosed") ?? "[]")).toEqual(["Records"]);
    expect(within(nav).getByRole("button", { name: "Records" })).toHaveAttribute("aria-expanded", "false");
  });

  it("shows the team breadcrumb and a read-only admin badge for auditors", async () => {
    mockApi({ ...shellRoutes("platform_auditor"), ...adminRoutes });
    const { router } = renderApp(`/teams/${team.slug}/settings?tab=audit`);
    const crumbs = await screen.findByRole("navigation", { name: "Breadcrumb" });
    await waitFor(() => expect(crumbs).toHaveTextContent("Platform Tools"));
    await waitFor(() => expect(crumbs).toHaveTextContent("Team settings"));
    expect(crumbs).toHaveTextContent("Audit log");
    await waitFor(() => expect(document.title).toBe("Audit log · Team settings · Open MCP Portal"));

    await router.navigate({ href: "/admin/audit" });
    expect(await screen.findByText("Read-only")).toBeInTheDocument();
    expect(await screen.findByRole("heading", { level: 1, name: "Audit log" })).toBeInTheDocument();
  });

  it("shows platform staff who aren't members the team's overview and settings", async () => {
    mockApi({ ...shellRoutes("platform_admin", null), ...adminRoutes });
    const { container } = renderApp(`/teams/${team.slug}`);
    expect(await screen.findByRole("heading", { level: 1, name: team.name })).toBeInTheDocument();
    expect(screen.getByText("You're viewing this team as platform staff")).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
    expect(within(nav).getByRole("link", { name: "Team settings" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Current workspace:\s*Platform Tools/ })).toHaveTextContent("Viewing as platform staff");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows the not-found page for an unknown address and an unknown team", async () => {
    mockApi(shellRoutes());
    const { router } = renderApp("/nowhere");
    expect(await screen.findByRole("heading", { level: 1, name: "Page not found" })).toBeInTheDocument();
    await router.navigate({ href: "/teams/missing" });
    expect(await screen.findByRole("heading", { level: 1, name: "Team not found" })).toBeInTheDocument();
  });

  it("signs out from the account menu", async () => {
    const u = userEvent.setup();
    const calls = mockApi({ ...shellRoutes(), "POST /auth/logout": () => ({ ok: true }) });
    const assign = vi.fn();
    vi.stubGlobal("location", { ...window.location, assign, origin: "http://localhost", pathname: "/", search: "" });
    renderApp("/");
    await screen.findByRole("heading", { level: 1, name: "Welcome, Una" });
    await u.click(screen.getByRole("button", { name: /Account:\s*Una User/ }));
    await u.click(await screen.findByRole("menuitem", { name: "Sign out" }));
    await waitFor(() => expect(assign).toHaveBeenCalledWith("/"));
    const logout = calls.find((c) => c.url === "/auth/logout");
    expect(logout?.headers.get("X-CSRF-Token")).toBe("csrf-123");
  });
});

describe("command palette", () => {
  it("opens with Ctrl+K and navigates to a team", async () => {
    const u = userEvent.setup();
    mockApi(shellRoutes());
    const { router } = renderApp("/");
    await screen.findByRole("heading", { level: 1, name: "Welcome, Una" });

    await u.keyboard("{Control>}k{/Control}");
    const dialog = await screen.findByRole("dialog", { name: "Command palette" });
    await u.type(within(dialog).getByRole("combobox", { name: "Command palette" }), "Platform Tools");
    await u.keyboard("{Enter}");

    await waitFor(() => expect(router.state.location.pathname).toBe(`/teams/${team.slug}`));
    expect(await screen.findByRole("heading", { level: 1, name: team.name })).toBeInTheDocument();
  });

  it("runs a quick action: Add member opens the dialog in Team settings", async () => {
    const u = userEvent.setup();
    mockApi(shellRoutes());
    const { router } = renderApp(`/teams/${team.slug}`);
    await screen.findByRole("heading", { level: 1, name: team.name });

    await u.click(screen.getByRole("button", { name: /Search or jump to/ }));
    const dialog = await screen.findByRole("dialog", { name: "Command palette" });
    await u.type(within(dialog).getByRole("combobox", { name: "Command palette" }), "add member");
    await u.keyboard("{Enter}");

    await waitFor(() => expect(router.state.location.pathname).toBe(`/teams/${team.slug}/settings`));
    expect(await screen.findByRole("dialog", { name: "Add member" })).toBeInTheDocument();
  });

  it("lists admin pages for platform staff only", async () => {
    const u = userEvent.setup();
    mockApi({ ...shellRoutes("none"), "GET /v1/me": () => meFor("none") });
    renderApp("/");
    await screen.findByRole("heading", { level: 1, name: "Welcome, Una" });
    await u.keyboard("{Control>}k{/Control}");
    const dialog = await screen.findByRole("dialog", { name: "Command palette" });
    await u.type(within(dialog).getByRole("combobox", { name: "Command palette" }), "audit");
    // The team's audit log (an owner), not the platform's.
    expect(within(dialog).getByRole("option", { name: /Audit log/ })).toHaveTextContent("Team settings");
    expect(within(dialog).queryByText("Admin")).toBeNull();
  });
});
