/* Home (your teams, the admin card for platform staff) and Profile. */
import { screen, within } from "@testing-library/react";
import { axe } from "vitest-axe";
import { meFor, myTeam, team } from "./fixtures";
import { mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

describe("home", () => {
  it("lists your teams with your role and quick links", async () => {
    mockApi({ ...shellRoutes(), "GET /v1/me": () => ({ ...meFor(), teams: [myTeam("owner"), myTeam("member", { id: "t2", slug: "data", name: "Data Team", status: "archived" })] }) });
    const { container } = renderApp("/");
    const teams = await screen.findByRole("list", { name: "Your teams" });
    const rows = within(teams).getAllByRole("listitem");
    expect(rows[0]).toHaveTextContent("Platform ToolsOwner");
    expect(rows[1]).toHaveTextContent("Data TeamMemberArchived");
    expect(within(rows[0]!).getByRole("link", { name: "Platform Tools: team settings" })).toHaveAttribute("href", `/teams/${team.slug}/settings`);
    expect(screen.queryByText("Platform administration")).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("gives platform staff the way into Admin", async () => {
    mockApi(shellRoutes("platform_auditor"));
    renderApp("/");
    expect(await screen.findByText("Platform administration")).toBeInTheDocument();
    expect(screen.getByText("See users, teams, MCP servers and the audit log, read-only.")).toBeInTheDocument();
    const card = screen.getByText("Platform administration").closest("section")!;
    expect(within(card).getByRole("link", { name: "MCP servers" })).toHaveAttribute("href", "/admin/servers");
    expect(screen.getByRole("link", { name: /Open Admin/ })).toHaveAttribute("href", "/admin");
  });
});

describe("home without a team", () => {
  it("offers the catalog", async () => {
    mockApi(shellRoutes("none", null));
    const { container } = renderApp("/");
    expect(await screen.findByRole("link", { name: "Browse the catalog" })).toHaveAttribute("href", "/catalog");
    expect(await axe(container)).toHaveNoViolations();
  });
});

describe("profile", () => {
  it("shows who you are, your platform role and your teams", async () => {
    mockApi(shellRoutes("platform_admin"));
    const { container } = renderApp("/settings/profile");
    expect(await screen.findByRole("heading", { level: 1, name: "Profile" })).toBeInTheDocument();
    const you = screen.getByRole("heading", { name: "You" }).closest("section")!;
    expect(within(you).getByText("una@example.com")).toBeInTheDocument();
    expect(within(you).getByText("Platform admin")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: team.name })).toHaveAttribute("href", `/teams/${team.slug}`);
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toHaveTextContent("Profile");
    const groups = screen.getByRole("heading", { name: "Your groups" }).closest("section")!;
    expect(groups).toHaveTextContent("From your identity provider");
    expect(within(within(groups).getByRole("list", { name: "Your groups" })).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["everyone", "engineering"]);
    expect(within(groups).queryByRole("button")).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("says when the identity provider sent no groups", async () => {
    mockApi({ ...shellRoutes("none"), "GET /v1/me": () => ({ ...meFor("none"), groups: [] }) });
    renderApp("/settings/profile");
    expect(await screen.findByText("Your identity provider didn't send any groups.")).toBeInTheDocument();
  });

  it("explains how to join a team when you have none", async () => {
    mockApi(shellRoutes("none", null));
    renderApp("/settings/profile");
    expect(await screen.findByText(/You aren't on a team yet\. To join a team, ask one of its owners/)).toBeInTheDocument();
  });
});
