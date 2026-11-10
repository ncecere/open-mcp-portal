/* The team pages: the overview by role, Team settings' Members (roles, add, invites, leave), Audit log and General. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { auditEntry, invite, meFor, member, members, page, team } from "./fixtures";
import { type Handler, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const base = `/v1/teams/${team.slug}`;
const routes = (platformRole: Schemas["PlatformRole"] = "none", teamRole: Schemas["TeamRole"] | null = "owner", extra: Record<string, Handler> = {}) => ({
  ...shellRoutes(platformRole, teamRole),
  [`GET ${base}/audit`]: () => page([auditEntry()]),
  ...extra,
});

describe("team overview", () => {
  it("shows editors and above the counts, the members and the recent changes", async () => {
    mockApi(routes("none", "owner"));
    const { container } = renderApp(`/teams/${team.slug}`);
    expect(await screen.findByRole("heading", { level: 1, name: team.name })).toBeInTheDocument();
    expect(screen.getByText(team.description)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Your role: Owner: what this role can do" })).toBeInTheDocument();
    // The stat card's label is its link; the card holds the number.
    const count = await screen.findByRole("link", { name: "Members" });
    expect(count).toHaveAttribute("href", `/teams/${team.slug}/settings`);
    expect(count.closest("dl")).toHaveTextContent("Members4");
    const list = screen.getByRole("list", { name: "Members" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(4);
    const recent = await screen.findByRole("list", { name: "Recent changes" });
    expect(within(recent).getByRole("link")).toHaveTextContent("Una User·Changed member role·Casey Editor");
    expect(within(recent).getByRole("link")).toHaveAttribute("href", `/teams/${team.slug}/settings?tab=audit&record=101`);
    expect(screen.getByRole("link", { name: "Add member" })).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows a member what their role can do instead of the audit log", async () => {
    const calls = mockApi(routes("none", "member"));
    const { container } = renderApp(`/teams/${team.slug}`);
    expect(await screen.findByRole("heading", { name: "Your role" })).toBeInTheDocument();
    expect(screen.getByText("Use the gateways granted to them")).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Recent changes" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Add member" })).toBeNull();
    expect(calls.some((c) => c.url.endsWith("/audit"))).toBe(false);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("says an archived team is read-only", async () => {
    mockApi(routes("none", "owner", { [`GET ${base}`]: (): Schemas["TeamView"] => ({ team: { ...team, status: "archived" }, role: "owner" }) }));
    renderApp(`/teams/${team.slug}`);
    expect(await screen.findByText("This team is archived")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Add member" })).toBeNull();
  });
});

describe("Team settings › Members", () => {
  it("lets an admin change roles below owner, and shows the only owner's reason", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes("none", "admin", {
        "GET /v1/me": () => ({ ...meFor("none", "admin"), user: { ...meFor().user, id: "33333333-3333-4333-8333-333333333333" } }),
        [`PATCH ${base}/members/44444444-4444-4444-8444-444444444444`]: () => member("admin"),
      }),
    );
    const { container } = renderApp(`/teams/${team.slug}/settings`);
    const table = await screen.findByRole("table", { name: "Team members" });
    await within(table).findByText("Casey Editor");
    // An admin can't change the owner, or make anyone an owner.
    expect(within(table).queryByRole("combobox", { name: "Role for Una User" })).toBeNull();
    const select = within(table).getByRole("combobox", { name: "Role for Casey Editor" });
    expect(within(select).getAllByRole("option").map((o) => o.textContent)).toEqual(["Admin", "Editor", "Member"]);
    expect(await axe(container)).toHaveNoViolations();
    await u.selectOptions(select, "admin");
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ role: "admin" }));
    expect(calls.find((c) => c.method === "PATCH")?.headers.get("If-Match")).toBe('"1"');
  });

  it("asks before making someone an owner", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("none", "owner", { [`PATCH ${base}/members/44444444-4444-4444-8444-444444444444`]: () => member("owner") }));
    renderApp(`/teams/${team.slug}/settings`);
    const table = await screen.findByRole("table", { name: "Team members" });
    await u.selectOptions(await within(table).findByRole("combobox", { name: "Role for Casey Editor" }), "owner");
    const ask = await screen.findByRole("alertdialog", { name: "Make Casey Editor an owner?" });
    expect(calls.some((c) => c.method === "PATCH")).toBe(false);
    await u.click(within(ask).getByRole("button", { name: "Make owner" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ role: "owner" }));
  });

  it("explains the only owner can't be changed or leave", async () => {
    const u = userEvent.setup();
    mockApi(routes("none", "owner"));
    renderApp(`/teams/${team.slug}/settings`);
    const table = await screen.findByRole("table", { name: "Team members" });
    expect(await within(table).findByText("The only owner. Make someone else an owner to change this.")).toBeInTheDocument();
    await u.click(within(table).getByRole("button", { name: "Actions for Una User" }));
    expect(await screen.findByRole("menuitem", { name: /Leave team/ })).toHaveAttribute("aria-disabled", "true");
  });

  it("adds a member by email and says when they were invited instead", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("none", "owner", { [`POST ${base}/members`]: (): Schemas["MemberAddResult"] => ({ status: "invited", invite: invite({ email: "new@example.com" }) }) }));
    renderApp(`/teams/${team.slug}/settings`);
    await u.click(await screen.findByRole("button", { name: "Add member" }));
    const dialog = await screen.findByRole("dialog", { name: "Add member" });
    await u.click(within(dialog).getByRole("button", { name: "Add member" }));
    expect(await within(dialog).findByText("Enter an email address.")).toBeInTheDocument();
    await u.type(within(dialog).getByRole("textbox", { name: "Email address" }), "new@example.com");
    await u.selectOptions(within(dialog).getByRole("combobox", { name: "Role" }), "editor");
    await u.click(within(dialog).getByRole("button", { name: "Add member" }));
    expect(await within(dialog).findByText("Invite created")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ email: "new@example.com", role: "editor" });
  });

  it("lists open invites for managers, and members see the list read-only without invites", async () => {
    mockApi(routes("none", "owner"));
    const { unmount } = renderApp(`/teams/${team.slug}/settings`);
    expect(await screen.findByText(invite().email)).toBeInTheDocument();
    unmount();

    const calls = mockApi(routes("none", "member"));
    renderApp(`/teams/${team.slug}/settings`);
    expect(await screen.findByText("Members can view the team's members. Admins and owners can add, change and remove them.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add member" })).toBeNull();
    expect(screen.queryByRole("tab", { name: /Audit log/ })).toBeNull();
    expect(calls.some((c) => c.url.endsWith("/invites"))).toBe(false);
  });
});

describe("Team settings › Audit log", () => {
  it("lists the team's entries with a simple change and opens one", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("none", "editor"));
    const { container } = renderApp(`/teams/${team.slug}/settings?tab=audit`);
    const table = await screen.findByRole("table", { name: "Audit log" });
    const row = (await within(table).findByText("Changed member role")).closest("tr")!;
    expect(row).toHaveTextContent("Role Member → Editor");
    expect(await axe(container)).toHaveNoViolations();
    await u.click(within(row).getByText("Changed member role"));
    expect(await screen.findByRole("heading", { level: 1, name: "Changed member role" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "What changed: Changed member role" })).toHaveTextContent("RoleMemberEditor");
    expect(calls.some((c) => c.url === `${base}/audit` && c.search.get("limit") === "50")).toBe(true);
  });

  it("opens a linked entry by id", async () => {
    mockApi(routes("none", "owner", { [`GET ${base}/audit`]: () => page([]), [`GET ${base}/audit/101`]: () => auditEntry() }));
    renderApp(`/teams/${team.slug}/settings?tab=audit&record=101`);
    expect(await screen.findByRole("heading", { level: 1, name: "Changed member role" })).toBeInTheDocument();
  });
});

describe("Team settings › General", () => {
  it("is read-only for team owners, who can leave unless they're the only owner", async () => {
    mockApi(routes("none", "owner", { [`GET ${base}/members`]: () => [member("owner"), { ...members[1]!, role: "owner" }] }));
    const { container } = renderApp(`/teams/${team.slug}/settings?tab=general`);
    expect(await screen.findByText("Platform admins rename teams. Ask one if something here needs to change.")).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Name" })).toBeNull();
    await waitFor(() => expect(screen.getByRole("button", { name: "Leave team" })).toBeEnabled());
    expect(screen.queryByRole("button", { name: "Archive team" })).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("lets platform admins rename the team through the admin API, with If-Match", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", null, { [`PATCH /v1/admin/teams/${team.slug}`]: () => ({ team, memberCount: 4, ownerCount: 1, ownerInvites: 0 }) }));
    renderApp(`/teams/${team.slug}/settings?tab=general`);
    const name = await screen.findByRole("textbox", { name: "Name" });
    await u.clear(name);
    await u.type(name, "Tools");
    await u.click(screen.getByRole("button", { name: /Save/ }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ name: "Tools", description: team.description }));
    expect(calls.find((c) => c.method === "PATCH")?.headers.get("If-Match")).toBe(`"${team.revision}"`);
    expect(screen.getByRole("button", { name: "Archive team" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Leave team" })).toBeNull();
  });
});
