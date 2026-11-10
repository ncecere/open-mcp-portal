/* Admin → Users and Teams: server facets, the user page (platform role, suspend), creating a team, and a team's tabs. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { auditEntry, invite, member, myTeam, page, team, teamPublishing, teamSummary, user } from "./fixtures";
import { type Handler, Reply, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const other = user({ id: "77777777-7777-4777-8777-777777777777", email: "pat@example.com", displayName: "Pat Admin", platformRole: "platform_admin", teamCount: 2 });
const detail: Schemas["UserDetail"] = { user: other, teams: [myTeam("editor")] };

const routes = (role: "platform_admin" | "platform_auditor" = "platform_admin", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes(role),
  "GET /v1/admin/users": () => page([other]),
  [`GET /v1/admin/users/${other.id}`]: () => detail,
  "GET /v1/admin/teams": () => page([teamSummary()]),
  [`GET /v1/admin/teams/${team.slug}`]: () => teamSummary(),
  "GET /v1/admin/audit": () => page([]),
  [`GET /v1/teams/${team.slug}/audit`]: () => page([auditEntry()]),
  [`GET /v1/admin/teams/${team.slug}/publishing`]: () => teamPublishing(),
  ...extra,
});

describe("Admin → Users", () => {
  it("filters users by role and search on the server and shows team counts", async () => {
    const calls = mockApi(routes());
    const { container } = renderApp("/admin/users?role=platform_admin&q=pat");
    const table = await screen.findByRole("table", { name: "Users" });
    const row = (await within(table).findByText("Pat Admin")).closest("tr")!;
    expect(row).toHaveTextContent("Platform admin");
    expect(row).toHaveTextContent("2");
    await waitFor(() => expect(calls.some((c) => c.url === "/v1/admin/users" && c.search.get("role") === "platform_admin" && c.search.get("q") === "pat")).toBe(true));
    expect(within(row).getByRole("link", { name: "Pat Admin" })).toHaveAttribute("href", `/admin/users/${other.id}`);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("asks before changing a platform role, naming what it can do, and sends If-Match", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", { [`PATCH /v1/admin/users/${other.id}`]: () => ({ ...other, platformRole: "platform_auditor", revision: 2 }) }));
    const { container } = renderApp(`/admin/users/${other.id}`);
    expect(await screen.findByRole("heading", { level: 1, name: "Pat Admin" })).toBeInTheDocument();
    const teams = screen.getByRole("table", { name: "Team memberships" });
    expect(within(teams).getByRole("link", { name: team.name })).toHaveAttribute("href", `/admin/teams/${team.slug}`);
    expect(await axe(container)).toHaveNoViolations();

    await u.selectOptions(screen.getByRole("combobox", { name: "Platform role" }), "platform_auditor");
    const dialog = await screen.findByRole("alertdialog", { name: "Make Pat Admin a platform auditor?" });
    expect(dialog).toHaveTextContent("can't change anything");
    await u.click(within(dialog).getByRole("button", { name: "Make auditor" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ platformRole: "platform_auditor" }));
    expect(calls.find((c) => c.method === "PATCH")?.headers.get("If-Match")).toBe('"1"');
  });

  it("suspends after confirming", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", { [`PATCH /v1/admin/users/${other.id}`]: () => ({ ...other, status: "suspended" }) }));
    renderApp(`/admin/users/${other.id}`);
    await screen.findByRole("heading", { level: 1, name: "Pat Admin" });
    await u.click(screen.getByRole("button", { name: "More actions" }));
    await u.click(await screen.findByRole("menuitem", { name: "Suspend…" }));
    const ask = await screen.findByRole("alertdialog", { name: "Suspend Pat Admin?" });
    // What stops, and that reactivating brings it back.
    expect(ask).toHaveTextContent("their connected apps, their API keys and their access to teams and gateways stop working");
    expect(ask).toHaveTextContent("Reactivating restores them");
    await u.click(within(ask).getByRole("button", { name: "Suspend" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ status: "suspended" }));
  });

  it("is read-only for auditors", async () => {
    mockApi(routes("platform_auditor"));
    renderApp(`/admin/users/${other.id}`);
    await screen.findByRole("heading", { level: 1, name: "Pat Admin" });
    expect(screen.getByRole("combobox", { name: "Platform role" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "More actions" })).toBeNull();
  });

  it("shows the not-found page for an unknown user", async () => {
    mockApi(routes());
    renderApp("/admin/users/88888888-8888-4888-8888-888888888888");
    expect(await screen.findByRole("heading", { level: 1, name: "User not found" })).toBeInTheDocument();
  });
});

describe("Admin → Teams", () => {
  it("lists teams with members and owners, and says Owner invited rather than No owner", async () => {
    const invited = teamSummary({ team: { ...team, id: "t2", slug: "data", name: "Data Team" }, memberCount: 0, ownerCount: 0, ownerInvites: 1 });
    const orphan = teamSummary({ team: { ...team, id: "t3", slug: "orphan", name: "Orphan Team" }, memberCount: 2, ownerCount: 0, ownerInvites: 0 });
    mockApi(routes("platform_admin", { "GET /v1/admin/teams": () => page([teamSummary(), invited, orphan]) }));
    const { container } = renderApp("/admin/teams");
    const table = await screen.findByRole("table", { name: "Teams" });
    expect((await within(table).findByText("Data Team")).closest("tr")).toHaveTextContent("Owner invited");
    expect(within(table).getByText("Orphan Team").closest("tr")).toHaveTextContent("No owner");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("creates a team with a suggested slug and its owner, and shows a taken slug on the field", async () => {
    const u = userEvent.setup();
    let taken = true;
    const calls = mockApi(
      routes("platform_admin", {
        "POST /v1/admin/teams": (): Schemas["TeamCreated"] | Reply =>
          taken ? Reply.error(409, "slug_taken", "Slug taken") : { team: teamSummary(), owner: { status: "invited", invite: invite({ email: "owner@example.com", role: "owner" }) } },
      }),
    );
    renderApp("/admin/teams");
    await u.click(await screen.findByRole("button", { name: "Create team" }));
    const dialog = await screen.findByRole("dialog", { name: "Create team" });
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "Platform Tools");
    expect(within(dialog).getByRole("textbox", { name: "Slug" })).toHaveValue("platform-tools");
    await u.type(within(dialog).getByRole("textbox", { name: "Owner's email" }), "owner@example.com");
    await u.click(within(dialog).getByRole("button", { name: "Create team" }));
    expect(await within(dialog).findByText("A team with this slug already exists. Choose another.")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ name: "Platform Tools", slug: "platform-tools", ownerEmail: "owner@example.com" });

    taken = false;
    await u.clear(within(dialog).getByRole("textbox", { name: "Slug" }));
    await u.type(within(dialog).getByRole("textbox", { name: "Slug" }), "platform-tools-2");
    await u.click(within(dialog).getByRole("button", { name: "Create team" }));
    expect(await within(dialog).findByText("owner@example.com was invited as owner.", { exact: false })).toBeInTheDocument();
  });

  it("offers no Create team to auditors", async () => {
    mockApi(routes("platform_auditor"));
    renderApp("/admin/teams");
    await screen.findByRole("table", { name: "Teams" });
    expect(screen.queryByRole("button", { name: "Create team" })).toBeNull();
  });

  it("shows a team's overview with counts and recent changes", async () => {
    mockApi(routes());
    const { container } = renderApp(`/admin/teams/${team.slug}`);
    expect(await screen.findByRole("heading", { level: 1, name: team.name })).toBeInTheDocument();
    expect(screen.getByRole("tablist", { name: "Team sections" })).toBeInTheDocument();
    expect(await screen.findByText("Changed member role: Casey Editor: Role Member → Editor")).toBeInTheDocument();
    expect(screen.getByText(team.description)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("lists members read-only, assigns an owner and revokes open invites", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes("platform_admin", {
        [`GET /v1/teams/${team.slug}/members`]: () => [member("owner")],
        [`GET /v1/teams/${team.slug}/invites`]: () => [invite({ role: "owner", email: "new.owner@example.com" })],
        [`DELETE /v1/teams/${team.slug}/invites/${invite().id}`]: () => ({ ok: true }),
        [`POST /v1/admin/teams/${team.slug}/owners`]: (): Schemas["MemberAddResult"] => ({ status: "added", member: member("owner") }),
      }),
    );
    const { container } = renderApp(`/admin/teams/${team.slug}?tab=members`);
    const table = await screen.findByRole("table", { name: "Members" });
    expect(await within(table).findByText("Una User")).toBeInTheDocument();
    expect(within(table).queryByRole("combobox")).toBeNull();
    const invites = (await screen.findByRole("heading", { name: "Open invites" })).closest("section")!;
    expect(within(invites).getByText("new.owner@example.com")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();

    await u.click(within(invites).getByRole("button", { name: "Revoke the invite for new.owner@example.com" }));
    await u.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Revoke invite" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url.endsWith(`/invites/${invite().id}`))).toBe(true));

    await u.click(screen.getByRole("button", { name: "Assign owner" }));
    const dialog = await screen.findByRole("dialog", { name: "Assign an owner" });
    await u.type(within(dialog).getByRole("combobox", { name: "New owner" }), "x@example.com");
    await u.click(await screen.findByRole("option", { name: /Invite x@example.com/ }));
    await u.click(within(dialog).getByRole("button", { name: "Assign owner" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST" && c.url.endsWith("/owners"))?.body).toEqual({ email: "x@example.com" }));
  });

  it("invites a dev persona's name@localhost as owner", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes("platform_admin", {
        "GET /v1/admin/users": () => page([]),
        [`POST /v1/admin/teams/${team.slug}/owners`]: (): Schemas["MemberAddResult"] => ({ status: "invited", invite: invite({ email: "alex@localhost", role: "owner" }) }),
      }),
    );
    renderApp(`/admin/teams/${team.slug}?tab=members`);
    await u.click(await screen.findByRole("button", { name: "Assign owner" }));
    const dialog = await screen.findByRole("dialog", { name: "Assign an owner" });
    await u.type(within(dialog).getByRole("combobox", { name: "New owner" }), "alex@localhost");
    await u.click(await screen.findByRole("option", { name: /Invite alex@localhost/ }));
    await u.click(within(dialog).getByRole("button", { name: "Assign owner" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ email: "alex@localhost" }));
  });

  it("saves a team's settings with If-Match and archives it from the Danger zone", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", { [`PATCH /v1/admin/teams/${team.slug}`]: () => teamSummary() }));
    renderApp(`/admin/teams/${team.slug}?tab=settings`);
    const name = await screen.findByRole("textbox", { name: "Name" });
    await u.clear(name);
    await u.type(name, "Platform Tooling");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ name: "Platform Tooling", description: team.description }));
    expect(calls.find((c) => c.method === "PATCH")?.headers.get("If-Match")).toBe(`"${team.revision}"`);

    await u.click(screen.getByRole("button", { name: "Archive team" }));
    await u.click(within(await screen.findByRole("alertdialog", { name: `Archive ${team.name}?` })).getByRole("button", { name: "Archive team" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PATCH").at(-1)?.body).toEqual({ status: "archived" }));
  });
});
