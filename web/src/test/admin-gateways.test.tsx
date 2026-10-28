/* Admin → Gateways (filters, platform gateways, grants, a team gateway's switch) and Admin → Calls. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { gateway, gatewayCapabilities, gatewayCapability, gatewayId, gatewayOptions, optionsPage, grant, mcpCall, mcpServer, myGateway, page, platformGateway, team, teamSummary, user } from "./fixtures";
import { type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

type Staff = "platform_admin" | "platform_auditor";
const one = `/v1/admin/gateways/${gatewayId}`;

const routes = (role: Staff = "platform_admin", g = platformGateway(), extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes(role, null),
  "GET /v1/admin/mcp-servers": () => page([mcpServer()]),
  "GET /v1/admin/gateways": () => page([g, gateway({ id: "g2", name: "Support tools", slug: "support-tools" })]),
  [`GET ${one}`]: () => g,
  [`GET ${one}/capabilities`]: () => gatewayCapabilities([gatewayCapability({ minRole: null })]),
  [`GET ${one}/grants`]: () => [grant(), grant({ id: "g-user", subjectKind: "user", team: undefined, user: { id: user().id, email: user().email, displayName: user().displayName, status: "active" } }), grant({ id: "g-group", subjectKind: "group", team: undefined, group: "engineering" })],
  "GET /v1/admin/gateway-options": (_b, call) => optionsPage(gatewayOptions.filter((o) => o.source === "catalog"), call.search),
  "GET /v1/admin/teams": () => page([teamSummary()]),
  "GET /v1/admin/users": () => page([user()]),
  "GET /v1/admin/calls": () => page([mcpCall()]),
  // Staff use only what they're granted: none of these by default.
  "GET /v1/me/gateways": () => [],
  ...extra,
});

describe("Admin → Gateways", () => {
  it("lists every gateway with its owner, filters on the server, and offers platform admins Create", async () => {
    const calls = mockApi(routes());
    const { container } = renderApp("/admin/gateways?ownerKind=platform&team=platform-tools");
    const table = await screen.findByRole("table", { name: "Gateways" });
    const row = (await within(table).findByText("Company tools")).closest("tr")!;
    expect(row).toHaveTextContent("Platform");
    expect(row).toHaveTextContent("2 grants");
    expect(within(row).getByRole("link", { name: "Company tools" })).toHaveAttribute("href", `/admin/gateways/${gatewayId}`);
    expect(screen.getByRole("button", { name: "Create platform gateway" })).toBeInTheDocument();
    await waitFor(() => expect(calls.some((c) => c.url === "/v1/admin/gateways" && c.search.get("ownerKind") === "platform" && c.search.get("team") === "platform-tools")).toBe(true));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("gives auditors no Create", async () => {
    mockApi(routes("platform_auditor"));
    renderApp("/admin/gateways");
    await within(await screen.findByRole("table", { name: "Gateways" })).findByText("Company tools");
    expect(screen.queryByRole("button", { name: "Create platform gateway" })).toBeNull();
  });

  it("creates a platform gateway through the admin API", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", platformGateway(), { "POST /v1/admin/gateways": () => new Reply(201, { data: platformGateway() }) }));
    renderApp("/admin/gateways?form=new");
    expect(await screen.findByRole("heading", { level: 1, name: "Create platform gateway" })).toBeInTheDocument();
    await u.type(screen.getByRole("textbox", { name: "Name" }), "Company tools");
    await u.click(screen.getByRole("button", { name: "Create gateway" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toEqual({ slug: "company-tools", name: "Company tools", enabled: true, capturePayloads: false }));
    expect(await screen.findByRole("heading", { level: 1, name: "Company tools" })).toBeInTheDocument();
  });
});

describe("Admin → a platform gateway › header and Overview", () => {
  it("names the grants in the header: none, one or more", async () => {
    mockApi(routes("platform_admin", platformGateway({ grantCount: 0 })));
    const { unmount } = renderApp(`/admin/gateways/${gatewayId}`);
    expect(await screen.findByRole("heading", { level: 1, name: "Company tools" })).toBeInTheDocument();
    expect(await screen.findByText("No grants")).toBeInTheDocument();
    unmount();
    mockApi(routes("platform_admin", platformGateway({ grantCount: 1 })));
    renderApp(`/admin/gateways/${gatewayId}`);
    expect(await screen.findByText("1 grant")).toBeInTheDocument();
  });

  it("tells a platform admin who isn't granted it who can connect, without snippets", async () => {
    mockApi(routes());
    const { container } = renderApp(`/admin/gateways/${gatewayId}`);
    expect(await screen.findByText("You can't connect to this gateway yourself.")).toBeInTheDocument();
    expect(await screen.findByText(/Only the teams, people and SSO groups it's granted to can connect \(teams: Platform Tools; people: Una User; SSO groups: engineering\)/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "See its access" })).toHaveAttribute("href", expect.stringContaining("tab=access"));
    expect(screen.queryByRole("textbox", { name: "Name in your client" })).toBeNull();
    expect(screen.queryByText(/claude mcp add/)).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("says nobody can connect to a platform gateway granted to no one", async () => {
    mockApi(routes("platform_admin", platformGateway({ grantCount: 0 }), { [`GET ${one}/grants`]: () => [] }));
    renderApp(`/admin/gateways/${gatewayId}`);
    expect(await screen.findByText(/It isn't granted to anyone yet, so nobody can connect/)).toBeInTheDocument();
  });

  it("shows the snippets to a platform admin it's granted to", async () => {
    const mine = myGateway({ ownerKind: "platform", slug: "company-tools", name: "Company tools", teamSlug: undefined, teamName: undefined, access: ["user_grant"] });
    mockApi(routes("platform_admin", platformGateway(), { "GET /v1/me/gateways": () => [mine] }));
    renderApp(`/admin/gateways/${gatewayId}`);
    expect(await screen.findByRole("textbox", { name: "Name in your client" })).toHaveValue("company-tools");
    expect(screen.queryByText("You can't connect to this gateway yourself.")).toBeNull();
  });
});

describe("Admin → a platform gateway › Access", () => {
  it("lists grants to teams, people and groups, and explains what they cover", async () => {
    mockApi(routes());
    const { container } = renderApp(`/admin/gateways/${gatewayId}?tab=access`);
    const table = await screen.findByRole("table", { name: "Grants" });
    expect(await within(table).findByText(team.name)).toBeInTheDocument();
    expect(within(table).getByText("Una User")).toBeInTheDocument();
    expect(within(table).getByText("engineering")).toBeInTheDocument();
    expect(screen.getByText(/A team grant covers everyone on the team now, and people who join later/)).toBeInTheDocument();
    expect(screen.getByText(/uses the groups claim your identity provider sends at sign-in/)).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe("Access · Company tools · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("adds a team, a person by email and an SSO group, and says when a person is unknown", async () => {
    const u = userEvent.setup();
    let unknown = true;
    const calls = mockApi(
      routes("platform_admin", platformGateway(), {
        [`POST ${one}/grants`]: (body) => {
          const b = body as { subjectKind: string };
          if (b.subjectKind === "user" && unknown) return Reply.error(404, "subject_not_found", "No such user");
          return new Reply(201, { data: grant() });
        },
      }),
    );
    renderApp(`/admin/gateways/${gatewayId}?tab=access`);
    await u.click(await screen.findByRole("button", { name: "Add grant" }));
    let dialog = await screen.findByRole("dialog", { name: "Grant access to Company tools" });
    // A team grant covers the team's service accounts too (decision 23).
    expect(dialog).toHaveTextContent("Everyone on the team, including people who join later, and the team's service accounts.");
    await u.selectOptions(await within(dialog).findByRole("combobox", { name: "Team" }), team.slug);
    await u.click(within(dialog).getByRole("button", { name: "Grant access" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "POST").at(-1)?.body).toEqual({ subjectKind: "team", team: team.slug, toolScope: null }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Grant access to Company tools" })).toBeNull());

    await u.click(screen.getByRole("button", { name: "Add grant" }));
    dialog = await screen.findByRole("dialog", { name: "Grant access to Company tools" });
    await u.click(within(dialog).getByRole("radio", { name: /A person/ }));
    await u.type(within(dialog).getByRole("textbox", { name: "Email" }), "nobody@example.com");
    await u.click(within(dialog).getByRole("button", { name: "Grant access" }));
    expect(await within(dialog).findByText("Nobody with this email has signed in yet.")).toBeInTheDocument();
    unknown = false;
    await u.click(within(dialog).getByRole("radio", { name: /An SSO group/ }));
    await u.type(within(dialog).getByRole("textbox", { name: "Group name" }), "engineering");
    await u.click(within(dialog).getByRole("button", { name: "Grant access" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "POST").at(-1)?.body).toEqual({ subjectKind: "group", group: "engineering", toolScope: null }));
  });

  it("removes a grant after confirming; auditors only read", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", platformGateway(), { [`DELETE ${one}/grants/g-group`]: () => ({ ok: true }) }));
    const { unmount } = renderApp(`/admin/gateways/${gatewayId}?tab=access`);
    await u.click(await screen.findByRole("button", { name: "Actions for engineering" }));
    await u.click(await screen.findByRole("menuitem", { name: "Remove…" }));
    const ask = await screen.findByRole("alertdialog", { name: "Remove access for engineering?" });
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    await u.click(within(ask).getByRole("button", { name: "Remove access" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url === `${one}/grants/g-group`)).toBe(true));
    unmount();

    mockApi(routes("platform_auditor"));
    renderApp(`/admin/gateways/${gatewayId}?tab=access`);
    await within(await screen.findByRole("table", { name: "Grants" })).findByText("engineering");
    expect(screen.queryByRole("button", { name: "Add grant" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Actions for engineering" })).toBeNull();
  });

  it("picks only catalog capabilities, without minimum roles", async () => {
    const u = userEvent.setup();
    mockApi(routes());
    renderApp(`/admin/gateways/${gatewayId}?tab=capabilities`);
    await u.click(await screen.findByRole("button", { name: "Edit selection" }));
    await u.click(await screen.findByRole("checkbox", { name: "wiki__search" }));
    expect(screen.queryByRole("combobox", { name: /Who may use/ })).toBeNull();
    expect(screen.queryByRole("checkbox", { name: "service-status__restart" })).toBeNull();
  });
});

describe("Admin → a team gateway", () => {
  const teamGateway = gateway();

  it("is read-only except the switch, which asks before turning it off", async () => {
    const u = userEvent.setup();
    let current = teamGateway;
    const calls = mockApi(routes("platform_admin", teamGateway, { [`GET ${one}`]: () => current, [`PATCH ${one}`]: () => (current = gateway({ enabled: false, revision: 8 })) }));
    renderApp(`/admin/gateways/${gatewayId}?tab=settings`);
    expect(await screen.findByRole("textbox", { name: "Name" })).toBeDisabled();
    // One notice says who changes it and that the switch is here (not a second one from Settings).
    expect(screen.getAllByText(/This gateway belongs to Platform Tools.*You can switch it off here/)).toHaveLength(1);
    expect(screen.queryByText(/This is a team gateway/)).toBeNull();
    expect(screen.queryByText(/You can view these settings/)).toBeNull();
    expect(screen.queryByRole("tab", { name: /Access/ })).toBeNull();
    await u.click(screen.getByRole("button", { name: "Disable gateway" }));
    const ask = await screen.findByRole("alertdialog", { name: "Disable Support tools?" });
    await u.click(within(ask).getByRole("button", { name: "Disable gateway" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ enabled: false }));
    expect(calls.find((c) => c.method === "PATCH")?.headers.get("If-Match")).toBe('"7"');
    expect(await screen.findByRole("button", { name: "Enable gateway" })).toBeInTheDocument();
  });

  it("tells staff who aren't on the team that only its members connect", async () => {
    mockApi(routes("platform_auditor", teamGateway));
    renderApp(`/admin/gateways/${gatewayId}`);
    expect(await screen.findByText("You can't connect to this gateway yourself.")).toBeInTheDocument();
    expect(screen.getByText(/Only members of Platform Tools can connect to it/)).toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Name in your client" })).toBeNull();
  });

  it("gives auditors no switch and no capability editing", async () => {
    const u = userEvent.setup();
    mockApi(routes("platform_auditor", teamGateway));
    renderApp(`/admin/gateways/${gatewayId}?tab=capabilities`);
    expect(await screen.findByRole("heading", { level: 1, name: "Support tools" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /able gateway/ })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit selection" })).toBeNull();
    await u.click(screen.getByRole("tab", { name: /Activity/ }));
    expect(await within(await screen.findByRole("table", { name: "Calls" })).findByText("service-status__get_status")).toBeInTheDocument();
  });
});

describe("Admin → Calls", () => {
  it("says in words why calls were refused or failed, never the raw class", async () => {
    mockApi(
      routes("platform_admin", platformGateway(), {
        "GET /v1/admin/calls": () =>
          page([
            mcpCall({ id: 1, outcome: "denied", errorClass: "unknown", exposedName: "nope__x" }),
            mcpCall({ id: 2, outcome: "denied", errorClass: "gateway_disabled", exposedName: "off__x" }),
            mcpCall({ id: 3, outcome: "denied", errorClass: "team_archived", exposedName: "arch__x" }),
            mcpCall({ id: 4, outcome: "upstream_error", errorClass: "rate_limited", exposedName: "busy__x" }),
            mcpCall({ id: 5, outcome: "upstream_error", errorClass: "brand_new_class", exposedName: "new__x" }),
          ]),
      }),
    );
    renderApp("/admin/calls");
    const table = await screen.findByRole("table", { name: "Calls" });
    const row = async (name: string) => (await within(table).findByText(name)).closest("tr")!;
    expect(await row("nope__x")).toHaveTextContent("DeniedNot offered by the gateway");
    expect(await row("off__x")).toHaveTextContent("Gateway turned off");
    expect(await row("arch__x")).toHaveTextContent("Team archived");
    expect(await row("busy__x")).toHaveTextContent("Rate limited by the server");
    expect(await row("new__x")).toHaveTextContent("Brand new class");
    expect(within(table).getByText("Gateway turned off")).toHaveAttribute("title", "Recorded as gateway_disabled");
    for (const raw of ["unknown", "gateway_disabled", "team_archived", "rate_limited", "brand_new_class"]) expect(within(table).queryByText(raw)).toBeNull();
  });

  it("lists every call with its gateway and server, and filters on the server", async () => {
    const calls = mockApi(routes());
    const { container } = renderApp(`/admin/calls?gateway=${gatewayId}&outcome=upstream_error&team=platform-tools&person=${user().id}`);
    const table = await screen.findByRole("table", { name: "Calls" });
    const row = (await within(table).findByText("service-status__get_status")).closest("tr")!;
    expect(within(row).getByRole("link", { name: "Support tools" })).toHaveAttribute("href", `/admin/gateways/${gatewayId}`);
    expect(row).toHaveTextContent("OK");
    expect(screen.getByText(/Arguments and results are kept only for gateways and servers that record call contents/)).toBeInTheDocument();
    await waitFor(() =>
      expect(
        calls.some(
          (c) =>
            c.url === "/v1/admin/calls" &&
            c.search.get("gateway") === gatewayId &&
            c.search.get("outcome") === "upstream_error" &&
            c.search.get("team") === "platform-tools" &&
            c.search.get("user") === user().id,
        ),
      ).toBe(true),
    );
    expect(await axe(container)).toHaveNoViolations();
  });
});
