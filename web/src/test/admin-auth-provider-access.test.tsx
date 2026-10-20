/*
 * Who may use an auth provider (decision 69, H-5): Admin → Auth providers' list flags providers that are open to
 * every team, and a record's Access tab shows the mode, the listed teams and servers and the servers the list blocks,
 * saved as a whole with If-Match (platform admins; auditors read). A server's requirement picker asks for the
 * providers open to its team; My connections says whether a token holds every granted scope; the connect page says
 * when the provider's list excluded the server.
 */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { mcpServer, page, serverId, team } from "./fixtures";
import { authProvider, connection, preset, providerAccess, providerId, providerSummaries, serverRequirement } from "./fixtures-providers";
import { type Call, type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

const base = "/v1/admin/auth-providers";
const record = `/admin/auth-providers/${providerId}`;
const puts = (calls: Call[]) => calls.filter((c) => c.method === "PUT" && c.url === `${base}/${providerId}/access`);

const routes = (role: "platform_admin" | "platform_auditor", access = providerAccess(), extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes(role, null),
  [`GET ${base}`]: () => [authProvider({ accessMode: access.accessMode })],
  [`GET ${base}/${providerId}`]: () => authProvider({ accessMode: access.accessMode }),
  [`GET ${base}/${providerId}/access`]: () => access,
  "GET /v1/admin/auth-provider-presets": () => [preset()],
  "GET /v1/admin/mcp-servers": () => page([mcpServer()]),
  "GET /v1/admin/teams": () => page([]),
  ...extra,
});

describe("Admin → Auth providers › Access", () => {
  it("flags a provider that is open to every team in the list and on its record", async () => {
    mockApi(routes("platform_admin", providerAccess({ accessMode: "open" })));
    renderApp("/admin/auth-providers");
    const table = await screen.findByRole("table", { name: "Auth providers" });
    const row = (await within(table).findByRole("link", { name: "GitHub" })).closest("tr")!;
    expect(row).toHaveTextContent("Open to every team");
  });

  it("shows who is listed, saves the whole list with If-Match, and says what taking a team off does", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", providerAccess(), { [`PUT ${base}/${providerId}/access`]: (body) => ({ ...providerAccess(), ...(body as object), teams: [], revision: 3 }) }));
    const { container } = renderApp(`${record}?tab=access`);
    expect(await screen.findByRole("radio", { name: /Restricted/ })).toBeChecked();
    expect(screen.queryByText(/Any editor of any team can require/)).toBeNull();
    // The listed team and server are shown by name.
    const teams = await screen.findByRole("combobox", { name: "Teams" });
    expect(teams).toBeInTheDocument();
    expect(screen.getByText("Platform tools")).toBeInTheDocument();
    expect(screen.getByText("Wiki")).toBeInTheDocument();
    expect(screen.getByText(/stops receiving tokens on the next call/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();

    // Removing the team is a change to save.
    await u.click(within(screen.getByLabelText("Listed teams")).getByRole("button", { name: "Remove Platform tools" }));
    await u.click(await screen.findByRole("button", { name: "Save access" }));
    await waitFor(() => expect(puts(calls)).toHaveLength(1));
    expect(puts(calls)[0]!.headers.get("If-Match")).toBe('"2"');
    expect(puts(calls)[0]!.body).toEqual({ accessMode: "restricted", teamIds: [], serverIds: ["50505050-5050-4505-8505-505050505050"] });
  });

  it("warns that an open provider is open to every team, and opens or restricts it", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", providerAccess({ accessMode: "open", teams: [], servers: [] })));
    renderApp(`${record}?tab=access`);
    expect(await screen.findByText(/Any editor of any team can require GitHub on their servers/)).toBeInTheDocument();
    await u.click(screen.getByRole("radio", { name: /Restricted/ }));
    expect(await screen.findByText(/Nobody is listed, so no team or server can require GitHub yet/)).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Save access" }));
    await waitFor(() => expect(puts(calls)).toHaveLength(1));
    expect(puts(calls)[0]!.body).toEqual({ accessMode: "restricted", teamIds: [], serverIds: [] });
  });

  it("lists the servers the list blocks, which still require the provider", async () => {
    mockApi(
      routes(
        "platform_admin",
        providerAccess({
          blockedCount: 3,
          blocked: [
            { id: "60606060-6060-4606-8606-606060606060", slug: "crm", name: "CRM", teamSlug: "sales", teamName: "Sales" },
            { id: "70707070-7070-4707-8707-707070707070", slug: "mail", name: "Mail", teamSlug: "sales", teamName: "Sales" },
          ],
        }),
      ),
    );
    renderApp(`${record}?tab=access`);
    expect(await screen.findByText("3 servers can't use GitHub")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "sales / crm" })).toHaveAttribute("href", "/admin/servers/60606060-6060-4606-8606-606060606060");
    expect(screen.getByText("and 1 more.")).toBeInTheDocument();
  });

  it("lets an auditor read the list but not change it", async () => {
    mockApi(routes("platform_auditor"));
    renderApp(`${record}?tab=access`);
    expect(await screen.findByRole("radio", { name: /Restricted/ })).toBeChecked();
    expect(screen.getByRole("radio", { name: /Restricted/ })).toHaveAttribute("aria-disabled", "true");
    expect(screen.queryByRole("button", { name: "Save access" })).toBeNull();
  });

  it("starts a new provider restricted, and says so", async () => {
    mockApi(routes("platform_admin"));
    renderApp("/admin/auth-providers?form=new");
    const custom = await screen.findByRole("radio", { name: /Custom OAuth 2.0 provider/ });
    await userEvent.setup().click(custom);
    await userEvent.setup().click(screen.getByRole("button", { name: "Continue" }));
    expect(await screen.findByText(/A new provider is restricted: no team or server may require it until you list them under Access/)).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "Narrow tokens per call" })).not.toBeChecked();
  });
});

describe("narrowing and the server pages", () => {
  it("sends narrowOnRefresh with the provider's settings, pre-filled only where the preset documents it", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", providerAccess(), { [`PATCH ${base}/${providerId}`]: (body) => authProvider({ ...(body as object), revision: 3 }) }));
    renderApp(`${record}?tab=settings`);
    const narrow = await screen.findByRole("switch", { name: "Narrow tokens per call" });
    expect(narrow).not.toBeChecked();
    await u.click(narrow);
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH" && c.url === `${base}/${providerId}`)).toBe(true));
    expect(calls.find((c) => c.method === "PATCH")!.body).toMatchObject({ narrowOnRefresh: true });
  });

  it("asks for the providers open to the server's team, and says when the one it has is not", async () => {
    const withGithub = mcpServer({ requirement: serverRequirement() });
    const calls = mockApi({
      ...shellRoutes("none", "editor"),
      [`GET /v1/teams/${team.slug}/mcp-servers`]: () => page([withGithub]),
      [`GET /v1/teams/${team.slug}/mcp-servers/${serverId}`]: () => withGithub,
      [`GET /v1/teams/${team.slug}/mcp-servers/${serverId}/capabilities`]: () => [],
      [`GET /v1/teams/${team.slug}/mcp-servers/${serverId}/health-checks`]: () => [],
      // The team's list leaves GitHub out, though the server still requires it.
      "GET /v1/auth-providers": (_, call) => (call.search.get("team") ? providerSummaries.slice(1) : providerSummaries),
    });
    renderApp(`/teams/${team.slug}/servers/${serverId}?tab=settings`);
    expect(await screen.findByText(/GitHub isn't open to this team/)).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "GitHub (not open to this team)" })).toBeInTheDocument();
    const asked = calls.find((c) => c.method === "GET" && c.url === "/v1/auth-providers" && c.search.get("team"));
    expect(asked?.search.get("team")).toBe(team.slug);
    expect(asked?.search.get("serverId")).toBe(serverId);
  });

  it("says on My connections whether a token holds every granted scope", async () => {
    mockApi({
      ...shellRoutes("none", "member"),
      "GET /v1/me/connections": () => [connection(), connection({ id: "c2", narrowsScopes: true, refreshable: true })],
      "GET /v1/auth-providers": () => providerSummaries,
    });
    renderApp("/settings/connections");
    const table = await screen.findByRole("table", { name: "Your connected accounts" });
    expect(await within(table).findByText("All granted scopes")).toBeInTheDocument();
    expect(within(table).getByText("Each call gets a token for only the scopes it needs")).toBeInTheDocument();
  });

  it("explains a connect that the provider's list excluded", async () => {
    mockApi({ ...shellRoutes("none", "member"), "GET /v1/auth-providers": () => providerSummaries, "GET /v1/me/connections": () => [] });
    renderApp("/connect/done?provider=github&result=not_allowed");
    expect(await screen.findByRole("heading", { level: 1, name: "Connected to GitHub, but the server can't use it" })).toBeInTheDocument();
    expect(screen.getByText(/add the team or server to the provider's access list/)).toBeInTheDocument();
  });

  it("is refused by the server, field by field", async () => {
    const u = userEvent.setup();
    const withGithub = mcpServer({ requirement: serverRequirement() });
    mockApi({
      ...shellRoutes("none", "editor"),
      [`GET /v1/teams/${team.slug}/mcp-servers/${serverId}`]: () => withGithub,
      [`GET /v1/teams/${team.slug}/mcp-servers`]: () => page([withGithub]),
      [`GET /v1/teams/${team.slug}/mcp-servers/${serverId}/capabilities`]: () => [],
      [`GET /v1/teams/${team.slug}/mcp-servers/${serverId}/health-checks`]: () => [],
      "GET /v1/auth-providers": () => providerSummaries,
      [`PATCH /v1/teams/${team.slug}/mcp-servers/${serverId}`]: () => Reply.error(422, "provider_not_allowed", "no"),
    });
    renderApp(`/teams/${team.slug}/servers/${serverId}?tab=settings`);
    await u.type(await screen.findByRole("textbox", { name: /Scopes/ }), "read:org{Enter}");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText(/This provider isn't open to this team/)).toBeInTheDocument();
  });
});
