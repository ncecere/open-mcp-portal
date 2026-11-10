/* Admin → Auth providers: the list, adding one from a preset (with URL parameters) or custom, the record's redirect URI, Settings (If-Match, the replace-only secret, confirmations), Delete (409 in_use), and auditors reading. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { emptyForm, endpointProblem, parseParams, providerProblems } from "../pages/admin/providers/form";
import { mcpServer, page } from "./fixtures";
import { authProvider, presets, providerId } from "./fixtures-providers";
import { type Call, type Handler, Reply, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const base = "/v1/admin/auth-providers";
const record = `/admin/auth-providers/${providerId}`;
const patches = (calls: Call[]) => calls.filter((c) => c.method === "PATCH" && c.url === `${base}/${providerId}`);

const routes = (role: "platform_admin" | "platform_auditor" = "platform_admin", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes(role, null),
  [`GET ${base}`]: () => [authProvider(), authProvider({ id: "p2", slug: "slack", name: "Slack", preset: "slack", enabled: false, serverCount: 0, connectionCount: 0 })],
  [`GET ${base}/${providerId}`]: () => authProvider(),
  "GET /v1/admin/auth-provider-presets": () => presets,
  "GET /v1/admin/mcp-servers": () => page([mcpServer()]),
  ...extra,
});

describe("Admin → Auth providers", () => {
  it("lists providers with their preset, switch, servers and connections", async () => {
    mockApi(routes());
    const { container } = renderApp("/admin/auth-providers");
    expect(await screen.findByRole("heading", { level: 1, name: "Auth providers" })).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Auth providers" });
    const github = (await within(table).findByRole("link", { name: "GitHub" })).closest("tr")!;
    expect(github).toHaveTextContent("github · GitHub preset");
    expect(github).toHaveTextContent("Enabled");
    expect(within(github).getByRole("link", { name: "1 server" })).toHaveAttribute("href", `/admin/servers?provider=${providerId}`);
    const slack = within(table).getByText("Slack").closest("tr")!;
    expect(slack).toHaveTextContent("Disabled");
    expect(slack).toHaveTextContent("None");
    await waitFor(() => expect(document.title).toBe("Auth providers · Admin · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("adds a provider from a preset, filling its URL parameters, and opens its record", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", { [`POST ${base}`]: (body) => new Reply(201, { data: authProvider({ ...(body as object), id: providerId }) }) }));
    const { router } = renderApp("/admin/auth-providers");
    await u.click(await screen.findByRole("button", { name: "Add auth provider" }));
    await u.click(await screen.findByRole("radio", { name: /Microsoft Entra ID/ }));
    const tenant = await screen.findByRole("textbox", { name: "Directory (tenant) ID, or organizations" });
    expect(tenant).toHaveValue("organizations");
    await u.clear(tenant);
    await u.type(tenant, "contoso.onmicrosoft.com");
    await u.click(screen.getByRole("button", { name: "Continue" }));

    expect(await screen.findByRole("heading", { name: "Add Microsoft Entra ID" })).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Authorization URL" })).toHaveValue("https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize");
    expect(screen.getByText("Add offline_access for refresh tokens.")).toBeInTheDocument();
    expect(screen.getByText(`${window.location.origin}/connect/callback`)).toBeInTheDocument();
    // Required: the client ID and (with a secret-based method) the secret.
    await u.click(screen.getByRole("button", { name: "Add provider" }));
    expect(await screen.findByText(/Enter the client ID of the OAuth app/)).toBeInTheDocument();
    expect(screen.getByText(/Enter the OAuth app's client secret/)).toBeInTheDocument();
    await u.type(screen.getByRole("textbox", { name: "Client ID" }), "app-123");
    await u.type(screen.getByLabelText("Client secret"), "s3cret-value");
    await u.click(screen.getByRole("button", { name: "Add provider" }));

    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url === base)).toBe(true));
    const body = calls.find((c) => c.method === "POST" && c.url === base)!.body as Schemas["AuthProviderCreate"];
    expect(body).toMatchObject({
      slug: "microsoft",
      name: "Microsoft Entra ID",
      preset: "microsoft",
      clientId: "app-123",
      clientSecret: "s3cret-value",
      tokenUrl: "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token",
      defaultScopes: ["openid", "offline_access", "User.Read"],
      pkce: true,
    });
    await waitFor(() => expect(router.state.location.pathname).toBe(record));
  });

  it("shows the server's refusals on their fields (a taken slug, an endpoint, a reserved parameter)", async () => {
    const u = userEvent.setup();
    let reply = Reply.error(409, "slug_taken", "taken");
    mockApi(routes("platform_admin", { [`POST ${base}`]: () => reply }));
    renderApp("/admin/auth-providers?form=new");
    await u.click(await screen.findByRole("radio", { name: /Custom OAuth 2.0 provider/ }));
    await u.click(screen.getByRole("button", { name: "Continue" }));
    await u.type(await screen.findByRole("textbox", { name: "Name" }), "Internal SSO");
    await u.type(screen.getByRole("textbox", { name: "Slug" }), "internal");
    await u.type(screen.getByRole("textbox", { name: "Client ID" }), "abc");
    await u.selectOptions(screen.getByRole("combobox", { name: "Token endpoint authentication" }), "none");
    await u.type(screen.getByRole("textbox", { name: "Authorization URL" }), "https://sso.example.com/authorize");
    await u.type(screen.getByRole("textbox", { name: "Token URL" }), "https://sso.example.com/token");
    await u.click(screen.getByRole("button", { name: "Add provider" }));
    expect(await screen.findByText("Another provider uses this slug. Choose another.")).toBeInTheDocument();
    reply = Reply.error(422, "url_not_allowed", "no", { field: "tokenUrl", reason: "private_address" });
    await u.type(screen.getByRole("textbox", { name: "Slug" }), "-2");
    await u.click(screen.getByRole("button", { name: "Add provider" }));
    expect(await screen.findByText(/internal \(private\) address until its network is allowed/)).toBeInTheDocument();
  });

  it("shows the redirect URI to register, with a copy button, and the configuration without the secret", async () => {
    mockApi(routes());
    const { container } = renderApp(record);
    expect(await screen.findByRole("heading", { level: 1, name: "GitHub" })).toBeInTheDocument();
    expect(screen.getAllByText("https://mcp.example.com/connect/callback").length).toBeGreaterThan(0);
    expect(screen.getByRole("button", { name: /Copy redirect URI/ })).toBeInTheDocument();
    expect(screen.getByText("Stored, ends in 9f2e")).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe("GitHub · Auth providers · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("keeps the client secret replace-only: never shown, sent only when typed, with If-Match", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", { [`PATCH ${base}/${providerId}`]: (body) => authProvider({ ...(body as object), revision: 3 }) }));
    renderApp(`${record}?tab=settings`);
    const secret = await screen.findByLabelText("Replace client secret");
    expect(secret).toHaveValue("");
    expect(secret).toHaveAttribute("type", "password");
    expect(screen.getByText(/The stored secret ends in 9f2e. Leave empty to keep it/)).toBeInTheDocument();

    await u.clear(screen.getByRole("textbox", { name: "Name" }));
    await u.type(screen.getByRole("textbox", { name: "Name" }), "GitHub.com");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(1));
    expect(patches(calls)[0]!.headers.get("If-Match")).toBe('"2"');
    expect(patches(calls)[0]!.body).not.toHaveProperty("clientSecret");
    expect(patches(calls)[0]!.body).toMatchObject({ name: "GitHub.com", revocationUrl: null });

    await u.type(screen.getByLabelText("Replace client secret"), "new-secret-1234");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(2));
    expect(patches(calls)[1]!.body).toMatchObject({ clientSecret: "new-secret-1234" });
    await waitFor(() => expect(screen.getByLabelText("Replace client secret")).toHaveValue(""));
  });

  it("asks before a new client ID disconnects people", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", { [`PATCH ${base}/${providerId}`]: (body) => authProvider({ ...(body as object), revision: 3 }) }));
    renderApp(`${record}?tab=settings`);
    const id = await screen.findByRole("textbox", { name: "Client ID" });
    await u.clear(id);
    await u.type(id, "Iv1.new");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    const ask = await screen.findByRole("alertdialog", { name: "Save GitHub?" });
    expect(ask).toHaveTextContent("A new client ID disconnects 3 people");
    expect(patches(calls)).toHaveLength(0);
    await u.click(within(ask).getByRole("button", { name: "Save provider" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(1));
  });

  it("names the servers that still require it before Delete is tried, when the record counts some", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes("platform_admin", {
        [`GET ${base}/${providerId}`]: () => authProvider({ serverCount: 2 }),
        "GET /v1/admin/mcp-servers": () => page([mcpServer({ id: "s1", slug: "github-tools" }), mcpServer({ id: "s2", slug: "issues" })]),
      }),
    );
    renderApp(`${record}?tab=settings`);
    await u.click(await screen.findByRole("button", { name: "Delete provider" }));
    const ask = await screen.findByRole("alertdialog", { name: "Delete GitHub?" });
    expect(within(ask).getByText(/2 servers still require GitHub, so it can't be deleted/)).toBeInTheDocument();
    expect(await within(ask).findByRole("link", { name: "platform-tools / github-tools" })).toHaveAttribute("href", "/admin/servers/s1");
    expect(within(ask).getByRole("link", { name: "platform-tools / issues" })).toBeInTheDocument();
    expect(calls.some((c) => c.method === "GET" && c.url === "/v1/admin/mcp-servers" && c.search.get("provider") === providerId)).toBe(true);
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    expect(await axe(ask)).toHaveNoViolations();
  });

  it("names the servers that still require it when Delete is refused (409 in_use)", async () => {
    const u = userEvent.setup();
    const servers = [{ id: "s1", slug: "github-tools", teamSlug: "platform-tools" }];
    mockApi(routes("platform_admin", { [`DELETE ${base}/${providerId}`]: () => Reply.error(409, "in_use", "in use", { serverCount: 3, servers }) }));
    renderApp(`${record}?tab=settings`);
    await u.click(await screen.findByRole("button", { name: "Delete provider" }));
    const ask = await screen.findByRole("alertdialog", { name: "Delete GitHub?" });
    await u.click(within(ask).getByRole("button", { name: "Delete provider" }));
    expect(await within(ask).findByText(/3 servers still require GitHub, so it can't be deleted/)).toBeInTheDocument();
    expect(within(ask).getByRole("link", { name: "platform-tools / github-tools" })).toHaveAttribute("href", "/admin/servers/s1");
    expect(within(ask).getByRole("link", { name: "See all 3 servers" })).toHaveAttribute("href", `/admin/servers?provider=${providerId}`);
    expect(await axe(ask)).toHaveNoViolations();
  });

  it("deletes a provider no server requires and returns to the list", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", { [`GET ${base}/${providerId}`]: () => authProvider({ serverCount: 0 }), [`DELETE ${base}/${providerId}`]: () => ({ ok: true }) }));
    const { router } = renderApp(`${record}?tab=settings`);
    await u.click(await screen.findByRole("button", { name: "Delete provider" }));
    await u.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Delete provider" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/admin/auth-providers"));
    expect(calls.some((c) => c.method === "DELETE")).toBe(true);
  });

  it("is read-only for auditors", async () => {
    mockApi(routes("platform_auditor"));
    const { container } = renderApp(`${record}?tab=settings`);
    expect(await screen.findByText("You can view these settings. Only platform admins can change them.")).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Name" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Delete provider" })).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });
});

describe("command palette (admin)", () => {
  it("lists Auth providers and Add auth provider for platform admins", async () => {
    const u = userEvent.setup();
    mockApi(routes());
    const { router } = renderApp("/admin/auth-providers");
    await screen.findByRole("heading", { level: 1, name: "Auth providers" });
    await u.keyboard("{Control>}k{/Control}");
    const dialog = await screen.findByRole("dialog", { name: "Command palette" });
    await u.type(within(dialog).getByRole("combobox", { name: "Command palette" }), "add auth provider");
    await u.keyboard("{Enter}");
    await waitFor(() => expect(router.state.location.search).toMatchObject({ form: "new" }));
    expect(await screen.findByRole("radio", { name: /GitHub/ })).toBeInTheDocument();
  });
});

describe("provider form checks", () => {
  it("refuses reserved and malformed extra parameters", () => {
    expect(parseParams("access_type=offline\nprompt=consent", "scope")).toEqual({ params: { access_type: "offline", prompt: "consent" } });
    expect(parseParams("state=x", "scope").problem).toMatch(/sets “state” itself/);
    expect(parseParams("user_scope=x", "user_scope").problem).toMatch(/sets “user_scope” itself/);
    expect(parseParams("novalue", "scope").problem).toMatch(/key=value/);
    expect(parseParams("a=1\na=2", "scope").problem).toMatch(/listed twice/);
  });

  it("keeps the connect pages' names free", () => {
    const f = { ...emptyForm, name: "X", clientId: "x", authorizationUrl: "https://a.example.com/a", tokenUrl: "https://a.example.com/t" };
    const opts = { creating: true, secret: "s", hasSecret: false, dev: false };
    expect(providerProblems({ ...f, slug: "done" }, opts).slug).toMatch(/connect pages/);
    expect(providerProblems({ ...f, slug: "callback" }, opts).slug).toMatch(/connect pages/);
    expect(providerProblems({ ...f, slug: "github" }, opts)).toEqual({});
  });

  it("checks endpoints like server URLs", () => {
    expect(endpointProblem("https://github.com/login/oauth/authorize", true, false)).toBeUndefined();
    expect(endpointProblem("", true, false)).toMatch(/Enter the address/);
    expect(endpointProblem("", false, false)).toBeUndefined();
    expect(endpointProblem("https://login.microsoftonline.com/{tenant}/x", true, false)).toMatch(/Fill in the part in braces/);
    expect(endpointProblem("ftp://x.example.com", true, false)).toMatch(/https/);
    expect(endpointProblem("http://localhost:9000/token", true, false)).toMatch(/https/);
    expect(endpointProblem("http://localhost:9000/token", true, true)).toBeUndefined();
    expect(endpointProblem("https://u:p@x.example.com", true, false)).toMatch(/user name/);
  });
});
