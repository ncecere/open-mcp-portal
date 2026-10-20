/*
 * The portal's own OAuth client for a server that authenticates the portal itself (decision 73,
 * docs/machine-oauth.md): the pure rules (what's wrong, what a save sends, what sends a published server back
 * to review, when the secret is entered again), Add, Settings and the Overview. The secret is replace-only:
 * it is never shown, and it is sent only when typed.
 */
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { type MachineConfig, type MachineForm, blankMachine, machineChanges, machineFormOf, machineInput, machineProblems, machineReview, secretWhy } from "../components/servers/machine-auth";
import { capabilities, healthCheck, mcpServer, page, serverId, team, teamPublishing } from "./fixtures";
import { detectResult } from "./fixtures-oauth";
import { type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

const base = `/v1/teams/${team.slug}/mcp-servers`;
const record = `/teams/${team.slug}/servers/${serverId}`;

const stored = (extra: Partial<MachineConfig> = {}): MachineConfig => ({
  tokenUrl: "https://login.example.com/oauth/token",
  clientIdHint: "ab12cd",
  hasClientSecret: true,
  clientSecretHint: "7890",
  tokenAuthMethod: "client_secret_basic",
  scopes: ["read"],
  audience: null,
  resource: "https://status.example.com/mcp",
  ...extra,
});

const machineServer = (extra: Partial<Schemas["McpServer"]> = {}, config: Partial<MachineConfig> = {}) =>
  mcpServer({ authMode: "machine_oauth", hasAuth: false, authHeaderName: undefined, authValueHint: "", credentials: [], machineOAuth: stored(config), ...extra });

const form = (extra: Partial<MachineForm> = {}): MachineForm => ({ ...machineFormOf(machineServer()), ...extra });

describe("machine OAuth (rules)", () => {
  it("asks for what the client needs before it is sent", () => {
    const none = { secret: "", url: "https://status.example.com/mcp" };
    expect(machineProblems("none", blankMachine, none)).toEqual({});
    const empty = machineProblems("machine_oauth", blankMachine, none);
    expect(Object.keys(empty).sort()).toEqual(["machineClientId", "machineSecret", "tokenUrl"]);
    expect(machineProblems("machine_oauth", { ...blankMachine, tokenUrl: "login.example.com", clientId: "c" }, { ...none, secret: "s" }).tokenUrl).toMatch(/full https address/);
    expect(machineProblems("machine_oauth", { ...blankMachine, tokenUrl: "https://login.example.com/t?x=1", clientId: "c" }, { ...none, secret: "s" }).tokenUrl).toMatch(/without a query/);
    expect(machineProblems("machine_oauth", { ...blankMachine, tokenUrl: "https://login.example.com/t", clientId: "c", resource: "nope" }, { ...none, secret: "s" }).machineResource).toMatch(/full address/);
    expect(machineProblems("machine_oauth", { ...blankMachine, tokenUrl: "https://login.example.com/t", clientId: "c", scopes: ["a b"] }, { ...none, secret: "s" }).machineScopes).toBeDefined();
    expect(machineProblems("machine_oauth", { ...blankMachine, tokenUrl: "https://login.example.com/t", clientId: "c", resource: "https://x.example/mcp" }, { ...none, secret: "s" })).toEqual({});
  });

  it("keeps a stored secret only while its token endpoint, client and server host stay (F-1)", () => {
    const server = machineServer();
    const ctx = (over: { secret?: string; url?: string } = {}) => ({ server, secret: over.secret ?? "", url: over.url ?? server.url });
    expect(machineProblems("machine_oauth", form(), ctx())).toEqual({});
    expect(machineProblems("machine_oauth", form({ tokenUrl: "https://other.example.com/token" }), ctx()).machineSecret).toMatch(/token endpoint changed/);
    expect(machineProblems("machine_oauth", form({ clientId: "another" }), ctx()).machineSecret).toMatch(/client ID changed/);
    expect(machineProblems("machine_oauth", form(), ctx({ url: "https://elsewhere.example.com/mcp" })).machineSecret).toMatch(/server's host changed/);
    expect(machineProblems("machine_oauth", form(), ctx({ url: "https://status.example.com/v2/mcp" }))).toEqual({});
    expect(machineProblems("machine_oauth", form({ tokenUrl: "https://other.example.com/token" }), ctx({ secret: "typed" }))).toEqual({});
    expect(secretWhy(form(), server.machineOAuth, { originMoved: false })).toBeUndefined();
    expect(secretWhy(form(), undefined, { originMoved: true })).toBeUndefined();
  });

  it("sends a whole client when new and only what changed when stored; the secret only when typed", () => {
    expect(machineInput({ ...blankMachine, tokenUrl: " https://login.example.com/token ", clientId: "c", scopes: ["read"], resource: "https://x.example/mcp" }, "s3cret")).toEqual({
      tokenUrl: "https://login.example.com/token",
      clientId: "c",
      clientSecret: "s3cret",
      tokenAuthMethod: "client_secret_basic",
      scopes: ["read"],
      resource: "https://x.example/mcp",
    });
    const s = stored();
    expect(machineChanges(form(), "", s)).toBeUndefined();
    expect(machineChanges(form({ scopes: ["read", "write"] }), "", s)).toEqual({ scopes: ["read", "write"] });
    expect(machineChanges(form({ tokenAuthMethod: "client_secret_post" }), "", s)).toEqual({ tokenAuthMethod: "client_secret_post" });
    expect(machineChanges(form(), "new-secret", s)).toEqual({ clientSecret: "new-secret" });
    expect(machineChanges(form({ resource: "", audience: "api://x" }), "", s)).toEqual({ resource: "", audience: "api://x" });
    expect(machineChanges(form({ tokenUrl: "https://other.example.com/token", clientId: "c2" }), "s", s)).toEqual({ tokenUrl: "https://other.example.com/token", clientId: "c2", clientSecret: "s" });
  });

  it("knows what sends a published server back to review", () => {
    const server = machineServer();
    expect(machineReview(server, form())).toBeUndefined();
    expect(machineReview(server, form({ scopes: ["read", "write"] }))).toBe("machine_scopes");
    expect(machineReview(server, form({ scopes: [] }))).toBeUndefined();
    expect(machineReview(server, form({ tokenUrl: "https://other.example.com/token" }))).toBe("machine_client");
    expect(machineReview(server, form({ clientId: "c2" }))).toBe("machine_client");
    expect(machineReview(server, form({ audience: "api://x" }))).toBe("machine_target");
    expect(machineReview(server, form({ resource: "" }))).toBe("machine_target");
    expect(machineReview(mcpServer(), form())).toBe("machine");
  });
});

const routes = (server = machineServer(), extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", "editor"),
  [`GET ${base}`]: () => page([server]),
  [`GET ${base}/${serverId}`]: () => server,
  [`GET ${base}/${serverId}/capabilities`]: () => capabilities,
  [`GET ${base}/${serverId}/health-checks`]: () => [healthCheck()],
  [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing({ effective: server.effectivePublishPolicy }),
  ...extra,
});

const machineOption = () => screen.getByRole("radio", { name: /^The portal's own OAuth client/ });

describe("Add MCP server: the portal's own OAuth client", () => {
  it("needs no detection, asks for the client, and sends the secret once", async () => {
    const u = userEvent.setup();
    const created: Schemas["McpServerCreated"] = { server: machineServer(), refresh: null, refreshError: null };
    const calls = mockApi(routes(machineServer(), { [`POST ${base}`]: () => new Reply(201, { data: created }) }));
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await u.type(await screen.findByRole("textbox", { name: "Name" }), "Orders API");
    await u.type(screen.getByRole("textbox", { name: "URL" }), "https://orders.example.com/mcp");
    expect(machineOption()).toBeEnabled();
    await u.click(machineOption());
    await u.click(screen.getByRole("button", { name: "Add server" }));
    expect(await screen.findByText("Enter the authorization server's token endpoint.")).toBeInTheDocument();
    expect(screen.getByText("Enter the client ID the authorization server gave the portal.")).toBeInTheDocument();
    expect(screen.getByText("Enter the client secret.")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST")).toBe(false);

    await u.type(screen.getByRole("textbox", { name: "Token endpoint" }), "https://login.example.com/oauth/token");
    await u.type(screen.getByRole("textbox", { name: "Client ID" }), "portal-client");
    const secret = screen.getByLabelText("Client secret");
    expect(secret).toHaveAttribute("type", "password");
    await u.type(secret, "very-secret-0001");
    await u.type(screen.getByRole("textbox", { name: /^Scopes/ }), "orders.read{enter}");
    await u.click(screen.getByRole("button", { name: /^Advanced/ }));
    await u.type(screen.getByRole("textbox", { name: /^Resource/ }), "https://orders.example.com/mcp");
    await u.click(screen.getByRole("button", { name: "Add server" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toMatchObject({
      authMode: "machine_oauth",
      machineOAuth: { tokenUrl: "https://login.example.com/oauth/token", clientId: "portal-client", clientSecret: "very-secret-0001", tokenAuthMethod: "client_secret_basic", scopes: ["orders.read"], resource: "https://orders.example.com/mcp" },
    }));
    expect(JSON.stringify(calls.find((c) => c.method === "POST")?.body)).not.toContain("oauth\":");
  });

  it("fills the token endpoint and resource from Detect sign-in when the authorization server offers the grant", async () => {
    const u = userEvent.setup();
    const detected = detectResult({
      machineOAuth: { tokenEndpoint: "https://github.com/login/oauth/access_token", grantTypesListed: true, clientCredentials: true, tokenAuthMethods: ["client_secret_post"], resource: "https://api.githubcopilot.com/mcp/" },
    });
    mockApi(routes(machineServer(), { [`POST ${base}/detect-auth`]: () => detected }));
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await u.type(await screen.findByRole("textbox", { name: "URL" }), "https://api.githubcopilot.com/mcp/");
    await u.click(screen.getByRole("button", { name: "Detect sign-in" }));
    await u.click(await screen.findByRole("radio", { name: /^The portal's own OAuth client/ }));
    expect(await screen.findByText("The authorization server offers client credentials")).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Token endpoint" })).toHaveValue("https://github.com/login/oauth/access_token");
    expect(screen.getByRole("combobox", { name: "Token method" })).toHaveValue("client_secret_post");
  });

  it("warns when the authorization server doesn't list the grant", async () => {
    const u = userEvent.setup();
    mockApi(
      routes(machineServer(), {
        [`POST ${base}/detect-auth`]: () => detectResult({ machineOAuth: { tokenEndpoint: "https://github.com/login/oauth/access_token", grantTypesListed: true, clientCredentials: false, tokenAuthMethods: [], resource: "" } }),
      }),
    );
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await u.type(await screen.findByRole("textbox", { name: "URL" }), "https://api.githubcopilot.com/mcp/");
    await u.click(screen.getByRole("button", { name: "Detect sign-in" }));
    await u.click(await screen.findByRole("radio", { name: /^The portal's own OAuth client/ }));
    expect(await screen.findByText("The authorization server doesn't list client credentials")).toBeInTheDocument();
  });
});

describe("Settings: the portal's own OAuth client", () => {
  it("shows the client without its secret and sends only what changed", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes(machineServer(), { [`PATCH ${base}/${serverId}`]: () => machineServer({ revision: 5 }) }));
    const { container } = renderApp(`${record}?tab=settings`);
    const endpoint = await screen.findByRole("textbox", { name: "Token endpoint" });
    expect(endpoint).toHaveValue("https://login.example.com/oauth/token");
    expect(screen.getByText(/The stored one ends in ab12cd/)).toBeInTheDocument();
    expect(screen.getByText(/ending in 7890/)).toBeInTheDocument();
    expect(screen.getByLabelText("Replace client secret")).toHaveValue("");
    expect(screen.queryByText("Detect sign-in first: OAuth sign-in needs what the server says about it.")).toBeNull();
    expect(screen.getByText(/Not with the portal's own OAuth client/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();

    // Narrowing the scopes needs no secret and says nothing about review.
    await u.type(screen.getByRole("textbox", { name: /^Scopes/ }), "write{enter}");
    expect(screen.queryByText("The server will leave the catalog")).toBeNull();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1));
    const body = calls.find((c) => c.method === "PATCH")?.body;
    expect(body).toMatchObject({ machineOAuth: { scopes: ["read", "write"] } });
    // Nothing else about authentication is sent, and no secret.
    expect(body).not.toHaveProperty("authMode");
    expect(body).not.toHaveProperty("sendIdentity");
    expect(JSON.stringify(body)).not.toContain("clientSecret");
  });

  it("asks for the secret again for another token endpoint, and sends nothing until it is typed", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes(machineServer(), { [`PATCH ${base}/${serverId}`]: () => machineServer({ revision: 5 }) }));
    renderApp(`${record}?tab=settings`);
    const endpoint = await screen.findByRole("textbox", { name: "Token endpoint" });
    await u.clear(endpoint);
    await u.type(endpoint, "https://other.example.com/token");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findAllByText(/Enter the client secret again: the token endpoint changed/)).not.toHaveLength(0);
    expect(calls.some((c) => c.method === "PATCH")).toBe(false);
    await u.type(screen.getByLabelText("Replace client secret"), "fresh-secret-0002");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1));
    expect(calls.find((c) => c.method === "PATCH")?.body).toMatchObject({ machineOAuth: { tokenUrl: "https://other.example.com/token", clientSecret: "fresh-secret-0002" } });
    expect(JSON.stringify(calls.find((c) => c.method === "PATCH")?.body)).not.toContain("clientId");
  });

  it("asks for the secret again when the server moves to another host, and not for a new path", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes(machineServer(), { [`PATCH ${base}/${serverId}`]: () => machineServer({ revision: 5 }) }));
    renderApp(`${record}?tab=settings`);
    const url = await screen.findByRole("textbox", { name: "URL" });
    await u.clear(url);
    await u.type(url, "https://status.example.com/v2/mcp");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1));
    expect(calls.find((c) => c.method === "PATCH")?.body).toMatchObject({ url: "https://status.example.com/v2/mcp" });
    expect(JSON.stringify(calls.find((c) => c.method === "PATCH")?.body)).not.toContain("machineOAuth");

    await u.clear(url);
    await u.type(url, "https://elsewhere.example.com/mcp");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect((await screen.findAllByText(/the server's host changed/)).length).toBeGreaterThan(0);
    expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1);
  });

  it("warns before a wider scope sends a published server back to review, and not before a narrower one", async () => {
    const u = userEvent.setup();
    mockApi(routes(machineServer({ publishState: "published" }, { scopes: ["read", "write"] })));
    renderApp(`${record}?tab=settings`);
    const scopes = await screen.findByRole("textbox", { name: /^Scopes/ });
    await u.click(screen.getByRole("button", { name: "Remove scope write" }));
    expect(screen.queryByText("The server will leave the catalog")).toBeNull();
    await u.type(scopes, "admin{enter}");
    expect(await screen.findByText("The server will leave the catalog")).toBeInTheDocument();
    expect(screen.getByText(/a scope it didn't ask for before/)).toBeInTheDocument();
  });

  it("switches a server to the mode with a whole client, and describes the portal's token on the Overview", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes(mcpServer({ authMode: "none", hasAuth: false, authHeaderName: undefined, credentials: [] }), { [`PATCH ${base}/${serverId}`]: () => machineServer({ revision: 5 }) }));
    renderApp(`${record}?tab=settings`);
    await u.click(await screen.findByRole("radio", { name: /^The portal's own OAuth client/ }));
    await u.type(screen.getByRole("textbox", { name: "Token endpoint" }), "https://login.example.com/oauth/token");
    await u.type(screen.getByRole("textbox", { name: "Client ID" }), "portal-client");
    await u.type(screen.getByLabelText("Client secret"), "very-secret-0001");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1));
    expect(calls.find((c) => c.method === "PATCH")?.body).toMatchObject({
      authMode: "machine_oauth",
      machineOAuth: { tokenUrl: "https://login.example.com/oauth/token", clientId: "portal-client", clientSecret: "very-secret-0001" },
    });
  });

  it("explains a refused secret in words", async () => {
    const u = userEvent.setup();
    mockApi(routes(machineServer(), { [`PATCH ${base}/${serverId}`]: () => Reply.error(422, "client_secret_required", "x", { reason: "origin_changed", field: "machineOAuth.clientSecret" }) }));
    renderApp(`${record}?tab=settings`);
    await u.type(await screen.findByRole("textbox", { name: /^Scopes/ }), "write{enter}");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText(/nothing was sent anywhere/i)).toBeInTheDocument();
  });
});

describe("Overview: the portal's own OAuth client", () => {
  it("shows the token endpoint, the client's hints and what each call carries, never the secret", async () => {
    mockApi(routes(machineServer()));
    renderApp(record);
    expect(await screen.findByText("The portal's OAuth client")).toBeInTheDocument();
    expect(screen.getByText("https://login.example.com/oauth/token")).toBeInTheDocument();
    expect(screen.getByText(/ID ending in ab12cd, secret ending in 7890/)).toBeInTheDocument();
    expect(screen.getByText(/The portal's own token \(client credentials\) in Authorization: Bearer, the same for every caller/)).toBeInTheDocument();
    expect(screen.queryByText("User authorization")).toBeNull();
  });
});
