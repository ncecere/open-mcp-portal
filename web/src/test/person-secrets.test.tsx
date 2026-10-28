/*
 * Each person's own key for a server (decision 72): the page a call's link
 * opens (/connect/secret/{request}) names the server, its team, the address the
 * key goes to and how it is sent, takes the key in a password field and sends
 * the origin it showed; the key is never echoed, listed or kept in the page
 * once saved. Account › My connections lists the entries (never a key) and
 * enters, replaces, lets agents use and removes; Admin › Users removes
 * anyone's; a bad link is explained; the server's settings choose how it is sent.
 */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { secretLinkProblem } from "../pages/connect/secret";
import { keyProblem } from "../components/secrets/key-form";
import { secretFormOf, secretInput, secretProblems, keysDeleted } from "../components/servers/person-secret";
import type { McpServer } from "../components/servers/labels";
import { Reply, mockApi, renderApp, renderBare, shellRoutes } from "./harness";
import { ServerSecrets } from "../components/secrets/server-secrets";
import { ApiError } from "../api/client";

const serverId = "5b1d5b8e-6f0a-4a47-9a1b-0c0f5a8d1111";
const requestId = "A".repeat(43);
const secretKey = "sk-live-PASTED-0123456789";
const config = { placement: "header" as const, name: "X-API-Key", prefix: "Token ", label: "Acme API key", help: "Acme › Settings › API keys." };
const server = { id: serverId, slug: "acme", name: "Acme", teamSlug: "tools", teamName: "Tools" };

const entry = (extra: Record<string, unknown> = {}) => ({
  server,
  config,
  origin: "https://mcp.acme.example",
  hasSecret: false,
  reachable: true,
  canSetup: false,
  isSetup: false,
  ...extra,
});

const secretRequest = (extra: Record<string, unknown> = {}) => ({
  id: requestId,
  reason: "secret_missing",
  server,
  config,
  origin: "https://mcp.acme.example",
  gateway: { id: "9b1d5b8e-6f0a-4a47-9a1b-0c0f5a8d2222", slug: "support", name: "Support tools", exists: true },
  capability: { kind: "tool", exposedName: "acme__create_ticket", title: "Create ticket" },
  secret: entry(),
  ...extra,
});

afterEach(() => vi.restoreAllMocks());

describe("The page a call's link opens", () => {
  const path = `/connect/secret/${requestId}`;

  it("names the server, team, address and placement, takes the key in a password field and sends the origin shown", async () => {
    const u = userEvent.setup();
    const calls = mockApi({
      ...shellRoutes(),
      [`GET /v1/connect/secret-requests/${requestId}`]: () => secretRequest(),
      [`PUT /v1/me/server-secrets/${serverId}`]: () => entry({ hasSecret: true, hint: "6789", status: "active" }),
    });
    const { container } = renderApp(path);
    expect(await screen.findByRole("heading", { level: 1, name: "Enter your Acme API key for Acme" })).toBeInTheDocument();
    expect(screen.getByRole("main")).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Main" })).toBeNull();
    expect(screen.getByText(/needs your own Acme API key, because Acme \(team Tools\) asks each person for theirs/)).toBeInTheDocument();
    expect(screen.getByText("https://mcp.acme.example")).toBeInTheDocument();
    expect(screen.getByText(/Header X-API-Key/)).toBeInTheDocument();
    expect(screen.getByText("Acme › Settings › API keys.")).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe("Enter your Acme API key · Open MCP Portal"));
    const input = screen.getByLabelText("Your Acme API key");
    expect(input).toHaveAttribute("type", "password");
    expect(input).toHaveAttribute("autocomplete", "off");
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
    expect(await axe(container)).toHaveNoViolations();

    await u.type(input, ` ${secretKey} `);
    expect(screen.queryByRole("switch", { name: /Let my agents use this key/ })).toBeNull();
    await u.click(screen.getByRole("button", { name: "Save key" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Your Acme API key is saved" })).toBeInTheDocument();
    const put = calls.find((c) => c.method === "PUT")!;
    expect(put.body).toEqual({ origin: "https://mcp.acme.example", value: secretKey });
    expect(put.headers.get("X-CSRF-Token")).toBe("csrf-123");
    // Never echoed: not in the page, not in a field, not in the title.
    expect(document.body.textContent).not.toContain(secretKey);
    expect(document.querySelector("input")?.getAttribute("value") ?? "").not.toContain(secretKey);
    expect(screen.getByText(/run acme__create_ticket again/)).toBeInTheDocument();
  });

  it("refuses a short key before sending, and says why when the server's address moved", async () => {
    const u = userEvent.setup();
    const calls = mockApi({
      ...shellRoutes(),
      [`GET /v1/connect/secret-requests/${requestId}`]: () => secretRequest({ reason: "secret_rejected" }),
      [`PUT /v1/me/server-secrets/${serverId}`]: () => Reply.error(409, "server_changed", "The server's address changed"),
    });
    renderApp(path);
    expect(await screen.findByText(/was refused by Acme: the key you entered before no longer works/)).toBeInTheDocument();
    await u.type(screen.getByLabelText("Your Acme API key"), "short");
    await u.click(screen.getByRole("button", { name: "Save key" }));
    expect(await screen.findByText("Enter the key: at least 8 characters.")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
    await u.clear(screen.getByLabelText("Your Acme API key"));
    await u.type(screen.getByLabelText("Your Acme API key"), secretKey);
    await u.click(screen.getByRole("button", { name: "Save key" }));
    expect(await screen.findByText("The server's address changed")).toBeInTheDocument();
    expect(screen.getByText(/It is on another host than the one this page showed/)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /is saved/ })).toBeNull();
  });

  it("warns that a query value is part of the address, and offers editors to read the server with their key", async () => {
    mockApi({
      ...shellRoutes(),
      [`GET /v1/connect/secret-requests/${requestId}`]: () => secretRequest({ config: { placement: "query", name: "api_key", label: "Acme key", help: "" }, secret: entry({ canSetup: true, config: { placement: "query", name: "api_key" } }) }),
    });
    renderApp(path);
    expect(await screen.findByText("This server takes the key in the address")).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: /Use my key to read this server's capabilities/ })).toBeInTheDocument();
  });

  it("explains another person's, an unknown and an expired link, and never acts on them", async () => {
    mockApi({ ...shellRoutes(), [`GET /v1/connect/secret-requests/${requestId}`]: () => Reply.error(404, "secret_request_not_found") });
    const { unmount } = renderApp(path);
    expect(await screen.findByRole("heading", { level: 1, name: "This link was made for someone else" })).toBeInTheDocument();
    expect(screen.queryByLabelText(/Your .* key/)).toBeNull();
    unmount();
    mockApi({ ...shellRoutes(), [`GET /v1/connect/secret-requests/${requestId}`]: () => Reply.error(410, "secret_request_expired") });
    renderApp(path);
    expect(await screen.findByRole("heading", { level: 1, name: "This link expired" })).toBeInTheDocument();
    expect(screen.getByText(/stop working if the server's address changed/)).toBeInTheDocument();
  });
});

describe("Account › My connections: keys for servers", () => {
  const routes = (list: unknown[], extra: Record<string, () => unknown> = {}) => ({
    ...shellRoutes(),
    "GET /v1/me/connections": () => [],
    "GET /v1/me/server-secrets": () => list,
    ...extra,
  });

  it("lists the entries without a key, and enters one with the origin shown", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes([entry(), entry({ server: { ...server, id: "6b1d5b8e-6f0a-4a47-9a1b-0c0f5a8d3333", name: "Beta" }, hasSecret: true, hint: "4321", status: "rejected" })], {
        [`PUT /v1/me/server-secrets/${serverId}`]: () => entry({ hasSecret: true, hint: "6789", status: "active" }),
      }),
    );
    renderApp("/settings/connections");
    const region = await screen.findByRole("heading", { name: "Keys for servers" });
    expect(region).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Your keys for servers" });
    expect(within(table).getByText("Acme")).toBeInTheDocument();
    expect(within(table).getByText("Ends in 4321")).toBeInTheDocument();
    expect(within(table).getByText("Refused: enter it again")).toBeInTheDocument();
    expect(table).not.toHaveTextContent(secretKey);
    await u.click(await within(table).findByRole("button", { name: "Actions for Acme" }));
    await u.click(await screen.findByRole("menuitem", { name: "Enter key…" }));
    const dialog = await screen.findByRole("dialog", { name: "Enter your key for Acme" });
    await u.type(within(dialog).getByLabelText("Your Acme API key"), secretKey);
    await u.click(within(dialog).getByRole("button", { name: "Save key" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ origin: "https://mcp.acme.example", value: secretKey }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Enter your key for Acme" })).toBeNull());
    expect(document.body.textContent).not.toContain(secretKey);
  });

  it("removes a key after asking", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes([entry({ hasSecret: true, hint: "6789", status: "active" })], { [`DELETE /v1/me/server-secrets/${serverId}`]: () => ({ ok: true }) }),
    );
    renderApp("/settings/connections");
    const table = await screen.findByRole("table", { name: "Your keys for servers" });
    await u.click(await within(table).findByRole("button", { name: "Actions for Acme" }));
    await u.click(await screen.findByRole("menuitem", { name: "Remove key…" }));
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    await u.click(await screen.findByRole("button", { name: "Remove key" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url === `/v1/me/server-secrets/${serverId}`)).toBe(true));
  });
});

describe("Admin › Users: a person's keys", () => {
  it("lists them without the keys and lets a platform admin remove one", async () => {
    const u = userEvent.setup();
    const calls = mockApi({
      ...shellRoutes("platform_admin"),
      "GET /v1/admin/users/u1/server-secrets": () => [entry({ hasSecret: true, hint: "6789", status: "active", reachable: false })],
      [`DELETE /v1/admin/users/u1/server-secrets/${serverId}`]: () => ({ ok: true }),
    });
    renderBare(<ServerSecrets owner={{ self: false, userId: "u1", name: "Blair" }} canRevoke />);
    const table = await screen.findByRole("table", { name: "Keys Blair entered for servers" });
    await u.click(await within(table).findByRole("button", { name: "Actions for Acme" }));
    expect(table).toHaveTextContent("Ends in 6789");
    expect(screen.queryByRole("menuitem", { name: "Enter key…" })).toBeNull();
    await u.click(await screen.findByRole("menuitem", { name: "Remove key…" }));
    await u.click(await screen.findByRole("button", { name: "Remove key" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url === `/v1/admin/users/u1/server-secrets/${serverId}`)).toBe(true));
  });
});

describe("The server's settings for each person's key", () => {
  const sv = (extra: Record<string, unknown> = {}) =>
    ({ id: serverId, name: "Acme", personSecret: { placement: "header", name: "X-API-Key", prefix: "Token ", label: "Acme API key", help: "", people: 3, rejected: 1, setup: { status: "missing" } }, ...extra }) as unknown as McpServer;

  it("builds the request and checks names", () => {
    expect(secretInput(secretFormOf(sv()))).toEqual({ placement: "header", name: "X-API-Key", prefix: "Token ", label: "Acme API key", help: "" });
    expect(secretInput({ placement: "bearer", name: "ignored", prefix: "ignored", label: " Key ", help: "" })).toEqual({ placement: "bearer", label: "Key", help: "" });
    expect(secretProblems({ placement: "header", name: "Cookie", prefix: "", label: "", help: "" }).name).toMatch(/header name/);
    expect(secretProblems({ placement: "header", name: "bad name", prefix: "", label: "", help: "" }).name).toBeDefined();
    expect(secretProblems({ placement: "query", name: "mcp-key", prefix: "", label: "", help: "" }).name).toBeDefined();
    expect(secretProblems({ placement: "query", name: "api_key", prefix: "", label: "", help: "" })).toEqual({});
    expect(secretProblems({ placement: "bearer", name: "", prefix: "", label: "", help: "" })).toEqual({});
  });

  it("says when saving deletes everyone's keys: another address, another way of sending it, leaving the mode", () => {
    const f = secretFormOf(sv());
    expect(keysDeleted(sv(), f, false, "person_secret")).toBe(false);
    expect(keysDeleted(sv(), { ...f, prefix: "Key " }, false, "person_secret")).toBe(false);
    expect(keysDeleted(sv(), f, true, "person_secret")).toBe(true);
    expect(keysDeleted(sv(), { ...f, placement: "query" }, false, "person_secret")).toBe(true);
    expect(keysDeleted(sv(), f, false, "none")).toBe(true);
    expect(keysDeleted(sv({ personSecret: { ...sv().personSecret, people: 0 } }), f, true, "none")).toBe(false);
  });

  it("checks a pasted key and words the link problems", () => {
    expect(keyProblem("short")).toBeDefined();
    expect(keyProblem("line1-aaaa\nline2-bbbb")).toBeDefined();
    expect(keyProblem(`  ${secretKey}  `)).toBeUndefined();
    expect(secretLinkProblem(new ApiError(404, "secret_request_not_found", "x")).title).toBe("This link was made for someone else");
    expect(secretLinkProblem(new ApiError(410, "secret_request_expired", "x")).title).toBe("This link expired");
  });
});
