/*
 * All the upstream auth modes of v0.3.2 in one form (decisions 72, 73 and 74): None, Static credential, Each
 * person's own key, The portal's own OAuth client and Sign-in with OAuth per person are offered side by side in
 * Add and Settings, in a fixed order, each mode shows only its own fields (nothing of another mode's state
 * stays on screen or travels in the request), a typed secret is not carried from one mode into another, what a
 * switch does to a published server is the same whichever way it goes, and the TLS card works beside every mode.
 */
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { authModeLabels, authChange, upstreamFormOf, type AuthMode } from "../components/servers/upstream-auth";
import { settingsAuthBody } from "../components/servers/settings-auth";
import { newPart } from "../components/servers/credentials";
import { capabilities, healthCheck, mcpServer, page, serverId, team, teamPublishing } from "./fixtures";
import { type Handler, mockApi, renderApp, shellRoutes } from "./harness";

type McpServer = Schemas["McpServer"];
const base = `/v1/teams/${team.slug}/mcp-servers`;
const record = `/teams/${team.slug}/servers/${serverId}`;
const sha = "ab".repeat(32);

const modeOrder: AuthMode[] = ["none", "static_header", "person_secret", "machine_oauth", "oauth"];

const ownKeys = (extra: Partial<McpServer> = {}): McpServer => ({
  ...mcpServer(),
  authMode: "person_secret",
  hasAuth: false,
  credentials: [],
  personSecret: { placement: "header", name: "X-API-Key", prefix: "", label: "Acme API key", help: "", people: 3, rejected: 0, setup: { status: "active", personName: "Ana" } },
  ...extra,
});
const machine = (extra: Partial<McpServer> = {}): McpServer => ({
  ...mcpServer(),
  authMode: "machine_oauth",
  hasAuth: false,
  authHeaderName: undefined,
  authValueHint: "",
  credentials: [],
  machineOAuth: {
    tokenUrl: "https://login.example.com/oauth/token",
    clientIdHint: "ab12cd",
    hasClientSecret: true,
    clientSecretHint: "7890",
    tokenAuthMethod: "client_secret_basic",
    scopes: ["read"],
    audience: null,
    resource: "https://status.example.com/mcp",
  },
  ...extra,
});
const withTls = (s: McpServer): McpServer => ({
  ...s,
  tls: {
    ca: {
      sha256: "cd".repeat(32),
      certificates: [{ subject: "CN=Internal CA", issuer: "CN=Internal CA", sha256: "cd".repeat(32), notBefore: "2026-01-01T00:00:00Z", notAfter: "2030-01-01T00:00:00Z" }],
    },
    client: {
      certificate: { subject: "CN=omp-portal", issuer: "CN=Internal CA", sha256: sha, notBefore: "2026-01-01T00:00:00Z", notAfter: "2027-01-18T00:00:00Z" },
      chainLength: 1,
      hasKey: true,
      status: "valid",
      daysLeft: 90,
    },
  },
});

const routes = (current: McpServer, extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", "owner"),
  [`GET ${base}`]: () => page([current]),
  [`GET ${base}/${serverId}`]: () => current,
  [`GET ${base}/${serverId}/capabilities`]: () => capabilities,
  [`GET ${base}/${serverId}/health-checks`]: () => [healthCheck()],
  [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing(),
  "GET /v1/auth-providers": () => [],
  ...extra,
});

/** What a mode shows that no other does. */
const fieldOf = {
  person_secret: () => screen.queryByRole("radio", { name: "A header" }),
  machine_oauth: () => screen.queryByRole("textbox", { name: "Token endpoint" }),
};

afterEach(() => vi.restoreAllMocks());

describe("the modes, side by side", () => {
  it("labels every mode and keeps their order", () => {
    expect(modeOrder.map((m) => authModeLabels[m])).toEqual([
      "None",
      "Static credential",
      "Each person's own key",
      "The portal's own OAuth client",
      "Sign-in with OAuth, per person",
    ]);
  });

  it("offers all five in Add, in order, and shows only the chosen mode's fields", async () => {
    const u = userEvent.setup();
    mockApi(routes(mcpServer()));
    const { container } = renderApp(`/teams/${team.slug}/servers?form=new`);
    await u.type(await screen.findByRole("textbox", { name: "URL" }), "https://orders.example.com/mcp");
    const radio = (m: AuthMode) => screen.getByRole("radio", { name: new RegExp(`^${authModeLabels[m]}`) });
    // In the order of modeOrder, one after the other in the page.
    for (let i = 1; i < modeOrder.length; i++) {
      const [before, after] = [modeOrder[i - 1] as AuthMode, modeOrder[i] as AuthMode];
      expect(radio(before).compareDocumentPosition(radio(after)) & Node.DOCUMENT_POSITION_FOLLOWING, `${after} after ${before}`).toBeTruthy();
    }
    // OAuth needs a detection first; the other four are offered at once.
    expect(screen.getByText(/Press Detect sign-in first/)).toBeInTheDocument();
    for (const m of modeOrder.filter((m) => m !== "oauth")) expect(radio(m)).toBeEnabled();
    // Each choice shows its own fields and none of another's, and exactly one mode is checked.
    const fields = { person_secret: fieldOf.person_secret, machine_oauth: fieldOf.machine_oauth };
    for (const m of ["person_secret", "machine_oauth", "none", "person_secret"] as AuthMode[]) {
      await u.click(radio(m));
      expect(radio(m)).toBeChecked();
      for (const [other, find] of Object.entries(fields)) {
        if (other === m) expect(find(), `${other} fields missing in ${m}`).not.toBeNull();
        else expect(find(), `${other} fields shown in ${m}`).toBeNull();
      }
      expect(modeOrder.filter((x) => radio(x).getAttribute("aria-checked") === "true" || (radio(x) as HTMLInputElement).checked)).toEqual([m]);
    }
    expect(await axe(container)).toHaveNoViolations();
  });

  it("does not carry a secret typed in one mode into another, nor send another mode's fields", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes(mcpServer(), {
        [`POST ${base}`]: () => ({ server: ownKeys(), refresh: null, refreshError: null, setupRequired: true }),
      }),
    );
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await u.type(await screen.findByRole("textbox", { name: "Name" }), "Orders API");
    await u.type(screen.getByRole("textbox", { name: "URL" }), "https://orders.example.com/mcp");
    await u.click(screen.getByRole("radio", { name: /^The portal's own OAuth client/ }));
    await u.type(screen.getByRole("textbox", { name: "Token endpoint" }), "https://login.example.com/oauth/token");
    await u.type(screen.getByRole("textbox", { name: "Client ID" }), "portal-client");
    await u.type(screen.getByLabelText("Client secret"), "typed-for-the-machine-client");
    // Away and back: the secret is gone, so it can't reach another mode's request.
    await u.click(screen.getByRole("radio", { name: /^Each person's own key/ }));
    expect(screen.queryByLabelText("Client secret")).toBeNull();
    await u.type(screen.getByRole("textbox", { name: "Header name" }), "X-API-Key");
    await u.click(screen.getByRole("button", { name: "Add server" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url === base)).toBe(true));
    const body = calls.find((c) => c.method === "POST" && c.url === base)?.body as Record<string, unknown>;
    expect(body).toMatchObject({ authMode: "person_secret", personSecret: { placement: "header", name: "X-API-Key" } });
    expect(body).not.toHaveProperty("machineOAuth");
    expect(body).not.toHaveProperty("oauth");
    expect(JSON.stringify(body)).not.toContain("typed-for-the-machine-client");
  });
});

describe("Settings with every mode", () => {
  it.each([
    ["person_secret", () => ownKeys(), /Not with each person's own key/],
    ["machine_oauth", () => machine(), /Not with the portal's own OAuth client/],
  ] as const)("a server in %s shows its own fields, no requirement, and the TLS card beside them", async (_mode, make, notWith) => {
    mockApi(routes(withTls(make())));
    const { container } = renderApp(`${record}?tab=settings`);
    expect(await screen.findByText("TLS to the server")).toBeInTheDocument();
    expect(screen.getByLabelText("Stored client certificate")).toHaveTextContent("CN=omp-portal");
    expect(screen.getByText(notWith)).toBeInTheDocument();
    // Only this mode's fields.
    expect(fieldOf.person_secret() !== null).toBe(_mode === "person_secret");
    expect(fieldOf.machine_oauth() !== null).toBe(_mode === "machine_oauth");
    expect(container.textContent).not.toMatch(/BEGIN|PRIVATE KEY/);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("switching a server from its own keys to the portal's client sends the mode and the client, once, with no key", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes(withTls(ownKeys()), { [`PATCH ${base}/${serverId}`]: () => withTls(machine({ revision: 5 })) }));
    renderApp(`${record}?tab=settings`);
    await u.click(await screen.findByRole("radio", { name: /^The portal's own OAuth client/ }));
    // The keys people entered are deleted by the switch, and the form says so before it is saved.
    expect(await screen.findByText(/entered a key for/)).toBeInTheDocument();
    await u.type(screen.getByRole("textbox", { name: "Token endpoint" }), "https://login.example.com/oauth/token");
    await u.type(screen.getByRole("textbox", { name: "Client ID" }), "portal-client");
    await u.type(screen.getByLabelText("Client secret"), "typed-once-0001");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1));
    const body = calls.find((c) => c.method === "PATCH")?.body as Record<string, unknown>;
    expect(body).toMatchObject({ authMode: "machine_oauth", machineOAuth: { tokenUrl: "https://login.example.com/oauth/token", clientId: "portal-client", clientSecret: "typed-once-0001" } });
    expect(body).not.toHaveProperty("personSecret");
    expect(body).not.toHaveProperty("tls"); // the TLS settings were not touched
  });
});

describe("what a switch does, whichever way it goes", () => {
  const form = (server: McpServer, mode: AuthMode) => ({ ...upstreamFormOf(server), mode });
  const opts = { urlChanged: false };

  it("sends a published server back to review when it enters a secret mode or the other one", () => {
    const none = mcpServer();
    expect(authChange(none, { ...form(none, "person_secret"), secret: { placement: "header", name: "X-K", prefix: "", label: "", help: "" } }, opts).review).toBe("secret");
    expect(authChange(none, { ...form(none, "machine_oauth"), machine: { ...upstreamFormOf(machine()).machine } }, opts).review).toBe("machine");
    // person_secret -> machine_oauth is a new way of authenticating too (it used to read as nothing to review).
    const keyed = ownKeys();
    expect(authChange(keyed, { ...form(keyed, "machine_oauth"), machine: upstreamFormOf(machine()).machine }, opts).review).toBe("machine");
    // machine_oauth -> person_secret
    const client = machine();
    expect(authChange(client, { ...form(client, "person_secret"), secret: { placement: "header", name: "X-K", prefix: "", label: "", help: "" } }, opts).review).toBe("secret");
    // Leaving either for None needs no review.
    expect(authChange(keyed, form(keyed, "none"), opts).review).toBeUndefined();
    expect(authChange(client, form(client, "none"), opts).review).toBeUndefined();
  });

  it("sends only the new mode's input", () => {
    const keyed = ownKeys();
    const toMachine = settingsAuthBody(
      keyed,
      { upstream: { ...form(keyed, "machine_oauth"), machine: { ...upstreamFormOf(machine()).machine, tokenUrl: "https://login.example.com/t", clientId: "c" } } },
      [],
      "s3cret-value",
    );
    expect(toMachine).toMatchObject({ authMode: "machine_oauth", machineOAuth: { tokenUrl: "https://login.example.com/t", clientId: "c", clientSecret: "s3cret-value" } });
    expect(toMachine).not.toHaveProperty("personSecret");
    const client = machine();
    const toKeys = settingsAuthBody(client, { upstream: { ...form(client, "person_secret"), secret: { placement: "query", name: "k", prefix: "", label: "", help: "" } } }, [], "");
    expect(toKeys).toMatchObject({ authMode: "person_secret", personSecret: { placement: "query", name: "k" } });
    expect(toKeys).not.toHaveProperty("machineOAuth");
    // A static part that sets Authorization can't stay beside the portal's token.
    const staticPart = { ...newPart(), kind: "bearer" as const, value: "x" };
    const withBearer = settingsAuthBody(keyed, { upstream: { ...form(keyed, "machine_oauth"), machine: { ...upstreamFormOf(machine()).machine, tokenUrl: "https://login.example.com/t", clientId: "c" } } }, [staticPart], "s");
    expect(JSON.stringify(withBearer)).not.toContain('"bearer"');
  });
});
