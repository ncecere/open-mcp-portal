/*
 * Decision 64: Add's "Send identity token" switch follows the address for a server with no authentication (public:
 * off, internal: on), says why, honours a choice the person makes, and a call's page says whether the token was sent.
 */
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Schemas } from "../api/client";
import { identitySentLabel } from "../components/gateways/labels";
import { capabilities, mcpCall, mcpServer, page, serverId, team, teamPublishing, healthCheck } from "./fixtures";
import { type Call, type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

const base = `/v1/teams/${team.slug}/mcp-servers`;
const created: Schemas["McpServerCreated"] = {
  server: mcpServer(),
  refresh: { listed: 4, added: 4, changed: 0, gone: 0, capabilities },
  refreshError: null,
};

const answers: Record<string, Schemas["IdentityDefault"]> = {
  "https://mcp.deepwiki.example.com/mcp": { basis: "public_host", sendIdentity: false },
  "https://mcp.corp.example.com/mcp": { basis: "internal_host", sendIdentity: true },
  "https://nowhere.example.com/mcp": { basis: "unresolved_host", sendIdentity: false },
};

const routes = (extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", "editor"),
  [`GET ${base}`]: () => page([]),
  [`POST ${base}/identity-default`]: (body) => answers[(body as { url: string }).url] ?? Reply.error(422, "url_not_allowed", "Not allowed"),
  [`POST ${base}`]: () => new Reply(201, { data: created }),
  [`GET ${base}/${serverId}`]: () => created.server,
  [`GET ${base}/${serverId}/capabilities`]: () => capabilities,
  [`GET ${base}/${serverId}/health-checks`]: () => [healthCheck()],
  [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing(),
  ...extra,
});

const posted = (calls: Call[]) => calls.find((c) => c.method === "POST" && c.url === base)?.body as Record<string, unknown> | undefined;

async function enter(u: ReturnType<typeof userEvent.setup>, url: string) {
  await u.type(await screen.findByRole("textbox", { name: "Name" }), "Wiki");
  await u.type(screen.getByRole("textbox", { name: "URL" }), url);
}

const identitySwitch = () => screen.getByRole("switch", { name: "Send identity token" });

describe("Add server › Send identity token follows the address", () => {
  it("starts off for a public address with no sign-in, says why, and sends the value shown", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes());
    renderApp(`/teams/${team.slug}/servers?form=new`);
    expect(await screen.findByText(/Enter the address: for a server with no sign-in/)).toBeInTheDocument();
    await enter(u, "https://mcp.deepwiki.example.com/mcp");
    expect(await screen.findByText(/This address is public and the server has no sign-in/)).toBeInTheDocument();
    expect(identitySwitch()).not.toBeChecked();
    expect(calls.find((c) => c.url === `${base}/identity-default`)?.body).toEqual({ url: "https://mcp.deepwiki.example.com/mcp" });
    await u.click(screen.getByRole("button", { name: "Add server" }));
    await waitFor(() => expect(posted(calls)?.sendIdentity).toBe(false));
  });

  it("starts on for an internal address", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes());
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await enter(u, "https://mcp.corp.example.com/mcp");
    expect(await screen.findByText(/This address is on your internal network/)).toBeInTheDocument();
    expect(identitySwitch()).toBeChecked();
    await u.click(screen.getByRole("button", { name: "Add server" }));
    await waitFor(() => expect(posted(calls)?.sendIdentity).toBe(true));
  });

  it("starts off, and says so, for a name the portal could not look up", async () => {
    const u = userEvent.setup();
    mockApi(routes());
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await enter(u, "https://nowhere.example.com/mcp");
    expect(await screen.findByText(/couldn't look this address up/)).toBeInTheDocument();
    expect(identitySwitch()).not.toBeChecked();
  });

  it("keeps a choice the person makes when the address changes", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes());
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await enter(u, "https://mcp.deepwiki.example.com/mcp");
    await screen.findByText(/This address is public/);
    await u.click(identitySwitch());
    expect(identitySwitch()).toBeChecked();
    const url = screen.getByRole("textbox", { name: "URL" });
    await u.clear(url);
    await u.type(url, "https://nowhere.example.com/mcp");
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && (c.body as { url?: string })?.url === "https://nowhere.example.com/mcp")).toBe(true));
    expect(identitySwitch()).toBeChecked();
    await u.click(screen.getByRole("button", { name: "Add server" }));
    await waitFor(() => expect(posted(calls)?.sendIdentity).toBe(true));
  });

  it("starts on for a static header, whatever the address, and does not ask", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes());
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await enter(u, "https://mcp.deepwiki.example.com/mcp");
    await screen.findByText(/This address is public/);
    await u.click(screen.getByRole("radio", { name: /^Static header/ }));
    expect(screen.getByText(/Servers that use a header or their own sign-in start with this on/)).toBeInTheDocument();
    expect(identitySwitch()).toBeChecked();
    expect(calls.filter((c) => c.url === `${base}/identity-default`)).toHaveLength(1);
  });

  it("leaves the choice to the server when the address could not be checked", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes());
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await enter(u, "https://refused.example.com/mcp");
    expect(await screen.findByText(/couldn't check this address/)).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Add server" }));
    await waitFor(() => expect(posted(calls)).toBeDefined());
    expect(posted(calls)).not.toHaveProperty("sendIdentity");
  });
});

describe("A call's page › Identity token", () => {
  it.each([
    [{ identitySent: true }, "Sent"],
    [{ identitySent: false }, "Not sent"],
    [{ outcome: "denied" as const }, "Not forwarded"],
    [{ method: "tools/list" }, "Not forwarded"],
    [{}, "Not recorded"],
  ])("says %j is %s", (extra, label) => {
    expect(identitySentLabel(mcpCall(extra))).toBe(label);
  });

  it("shows it among the details", async () => {
    mockApi({ ...shellRoutes("none", "owner"), [`GET /v1/teams/${team.slug}/calls/501`]: () => mcpCall({ identitySent: false }) });
    renderApp(`/teams/${team.slug}/calls/501`);
    const term = await screen.findByText("Identity token");
    expect(term.closest("div")).toHaveTextContent(/Not sent.*switch was off/);
  });
});
