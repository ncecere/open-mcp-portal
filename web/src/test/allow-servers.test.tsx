/* Account › My connections › Allow servers…: allow a server with no call and no link, its refusals (moved server, scopes the account lacks, not visible), and taking a single server back. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { redirectTo } from "../components/providers/labels";
import { connection, connectionId, connectServer, providerRef } from "./fixtures-providers";
import { type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

const allowablePath = `/v1/me/connections/${connectionId}/allowable-servers`;
const allowPath = `/v1/me/connections/${connectionId}/allow-server`;
const tools = connectServer();
const docs = connectServer({ id: "30303030-3030-4303-8303-303030303031", slug: "docs", name: "Docs", teamSlug: "writers", teamName: "Writers" });

const allowable = (extra: Partial<Schemas["AllowableServer"]> = {}): Schemas["AllowableServer"] => ({
  server: tools,
  origin: "https://tools.example.com",
  scopes: ["repo"],
  covered: true,
  allowed: false,
  ...extra,
});

const routes = (extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", "member"),
  "GET /v1/me/connections": () => [connection()],
  [`GET ${allowablePath}`]: () => [allowable(), allowable({ server: docs, origin: "https://docs.example.com", scopes: ["repo", "read:org"] })],
  ...extra,
});

async function openDialog(u: ReturnType<typeof userEvent.setup>) {
  const table = await screen.findByRole("table", { name: "Your connected accounts" });
  await u.click(await within(table).findByRole("button", { name: "Actions for GitHub" }));
  await u.click(await screen.findByRole("menuitem", { name: "Allow servers…" }));
  return screen.findByRole("dialog", { name: "Allowed servers for GitHub" });
}

afterEach(() => vi.restoreAllMocks());

describe("Allow servers from My connections", () => {
  it("lists the servers that need the account, with team, address and scopes, and the consent page's explanation", async () => {
    const u = userEvent.setup();
    mockApi(routes());
    const { container } = renderApp("/settings/connections");
    const dialog = await openDialog(u);
    const list = await within(dialog).findByRole("list", { name: "Servers that need GitHub" });
    const items = within(list).getAllByRole("listitem");
    expect(items).toHaveLength(2);
    expect(items[0]).toHaveTextContent("GitHub tools (Platform tools)");
    expect(items[0]).toHaveTextContent("Asks for repo · https://tools.example.com");
    expect(items[1]).toHaveTextContent("Docs (Writers)");
    expect(items[1]).toHaveTextContent("Asks for repo, read:org · https://docs.example.com");
    expect(within(dialog).getByText(/sends it only to servers you allow, and only while a server stays at the address shown here/)).toBeInTheDocument();
    expect(within(dialog).getByText(/an agent acting for you can't ask/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("allows a server with the address and scopes shown, and the list shows it allowed", async () => {
    const u = userEvent.setup();
    let allowed = false;
    const calls = mockApi(
      routes({
        [`GET ${allowablePath}`]: () => [allowable({ allowed })],
        [`POST ${allowPath}`]: () => {
          allowed = true;
          return { provider: providerRef(), server: tools, scopes: ["repo"] };
        },
      }),
    );
    renderApp("/settings/connections");
    const dialog = await openDialog(u);
    await u.click(await within(dialog).findByRole("button", { name: "Allow GitHub tools" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url === allowPath)).toBe(true));
    const post = calls.find((c) => c.method === "POST" && c.url === allowPath)!;
    expect(post.body).toEqual({ serverId: tools.id, origin: "https://tools.example.com", scopes: ["repo"] });
    expect(post.headers.get("X-CSRF-Token")).toBe("csrf-123");
    expect(await screen.findByText("GitHub tools was allowed")).toBeInTheDocument();
    expect(await within(dialog).findByText("Allowed")).toBeInTheDocument();
    expect(within(dialog).queryByRole("button", { name: "Allow GitHub tools" })).toBeNull();
    expect(within(dialog).getByRole("button", { name: "Take back GitHub tools" })).toBeInTheDocument();
    // No provider round trip.
    expect(calls.some((c) => c.url === "/v1/me/connections/start")).toBe(false);
  });

  it("refuses a server that moved since the list loaded: says so and shows its new address", async () => {
    const u = userEvent.setup();
    let origin = "https://tools.example.com";
    mockApi(
      routes({
        [`GET ${allowablePath}`]: () => [allowable({ origin })],
        [`POST ${allowPath}`]: () => {
          origin = "https://elsewhere.example.net";
          return Reply.error(409, "server_changed", "The server's address or the access it needs changed since this list was loaded. Reload and review it again.");
        },
      }),
    );
    renderApp("/settings/connections");
    const dialog = await openDialog(u);
    await u.click(await within(dialog).findByRole("button", { name: "Allow GitHub tools" }));
    // A danger toast is announced twice (the toast and a live region).
    expect((await screen.findAllByText("GitHub tools wasn't allowed")).length).toBeGreaterThan(0);
    expect((await screen.findAllByText(/changed since this list was loaded/)).length).toBeGreaterThan(0);
    expect(await within(dialog).findByText(/https:\/\/elsewhere\.example\.net/)).toBeInTheDocument();
    expect(within(dialog).queryByText("Allowed")).toBeNull();
  });

  it("sends an account that lacks the scopes to the provider with the union of its scopes and the server's", async () => {
    const u = userEvent.setup();
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const calls = mockApi(
      routes({
        "GET /v1/me/connections": () => [connection({ scopes: ["repo"] })],
        [`GET ${allowablePath}`]: () => [allowable({ scopes: ["repo", "read:org"], covered: false })],
        "POST /v1/me/connections/start": () => ({ authorizeUrl: "https://github.com/login/oauth/authorize?state=s1", scopes: ["repo", "read:org"], expiresAt: "2026-10-16T08:10:00Z" }),
      }),
    );
    renderApp("/settings/connections");
    const dialog = await openDialog(u);
    expect(within(dialog).queryByRole("button", { name: "Allow GitHub tools" })).toBeNull();
    await u.click(await within(dialog).findByRole("button", { name: "Grant more access for GitHub tools" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith("https://github.com/login/oauth/authorize?state=s1"));
    expect(calls.find((c) => c.url === "/v1/me/connections/start")!.body).toEqual({
      providerId: connection().provider.id,
      scopes: ["repo", "read:org"],
      returnTo: "/settings/connections?connected=github",
    });
    expect(calls.some((c) => c.url === allowPath)).toBe(false);
  });

  it("says when the portal refuses the allowance (a server the person can't use any more), and keeps the list", async () => {
    const u = userEvent.setup();
    mockApi(routes({ [`POST ${allowPath}`]: () => Reply.error(404, "server_not_found", "That server isn't one you can use, or it doesn't exist") }));
    renderApp("/settings/connections");
    const dialog = await openDialog(u);
    await u.click(await within(dialog).findByRole("button", { name: "Allow GitHub tools" }));
    expect(await within(dialog).findByText("Couldn't allow the server")).toBeInTheDocument();
    expect(within(dialog).getByText(/isn't one you can use/)).toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Allow Docs" })).toBeInTheDocument();
  });

  it("takes back one server's allowance, and offers to take back one that isn't offered to the person any more", async () => {
    const u = userEvent.setup();
    const gone = connectServer({ id: "30303030-3030-4303-8303-303030303032", slug: "old", name: "Old tools", teamSlug: "legacy", teamName: "Legacy" });
    let grants: Schemas["ProviderServerGrant"][] = [
      { server: tools, origin: "https://tools.example.com", scopes: ["repo"], consentedAt: "2026-10-16T08:00:00Z" },
      { server: gone, origin: "https://old.example.com", scopes: ["repo"], consentedAt: "2026-10-16T08:00:00Z" },
    ];
    const calls = mockApi(
      routes({
        "GET /v1/me/connections": () => [connection({ allowedServers: grants })],
        [`GET ${allowablePath}`]: () => [allowable({ allowed: grants.some((g) => g.server.id === tools.id) })],
        [`DELETE /v1/me/connections/${connectionId}/allowed-servers/${tools.id}`]: () => {
          grants = grants.filter((g) => g.server.id !== tools.id);
          return { ok: true };
        },
        [`DELETE /v1/me/connections/${connectionId}/allowed-servers/${gone.id}`]: () => {
          grants = grants.filter((g) => g.server.id !== gone.id);
          return { ok: true };
        },
      }),
    );
    renderApp("/settings/connections");
    const dialog = await openDialog(u);
    expect(await within(dialog).findByText("Allowed, but not offered to you now")).toBeInTheDocument();
    expect(within(dialog).getByText("Old tools (Legacy)")).toBeInTheDocument();
    await u.click(await within(dialog).findByRole("button", { name: "Take back GitHub tools" }));
    expect(await screen.findByText("GitHub tools is no longer allowed")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "DELETE" && c.url === `/v1/me/connections/${connectionId}/allowed-servers/${tools.id}`)).toBe(true);
    expect(await within(dialog).findByRole("button", { name: "Allow GitHub tools" })).toBeInTheDocument();
    await u.click(within(dialog).getByRole("button", { name: "Take back Old tools" }));
    await waitFor(() => expect(within(dialog).queryByText("Old tools (Legacy)")).toBeNull());
    expect(within(dialog).queryByText("Allowed, but not offered to you now")).toBeNull();
  });

  it("says so when no server needs the account", async () => {
    const u = userEvent.setup();
    mockApi(routes({ [`GET ${allowablePath}`]: () => [] }));
    renderApp("/settings/connections");
    const dialog = await openDialog(u);
    expect(await within(dialog).findByText(/No server you can use requires GitHub/)).toBeInTheDocument();
  });

  it("is only for a platform provider's account on My connections, not an MCP server's own sign-in", async () => {
    const u = userEvent.setup();
    const signIn = connection({
      id: "c9",
      provider: providerRef({ id: "40404040-4040-4404-8404-404040404040", slug: "docs-mcp", name: "Docs MCP", kind: "mcp_server", server: { id: docs.id, slug: docs.slug, name: "Docs", teamSlug: "writers" } }),
    });
    mockApi(routes({ "GET /v1/me/connections": () => [signIn] }));
    renderApp("/settings/connections");
    const table = await screen.findByRole("table", { name: "Your connected accounts" });
    await u.click(await within(table).findByRole("button", { name: "Actions for Docs" }));
    expect(await screen.findByRole("menuitem", { name: "Disconnect…" })).toBeInTheDocument();
    expect(screen.queryByRole("menuitem", { name: "Allow servers…" })).toBeNull();
  });
});
