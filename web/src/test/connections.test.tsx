/* Account › My connections (list, empty state, Connect, Connect again, Disconnect with confirmation) and the Connections card on Admin › Users › person (admins disconnect, auditors read). */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { redirectTo } from "../components/providers/labels";
import { NARROW_QUERY } from "@/lib/bitop-utils";
import { myTeam, page, user } from "./fixtures";
import { connection, connectionId, connectServer, googleId, providerId, providerRef, providerSummaries } from "./fixtures-providers";
import { type Handler, Reply, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const authorizeUrl = "https://github.com/login/oauth/authorize?client_id=Iv1.abc123&state=s1";
const started: Schemas["ConnectStarted"] = { authorizeUrl, scopes: ["repo", "read:org"], expiresAt: "2026-10-16T08:10:00Z" };
const google = connection({ id: "c2", provider: providerRef({ id: googleId, slug: "google", name: "Google", preset: "google" }), accountLabel: null, status: "needs_reconsent", scopes: ["openid"], lastUsedAt: null });

const routes = (extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", "member"),
  "GET /v1/me/connections": () => [connection(), google],
  "GET /v1/auth-providers": () => providerSummaries,
  "POST /v1/me/connections/start": () => started,
  ...extra,
});

afterEach(() => vi.restoreAllMocks());

describe("Account › My connections", () => {
  it("lists the person's accounts: provider, account, scopes, status and last use", async () => {
    mockApi(routes());
    const { container } = renderApp("/settings/connections");
    expect(await screen.findByRole("heading", { level: 1, name: "My connections" })).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Your connected accounts" });
    const github = (await within(table).findByText("GitHub")).closest("tr")!;
    expect(github).toHaveTextContent("Account: octocat");
    expect(github).toHaveTextContent("repo, read:org");
    expect(github).toHaveTextContent("Active");
    const g = within(table).getByText("Google").closest("tr")!;
    expect(g).toHaveTextContent("Needs reconnecting");
    expect(g).toHaveTextContent("Not used yet");
    await waitFor(() => expect(document.title).toBe("My connections · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("lists the servers an account is allowed for, with their teams; a connection nobody may use says so", async () => {
    const u = userEvent.setup();
    const allowedServers = [
      { server: connectServer(), origin: "https://tools.example.com", scopes: ["repo"], consentedAt: "2026-10-16T08:00:00Z" },
      { server: connectServer({ id: "s2", slug: "docs", name: "Docs", teamSlug: "writers", teamName: "Writers" }), origin: "https://docs.example.com", scopes: ["repo"], consentedAt: "2026-10-16T08:01:00Z" },
    ];
    mockApi(routes({ "GET /v1/me/connections": () => [connection({ allowedServers }), google] }));
    renderApp("/settings/connections");
    const table = await screen.findByRole("table", { name: "Your connected accounts" });
    const github = (await within(table).findByText("GitHub")).closest("tr")!;
    expect(github).toHaveTextContent("GitHub tools (Platform tools), Docs (Writers)");
    expect(github).toHaveTextContent("GitHub tools: https://tools.example.com");
    expect(within(table).getByText("Google").closest("tr")).toHaveTextContent("None yet");
    // Disconnecting says the servers are asked again.
    await u.click(within(table).getByRole("button", { name: "Actions for GitHub" }));
    await u.click(await screen.findByRole("menuitem", { name: "Disconnect…" }));
    expect(await screen.findByRole("alertdialog", { name: "Disconnect GitHub?" })).toHaveTextContent("You will also be asked again to allow each of the 2 servers that may use it now.");
  });

  it("explains when connections are needed when there are none", async () => {
    mockApi(routes({ "GET /v1/me/connections": () => [] }));
    renderApp("/settings/connections");
    expect(await screen.findByText("No connected accounts.")).toBeInTheDocument();
    expect(screen.getByText(/The first time you use one, your AI client shows a link to connect your account here/)).toBeInTheDocument();
  });

  it("disconnects after confirming, and the list loads again", async () => {
    const u = userEvent.setup();
    let list = [connection(), google];
    const calls = mockApi(
      routes({
        "GET /v1/me/connections": () => list,
        [`DELETE /v1/me/connections/${connectionId}`]: () => {
          list = [google];
          return { ok: true };
        },
      }),
    );
    renderApp("/settings/connections");
    const table = await screen.findByRole("table", { name: "Your connected accounts" });
    await u.click(await within(table).findByRole("button", { name: "Actions for GitHub" }));
    await u.click(await screen.findByRole("menuitem", { name: "Disconnect…" }));
    const ask = await screen.findByRole("alertdialog", { name: "Disconnect GitHub?" });
    expect(ask).toHaveTextContent("Its tokens are erased now");
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    await u.click(within(ask).getByRole("button", { name: "Disconnect" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url === `/v1/me/connections/${connectionId}`)).toBe(true));
    await waitFor(() => expect(within(table).queryByText("GitHub")).toBeNull());
    expect(await screen.findByText("GitHub was disconnected")).toBeInTheDocument();
  });

  it("connects again with the granted scopes, and sends the browser to the provider", async () => {
    const u = userEvent.setup();
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const calls = mockApi(routes());
    renderApp("/settings/connections");
    const table = await screen.findByRole("table", { name: "Your connected accounts" });
    await u.click(await within(table).findByRole("button", { name: "Actions for Google" }));
    await u.click(await screen.findByRole("menuitem", { name: "Reconnect" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith(authorizeUrl));
    const post = calls.find((c) => c.method === "POST" && c.url === "/v1/me/connections/start")!;
    expect(post.body).toEqual({ providerId: googleId, scopes: ["openid"], returnTo: "/settings/connections?connected=google" });
    expect(post.headers.get("X-CSRF-Token")).toBe("csrf-123");
  });

  it("comes back from the provider with a notice naming the connection, only when it's active", async () => {
    const u = userEvent.setup();
    mockApi(routes());
    const { container, router } = renderApp("/settings/connections?connected=github");
    const notice = await screen.findByText("GitHub is connected");
    expect(notice.closest('[role="status"]')).toHaveTextContent(/run it again in your AI client/);
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Dismiss" }));
    await waitFor(() => expect(screen.queryByText("GitHub is connected")).toBeNull());
    expect(router.state.location.search).toEqual({});
  });

  it("says nothing for a connection that isn't active, or an unknown or made-up provider", async () => {
    for (const at of ["/settings/connections?connected=google", "/settings/connections?connected=%3Cb%3Eevil", "/settings/connections?connected=gitlab"]) {
      mockApi(routes());
      const { unmount } = renderApp(at);
      await screen.findByRole("table", { name: "Your connected accounts" });
      expect(screen.queryByText(/is connected$/)).toBeNull();
      expect(screen.queryByText(/evil/)).toBeNull();
      unmount();
    }
  });

  it("keeps the provider and status in view on a phone", async () => {
    vi.stubGlobal("matchMedia", (q: string) => ({
      matches: q === NARROW_QUERY,
      media: q,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
    }));
    try {
      mockApi(routes());
      renderApp("/settings/connections");
      const table = await screen.findByRole("table", { name: "Your connected accounts" });
      const headers = within(table)
        .getAllByRole("columnheader")
        .map((h) => h.textContent ?? "");
      expect(headers.some((h) => h.includes("Provider"))).toBe(true);
      expect(headers.some((h) => h.includes("Status"))).toBe(true);
      expect(headers.some((h) => /Scopes|Last used|Connected/.test(h))).toBe(false);
      expect((await within(table).findByText("GitHub")).closest("tr")).toHaveTextContent("Account: octocat");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("connects an account ahead of time with the provider's default scopes", async () => {
    const u = userEvent.setup();
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const calls = mockApi(routes({ "GET /v1/me/connections": () => [] }));
    renderApp("/settings/connections");
    await u.click((await screen.findAllByRole("button", { name: "Connect account" }))[0]!);
    const dialog = await screen.findByRole("dialog", { name: "Connect an account" });
    expect(within(dialog).getByText("Asks for repo.")).toBeInTheDocument();
    expect(await axe(dialog)).toHaveNoViolations();
    await u.click(within(dialog).getByRole("button", { name: "Continue to GitHub" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith(authorizeUrl));
    expect(calls.find((c) => c.url === "/v1/me/connections/start")!.body).toEqual({ providerId, returnTo: "/settings/connections?connected=github" });
  });

  it("never leaves for an address that isn't http(s), and shows a refused start", async () => {
    const u = userEvent.setup();
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    mockApi(routes({ "GET /v1/me/connections": () => [], "POST /v1/me/connections/start": () => ({ ...started, authorizeUrl: "javascript:alert(1)" }) }));
    renderApp("/settings/connections");
    await u.click((await screen.findAllByRole("button", { name: "Connect account" }))[0]!);
    const dialog = await screen.findByRole("dialog");
    await u.click(within(dialog).getByRole("button", { name: "Continue to GitHub" }));
    expect(await within(dialog).findByText(/an address your browser can't go to/)).toBeInTheDocument();
    expect(go).not.toHaveBeenCalled();
  });
});

describe("command palette", () => {
  it("finds My connections by the words people use, and the account menu links it", async () => {
    const u = userEvent.setup();
    mockApi(routes());
    const { router } = renderApp("/");
    await screen.findByRole("heading", { level: 1, name: "Welcome, Una" });
    await u.keyboard("{Control>}k{/Control}");
    const dialog = await screen.findByRole("dialog", { name: "Command palette" });
    await u.type(within(dialog).getByRole("combobox", { name: "Command palette" }), "github");
    expect(within(dialog).getByRole("option", { name: /My connections/ })).toBeInTheDocument();
    await u.keyboard("{Enter}");
    await waitFor(() => expect(router.state.location.pathname).toBe("/settings/connections"));
  });
});

describe("Admin › Users › person › Connections", () => {
  const other = user({ id: "77777777-7777-4777-8777-777777777777", email: "pat@example.com", displayName: "Pat Person" });
  const adminRoutes = (role: "platform_admin" | "platform_auditor", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
    ...shellRoutes(role),
    [`GET /v1/admin/users/${other.id}`]: () => ({ user: other, teams: [myTeam("member")] }),
    [`GET /v1/admin/users/${other.id}/oauth-grants`]: () => [],
    [`GET /v1/admin/users/${other.id}/connections`]: () => [connection()],
    "GET /v1/admin/audit": () => page([]),
    ...extra,
  });

  it("lets platform admins disconnect a person's account after confirming", async () => {
    const u = userEvent.setup();
    const calls = mockApi(adminRoutes("platform_admin", { [`DELETE /v1/admin/users/${other.id}/connections/${connectionId}`]: () => ({ ok: true }) }));
    const { container } = renderApp(`/admin/users/${other.id}`);
    const table = await screen.findByRole("table", { name: "Accounts Pat Person connected" });
    expect(await within(table).findByText("GitHub")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(within(table).getByRole("button", { name: "Actions for GitHub" }));
    expect(screen.queryByRole("menuitem", { name: "Connect again" })).toBeNull();
    await u.click(await screen.findByRole("menuitem", { name: "Disconnect…" }));
    const ask = await screen.findByRole("alertdialog", { name: "Disconnect GitHub for Pat Person?" });
    await u.click(within(ask).getByRole("button", { name: "Disconnect" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url.endsWith(`/connections/${connectionId}`))).toBe(true));
  });

  it("is read-only for auditors", async () => {
    mockApi(adminRoutes("platform_auditor"));
    renderApp(`/admin/users/${other.id}`);
    const table = await screen.findByRole("table", { name: "Accounts Pat Person connected" });
    expect(await within(table).findByText("GitHub")).toBeInTheDocument();
    expect(within(table).queryByRole("button", { name: "Actions for GitHub" })).toBeNull();
  });

  it("shows a load error in the card without breaking the page", async () => {
    mockApi(adminRoutes("platform_admin", { [`GET /v1/admin/users/${other.id}/connections`]: () => Reply.error(500, "internal", "Boom") }));
    renderApp(`/admin/users/${other.id}`);
    expect(await screen.findByText("Boom")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: "Pat Person" })).toBeInTheDocument();
  });
});
