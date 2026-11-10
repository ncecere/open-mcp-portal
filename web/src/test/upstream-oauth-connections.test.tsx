/*
 * Sign-ins to MCP servers in OAuth mode wherever connections and needs show (docs/phase7-upstream-oauth.md): My
 * connections and Admin › Users labelled with the server, the connect and done pages, "Needs sign-in to …" badges,
 * My gateways' Sign in, the catalog's badge, and the audit words.
 */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { auditChange, changedRows } from "../components/audit/changes";
import { actionLabel } from "../components/audit/labels";
import { redirectTo } from "../components/providers/labels";
import { catalogServer, gateway, gatewayCapabilities, gatewayCapability, gatewayId, myGateway, myTeam, page, serverId, team, user } from "./fixtures";
import { serverConnection, serverProviderId, serverRequires } from "./fixtures-oauth";
import { connection, connectRequest, providerRef, providerSummaries, requestId } from "./fixtures-providers";
import { mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const serverRef = providerRef({ id: serverProviderId, slug: "mcp-0a1b2c3d4e5f", name: "GitHub MCP", preset: null, kind: "mcp_server", server: { id: serverId, slug: "github", name: "GitHub MCP", teamSlug: team.slug } });

afterEach(() => vi.restoreAllMocks());

describe("Server sign-ins in connections", () => {
  it("are named after the server on My connections, with an MCP server badge and the team", async () => {
    const u = userEvent.setup();
    mockApi({ ...shellRoutes("none", "member"), "GET /v1/me/connections": () => [connection(), serverConnection()], "GET /v1/auth-providers": () => providerSummaries });
    const { container } = renderApp("/settings/connections");
    const table = await screen.findByRole("table", { name: "Your connected accounts" });
    const row = (await within(table).findByText("GitHub MCP")).closest("tr")!;
    expect(within(row).getByText("MCP server")).toBeInTheDocument();
    expect(row).toHaveTextContent(`Team: ${team.slug}`);
    expect(row).toHaveTextContent("repo, read:org, read:user");
    expect(await axe(container)).toHaveNoViolations();
    await u.click(within(table).getByRole("button", { name: "Actions for GitHub MCP" }));
    await u.click(await screen.findByRole("menuitem", { name: "Disconnect…" }));
    const ask = await screen.findByRole("alertdialog", { name: "Disconnect GitHub MCP?" });
    expect(ask).toHaveTextContent("GitHub MCP sign-in ask you to connect it again");
  });

  it("are named after the server on a person's admin page", async () => {
    const other = user({ id: "77777777-7777-4777-8777-777777777777", email: "pat@example.com", displayName: "Pat Person" });
    mockApi({
      ...shellRoutes("platform_admin"),
      [`GET /v1/admin/users/${other.id}`]: () => ({ user: other, teams: [myTeam("member")] }),
      [`GET /v1/admin/users/${other.id}/oauth-grants`]: () => [],
      [`GET /v1/admin/users/${other.id}/connections`]: () => [serverConnection()],
      "GET /v1/admin/audit": () => page([]),
    });
    renderApp(`/admin/users/${other.id}`);
    const table = await screen.findByRole("table", { name: "Accounts Pat Person connected" });
    const row = (await within(table).findByText("GitHub MCP")).closest("tr")!;
    expect(within(row).getByText("MCP server")).toBeInTheDocument();
  });
});

describe("Connect pages for a server sign-in", () => {
  it("name the server and sign the person in to it", async () => {
    const u = userEvent.setup();
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const authorizeUrl = "https://github.com/login/oauth/authorize?client_id=Iv1.c0ffee&state=s3";
    const request = connectRequest({
      provider: serverRef,
      reason: "not_connected",
      grantedScopes: [],
      accountLabel: null,
      requestScopes: ["repo", "read:org", "read:user"],
      capability: { kind: "tool", exposedName: "github__get_me", title: "Get me" },
    });
    const calls = mockApi({
      ...shellRoutes(),
      [`GET /v1/connect/requests/${requestId}`]: () => request,
      "POST /v1/me/connections/start": () => ({ authorizeUrl, scopes: request.requestScopes, expiresAt: "2026-10-16T08:10:00Z" }),
    });
    const { container } = renderApp(`/connect/mcp-0a1b2c3d4e5f?request=${requestId}`);
    expect(await screen.findByRole("heading", { level: 1, name: "Sign in to GitHub MCP" })).toBeInTheDocument();
    expect(screen.getByText("The tool github__get_me needs you to sign in to GitHub MCP, so it can act as you there.")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "The request" })).toHaveTextContent(`MCP serverGitHub MCP (team ${team.slug})`);
    expect(within(screen.getByRole("list", { name: "Signing in to GitHub MCP asks you to allow" })).getAllByRole("listitem")).toHaveLength(3);
    expect(screen.getByText(/sends it only to GitHub MCP\./)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Continue to sign in" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith(authorizeUrl));
    expect(calls.find((c) => c.url === "/v1/me/connections/start")?.body).toEqual({ providerId: serverProviderId, requestId });
  });

  it("say which server the person signed in to on the done page", async () => {
    mockApi({ ...shellRoutes(), "GET /v1/auth-providers": () => providerSummaries, "GET /v1/me/connections": () => [serverConnection()] });
    renderApp("/connect/done?provider=mcp-0a1b2c3d4e5f&result=connected");
    expect(await screen.findByRole("heading", { level: 1, name: "Connected to GitHub MCP" })).toBeInTheDocument();
  });
});

describe("Needs sign-in badges", () => {
  const needsSignIn = gatewayCapability({ name: "get_me", exposedName: "github__get_me", serverName: "GitHub MCP", requires: serverRequires() });

  it("say a capability needs a sign-in to its server, on a gateway's Capabilities tab", async () => {
    const gw = `/v1/teams/${team.slug}/gateways`;
    mockApi({ ...shellRoutes("none", "owner"), [`GET ${gw}/${gatewayId}`]: () => gateway(), [`GET ${gw}/${gatewayId}/capabilities`]: () => gatewayCapabilities([needsSignIn]) });
    renderApp(`/teams/${team.slug}/gateways/${gatewayId}?tab=capabilities`);
    const row = await screen.findByRole("listitem", { name: "tool: github__get_me" });
    const badge = within(row).getByText("Needs sign-in to GitHub MCP");
    expect(badge.getAttribute("title")).toContain("Each person signs in to GitHub MCP and allows repo, read:org, read:user.");
  });

  it("offer Sign in to the server on My gateways", async () => {
    const u = userEvent.setup();
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const authorizeUrl = "https://github.com/login/oauth/authorize?state=s4";
    const calls = mockApi({
      ...shellRoutes("none", "member"),
      [`GET /v1/me/gateways/${gatewayId}`]: (): Schemas["MyGatewayDetail"] => ({ gateway: myGateway(), capabilities: [{ ...needsSignIn, requires: serverRequires({ connected: false }) }] }),
      "POST /v1/me/connections/start": () => ({ authorizeUrl, scopes: ["repo"], expiresAt: "2026-10-16T08:10:00Z" }),
    });
    const { container } = renderApp(`/gateways/${gatewayId}`);
    const table = await screen.findByRole("table", { name: "Accounts this gateway needs" });
    const row = within(table).getByText("GitHub MCP").closest("tr")!;
    expect(row).toHaveTextContent("MCP server sign-in");
    expect(await axe(container)).toHaveNoViolations();
    await u.click(within(row).getByRole("button", { name: "Sign in to GitHub MCP" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith(authorizeUrl));
    expect(calls.find((c) => c.url === "/v1/me/connections/start")?.body).toMatchObject({ providerId: serverProviderId });
  });

  it("show in the catalog, with the server's Sign-in per person badge", async () => {
    mockApi({
      ...shellRoutes("none", null),
      "GET /v1/catalog/servers": () => page([catalogServer({ authMode: "oauth" }), catalogServer({ id: "other", name: "Wiki", slug: "wiki" })]),
      [`GET /v1/catalog/servers/${serverId}`]: (): Schemas["CatalogServerDetail"] => ({
        server: catalogServer({ authMode: "oauth" }),
        capabilities: [{ id: "c1", kind: "tool", name: "get_me", title: "", description: "Who am I.", definition: { name: "get_me" }, requires: serverRequires() }],
      }),
    });
    const { unmount } = renderApp("/catalog");
    const table = await screen.findByRole("table", { name: "Published MCP servers" });
    expect(within((await within(table).findByText("Service status")).closest("tr")!).getByText("Sign-in per person")).toBeInTheDocument();
    expect(within(within(table).getByText("Wiki").closest("tr")!).queryByText("Sign-in per person")).toBeNull();
    unmount();
    renderApp(`/catalog/${serverId}`);
    expect(await screen.findByText("Each person signs in to Service status")).toBeInTheDocument();
    expect(within(screen.getByRole("listitem", { name: "tool: get_me" })).getByText("Needs sign-in to GitHub MCP")).toBeInTheDocument();
  });
});

describe("Audit words for server sign-in", () => {
  it("name the sign-in change and its fields, and why a sign-in was revoked", () => {
    expect(actionLabel("mcp_server.auth_update")).toBe("Changed MCP server sign-in");
    expect(actionLabel("provider_connection.revoke", { metadata: { reason: "server_auth_changed" } })).toBe("Disconnected account when its MCP server's sign-in changed");
    expect(actionLabel("provider_connection.revoke", { metadata: { reason: "server_deleted" } })).toBe("Disconnected account when its MCP server was deleted");
    expect(actionLabel("mcp_server.publish_request", { metadata: { reason: "upstream_auth_changed" } })).toBe("Requested catalog review after its sign-in changed");
    const e = {
      action: "mcp_server.auth_update",
      before: { mode: "static_header", scopes: [] },
      after: { mode: "oauth", registration: "manual", authorizationServer: "https://github.com/login/oauth", scopes: ["repo"], sendResource: true, clientIdChanged: true },
    };
    expect(changedRows(auditChange(e))).toEqual([
      { field: "Authentication", before: "Static header", after: "OAuth sign-in per person" },
      { field: "Scopes", before: [], after: ["repo"] },
      { field: "Registration", before: undefined, after: "Client entered by the team" },
      { field: "Authorization server", before: undefined, after: "https://github.com/login/oauth" },
      { field: "Resource indicator", before: undefined, after: "On" },
      { field: "New client ID", before: undefined, after: "Yes" },
    ]);
  });
});
