/*
 * A server's user-authorization requirement: Settings' "Requires a connection" (provider and scopes), the warning
 * that widening sends a published server back to review (and that narrowing doesn't), capability overrides on the
 * Capabilities tab, and what Admin's record and review show.
 */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { serverChangeWidens, widens } from "../components/servers/requirement";
import { capabilities, capability, healthCheck, mcpServer, page, serverId, team, teamPublishing } from "./fixtures";
import { googleId, providerId, providerSummaries, requires, serverRequirement } from "./fixtures-providers";
import { type Call, type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

type McpServer = Schemas["McpServer"];
const base = `/v1/teams/${team.slug}/mcp-servers`;
const recordPath = `/teams/${team.slug}/servers/${serverId}`;
const patches = (calls: Call[]) => calls.filter((c) => c.method === "PATCH" && c.url === `${base}/${serverId}`);

const withGithub = mcpServer({ requirement: serverRequirement() });
const capsWithGithub = [
  capability({ requires: requires() }),
  capability({ id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", name: "restart", requirementOverride: { mode: "none" }, requires: null }),
];

const routes = (role: Schemas["TeamRole"], server: McpServer, caps: Schemas["McpCapability"][] = capabilities, extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", role),
  [`GET ${base}`]: () => page([server]),
  [`GET ${base}/${serverId}`]: () => server,
  [`GET ${base}/${serverId}/capabilities`]: () => caps,
  [`GET ${base}/${serverId}/health-checks`]: () => [healthCheck()],
  [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing({ effective: server.effectivePublishPolicy }),
  "GET /v1/auth-providers": () => providerSummaries,
  [`PATCH ${base}/${serverId}`]: (body) => ({ ...server, revision: server.revision + 1, requirement: (body as { requirement?: unknown }).requirement ? serverRequirement() : null }),
  ...extra,
});

describe("Settings › User authorization", () => {
  it("requires a connection: a provider from the list and its scopes, saved with the server", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("editor", mcpServer()));
    const { container } = renderApp(`${recordPath}?tab=settings`);
    expect(await screen.findByText(/Each person who calls these capabilities connects their own account/)).toBeInTheDocument();
    await u.click(screen.getByRole("switch", { name: /Requires a connection/ }));
    const provider = await screen.findByRole("combobox", { name: "Provider" });
    expect(provider).toHaveValue(providerId);
    await u.selectOptions(provider, googleId);
    expect(screen.getByText(/Leave empty for the provider's default scopes \(openid, email\)/)).toBeInTheDocument();
    await u.type(screen.getByRole("textbox", { name: /Scopes/ }), "https://www.googleapis.com/auth/drive.readonly{Enter}");
    // A private server never leaves the catalog.
    expect(screen.queryByText("The server will leave the catalog")).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(1));
    expect(patches(calls)[0]!.body).toMatchObject({ requirement: { providerId: googleId, scopes: ["https://www.googleapis.com/auth/drive.readonly"] } });
    expect(patches(calls)[0]!.headers.get("If-Match")).toBe('"4"');
  });

  it("warns that widening a published server's requirement sends it back to review (approval required)", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("editor", mcpServer({ publishState: "published", requirement: serverRequirement() }), capsWithGithub));
    renderApp(`${recordPath}?tab=settings`);
    const scopes = await screen.findByRole("textbox", { name: /Scopes/ });
    await u.type(scopes, "admin:org{Enter}");
    expect(await screen.findByText("The server will leave the catalog")).toBeInTheDocument();
    expect(screen.getByText(/this sends more to the server than before/)).toBeInTheDocument();
    expect(screen.getByText("Saving takes the server out of the catalog until it's reviewed again")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(1));
    expect(patches(calls)[0]!.body).toMatchObject({ requirement: { providerId, scopes: ["repo", "admin:org"] } });
  });

  it("doesn't warn when narrowing or removing a requirement, and sends null to remove it", async () => {
    const u = userEvent.setup();
    const server = mcpServer({ publishState: "published", requirement: serverRequirement({ scopes: ["repo", "read:org"] }) });
    const calls = mockApi(routes("editor", server, [capability({ requires: requires({ scopes: ["repo", "read:org"] }) })]));
    renderApp(`${recordPath}?tab=settings`);
    await u.click(await screen.findByRole("button", { name: "Remove scope read:org" }));
    expect(screen.queryByText("The server will leave the catalog")).toBeNull();
    await u.click(screen.getByRole("switch", { name: /Requires a connection/ }));
    expect(screen.queryByText("The server will leave the catalog")).toBeNull();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(1));
    expect(patches(calls)[0]!.body).toMatchObject({ requirement: null });
  });

  it("says when the chosen provider is turned off, and members only read", async () => {
    mockApi(routes("member", mcpServer({ requirement: serverRequirement({ providerEnabled: false }) })));
    renderApp(`${recordPath}?tab=settings`);
    expect(await screen.findByText("GitHub is turned off")).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: /Requires a connection/ })).toHaveAttribute("aria-disabled", "true");
  });
});

describe("Capabilities › account overrides", () => {
  it("shows what each capability needs, and lets editors override it (If-Match on the server's revision)", async () => {
    const u = userEvent.setup();
    const server = mcpServer({ publishState: "published", requirement: serverRequirement() });
    const calls = mockApi(
      routes("editor", server, capsWithGithub, {
        [`PUT ${base}/${serverId}/capabilities/${capsWithGithub[0]!.id}/requirement`]: (body) =>
          capability({ requirementOverride: body as Schemas["CapabilityRequirementOverride"], requires: requires({ scopes: ["repo", "admin:org"] }) }),
      }),
    );
    const { container } = renderApp(`${recordPath}?tab=capabilities`);
    const tool = await screen.findByRole("listitem", { name: "tool: get_status" });
    expect(within(tool).getByText("Needs GitHub (repo)")).toBeInTheDocument();
    const restart = screen.getByRole("listitem", { name: "tool: restart" });
    expect(within(restart).getByText("No account")).toBeInTheDocument();
    expect(within(restart).queryByText(/Needs GitHub/)).toBeNull();
    expect(screen.getByText("Calls carry the caller's GitHub token")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();

    await u.click(within(tool).getByRole("button", { name: "Change the account get_status needs" }));
    const dialog = await screen.findByRole("dialog", { name: "Account for get_status" });
    // Each option says what it does to callers, to the token and to service accounts.
    expect(dialog).not.toHaveTextContent(/either way/);
    expect(dialog).toHaveTextContent(/Callers connect with the server's scopes, and each call sends their token to .*Service accounts require an explicitly allowed team service connection\./);
    expect(dialog).toHaveTextContent(/Callers are never asked to connect, and calls send no token to .*Service accounts can use it\./);
    expect(dialog).toHaveTextContent(/Callers connect with only the scopes below, and each call sends that token to/);
    await u.click(within(dialog).getByRole("radio", { name: /Other GitHub scopes/ }));
    const scopes = within(dialog).getByRole("textbox", { name: /Scopes/ });
    await u.type(scopes, "admin:org{Enter}");
    expect(within(dialog).getByText("The server will leave the catalog")).toBeInTheDocument();
    await u.click(within(dialog).getByRole("button", { name: "Save" }));
    const put = await waitFor(() => {
      const c = calls.find((x) => x.method === "PUT" && x.url.endsWith("/requirement"));
      expect(c).toBeDefined();
      return c!;
    });
    expect(put.body).toEqual({ mode: "scopes", scopes: ["repo", "admin:org"] });
    expect(put.headers.get("If-Match")).toBe('"4"');
  });

  it("explains 409 no_server_requirement", async () => {
    const u = userEvent.setup();
    mockApi(
      routes("editor", withGithub, capsWithGithub, {
        [`PUT ${base}/${serverId}/capabilities/${capsWithGithub[0]!.id}/requirement`]: () => Reply.error(409, "no_server_requirement", "No requirement"),
      }),
    );
    renderApp(`${recordPath}?tab=capabilities`);
    await u.click(await screen.findByRole("button", { name: "Change the account get_status needs" }));
    const dialog = await screen.findByRole("dialog");
    await u.click(within(dialog).getByRole("radio", { name: /No account/ }));
    await u.click(within(dialog).getByRole("button", { name: "Save" }));
    expect(await within(dialog).findByText(/The server no longer requires a connection/)).toBeInTheDocument();
  });

  it("offers no override to members, or on a server without a requirement", async () => {
    mockApi(routes("member", withGithub, capsWithGithub));
    const { unmount } = renderApp(`${recordPath}?tab=capabilities`);
    await screen.findByRole("listitem", { name: "tool: get_status" });
    expect(screen.queryByRole("button", { name: /Change the account/ })).toBeNull();
    unmount();
    mockApi(routes("editor", mcpServer()));
    renderApp(`${recordPath}?tab=capabilities`);
    await screen.findByRole("listitem", { name: "tool: get_status" });
    expect(screen.queryByRole("button", { name: /Change the account/ })).toBeNull();
  });
});

describe("Admin › server › requirement", () => {
  const pending = mcpServer({ publishState: "pending", publishRequestedAt: "2026-10-15T10:00:00Z", requirement: serverRequirement() });
  const adminRoutes: Record<string, Handler> = {
    ...shellRoutes("platform_admin", null),
    [`GET /v1/admin/mcp-servers/${serverId}`]: () => pending,
    [`GET /v1/admin/mcp-servers/${serverId}/capabilities`]: () => capsWithGithub,
    [`GET /v1/admin/mcp-servers/${serverId}/health-checks`]: () => [healthCheck()],
  };

  it("shows what the server receives on its record and in the review dialog", async () => {
    const u = userEvent.setup();
    mockApi(adminRoutes);
    renderApp(`/admin/servers/${serverId}`);
    expect(await screen.findByRole("heading", { name: "User authorization" })).toBeInTheDocument();
    expect(screen.getByText("MCP-Gateway-Provider-Token")).toBeInTheDocument();
    expect(await screen.findByText("restart")).toBeInTheDocument();
    // The facts line names it too.
    expect(screen.getAllByText("Needs GitHub (repo)").length).toBeGreaterThan(0);
    await u.click(screen.getByRole("button", { name: "Approve…" }));
    const dialog = await screen.findByRole("dialog", { name: /Approve Service status/ });
    const what = within(dialog).getByRole("region", { name: "What the server receives" });
    expect(what).toHaveTextContent("GitHub");
    expect(what).toHaveTextContent("repo");
    expect(what).toHaveTextContent("restart: No account");
  });
});

describe("requirement rules", () => {
  it("widen with a new provider or scope, never by narrowing or removing", () => {
    expect(widens(null, { providerId: "a", scopes: [] })).toBe(true);
    expect(widens({ providerId: "a", scopes: ["x"] }, { providerId: "b", scopes: ["x"] })).toBe(true);
    expect(widens({ providerId: "a", scopes: ["x"] }, { providerId: "a", scopes: ["x", "y"] })).toBe(true);
    expect(widens({ providerId: "a", scopes: ["x", "y"] }, { providerId: "a", scopes: ["x"] })).toBe(false);
    expect(widens({ providerId: "a", scopes: ["x"] }, null)).toBe(false);
  });

  it("count capabilities set to none as unaffected by the server's change", () => {
    const server = { requirement: serverRequirement() };
    const onlyNone = [capability({ requirementOverride: { mode: "none" }, requires: null })];
    expect(serverChangeWidens(server, { on: true, providerId, scopes: ["repo", "admin:org"] }, onlyNone)).toBe(false);
    expect(serverChangeWidens(server, { on: true, providerId, scopes: ["repo", "admin:org"] }, [capability({ requires: requires() })])).toBe(true);
    expect(serverChangeWidens(server, { on: false, providerId: "", scopes: [] }, [capability({ requires: requires() })])).toBe(false);
  });
});
