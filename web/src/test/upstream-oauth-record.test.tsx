/*
 * A server in OAuth mode (docs/phase7-upstream-oauth.md): the Overview's sign-in card (read as, Re-authorize as
 * me, people signed in), health "requires sign-in", the setup notices, Test and Refresh results; Settings
 * (replace-only secret, If-Match, review and sign-in warnings); Admin's review dialog and list filter.
 */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { redirectTo } from "../components/providers/labels";
import { capabilities, healthCheck, mcpServer, page, serverId, team, teamPublishing, teamSummary } from "./fixtures";
import { detectResult, githubUrl, oauthServer, setupConnection } from "./fixtures-oauth";
import { serverRequirement } from "./fixtures-providers";
import { type Call, type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

type Role = Schemas["TeamRole"];
const base = `/v1/teams/${team.slug}/mcp-servers`;
const record = `/teams/${team.slug}/servers/${serverId}`;
const authorizeUrl = "https://github.com/login/oauth/authorize?client_id=Iv1.c0ffee&state=s2";

const routes = (role: Role = "editor", server: Schemas["McpServer"] = oauthServer(), extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", role),
  [`GET ${base}`]: () => page([server]),
  [`GET ${base}/${serverId}`]: () => server,
  [`GET ${base}/${serverId}/capabilities`]: () => capabilities,
  [`GET ${base}/${serverId}/health-checks`]: () => [healthCheck({ signInRequired: true })],
  [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing(),
  [`GET /v1/auth-providers`]: () => [],
  [`POST ${base}/${serverId}/oauth/authorize-setup`]: () => ({ authorizeUrl, scopes: ["repo"], expiresAt: "2026-10-16T08:10:00Z" }),
  ...extra,
});

const patches = (calls: Call[]) => calls.filter((c) => c.method === "PATCH" && c.url === `${base}/${serverId}`);
const lapsed = oauthServer({}, { setupConnection: setupConnection({ status: "needs_reconsent" }) });

afterEach(() => vi.restoreAllMocks());

describe("OAuth server › Overview", () => {
  it("shows the sign-in, as whom the capabilities were read, people signed in, and Re-authorize as me", async () => {
    const u = userEvent.setup();
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const calls = mockApi(routes());
    const { container } = renderApp(record);
    const card = (await screen.findByRole("heading", { name: "Sign-in" })).closest("section")!;
    expect(card).toHaveTextContent("Sign-in with OAuth, per person");
    expect(card).toHaveTextContent("https://github.com/login/oauth");
    expect(card).toHaveTextContent("Another host: github.com");
    expect(card).toHaveTextContent("A client ID and secret the team entered (client ID ending in c0ffee)");
    expect(card).toHaveTextContent("repo, read:org, read:user");
    expect(card).toHaveTextContent("Capabilities read asAna Editor");
    expect(card).toHaveTextContent("12 people");
    expect(card).toHaveTextContent("Not sent: the server doesn't learn who's calling");
    expect(card).toHaveTextContent("The caller's own token in Authorization: Bearer.");
    expect(screen.getAllByText("Reachable — requires sign-in").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Sign-in per person").length).toBeGreaterThan(0);
    // A requirement doesn't apply: the call carries the person's own token for the server.
    expect(screen.queryByRole("heading", { name: "User authorization" })).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(within(card).getByRole("button", { name: "Re-authorize as me" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith(authorizeUrl));
    expect(calls.some((c) => c.method === "POST" && c.url.endsWith("/oauth/authorize-setup"))).toBe(true);
  });

  it("says as whom the capabilities were read after the setup sign-in (?setup=connected)", async () => {
    const u = userEvent.setup();
    mockApi(routes());
    const { router } = renderApp(`${record}?setup=connected`);
    const notice = await screen.findByText("Capabilities read as Ana Editor");
    await u.click(within(notice.closest("[role=status]") as HTMLElement).getByRole("button", { name: "Dismiss" }));
    await waitFor(() => expect(router.state.location.search).not.toHaveProperty("setup"));
  });

  it("asks an editor to sign in again when the setup sign-in lapsed; members are told who can", async () => {
    mockApi(routes("editor", lapsed, { [`POST ${base}/${serverId}/refresh`]: () => Reply.error(409, "setup_reconsent_required", "re-consent", { status: "needs_reconsent" }) }));
    const u = userEvent.setup();
    const { unmount } = renderApp(record);
    const notice = (await screen.findByText("Ana Editor's sign-in that reads its capabilities has lapsed")).closest("[role=status]") as HTMLElement;
    expect(within(notice).getByRole("button", { name: "Authorize to read its tools" })).toBeInTheDocument();
    expect(screen.getByText("Ana Editor · needs sign-in again")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: /Refresh capabilities/ }));
    expect(await screen.findByText("Nobody's sign-in can read the capabilities")).toBeInTheDocument();
    unmount();

    mockApi(routes("member", lapsed));
    renderApp(record);
    const forMember = (await screen.findByText("Ana Editor's sign-in that reads its capabilities has lapsed")).closest("[role=status]") as HTMLElement;
    expect(forMember).toHaveTextContent("An editor, admin or owner of the team signs in to read them.");
    expect(within(forMember).queryByRole("button")).toBeNull();
  });

  it("shows as whom a test signed in, or that it couldn't", async () => {
    const u = userEvent.setup();
    let result: Schemas["McpTestResult"] = { ok: true, latencyMs: 90, readAs: "Ana Editor", counts: { tools: 40, resources: 0, resourceTemplates: 0, prompts: 0 } };
    mockApi(routes("editor", oauthServer(), { [`POST ${base}/${serverId}/test`]: () => result }));
    renderApp(record);
    await u.click(await screen.findByRole("button", { name: /Test connection/ }));
    expect(await screen.findByText(/Signed in as Ana Editor\./)).toBeInTheDocument();
    result = { ok: false, latencyMs: 0, errorClass: "auth", setupRequired: true, readAs: null };
    await u.click(screen.getByRole("button", { name: /Test connection/ }));
    expect(await screen.findByText("The test couldn't sign in")).toBeInTheDocument();
  });
});

describe("OAuth server › Settings", () => {
  it("keeps the client secret unless one is typed, and sends only what changed with If-Match", async () => {
    const u = userEvent.setup();
    let current = oauthServer();
    const calls = mockApi(
      routes("editor", current, {
        [`GET ${base}/${serverId}`]: () => current,
        [`PATCH ${base}/${serverId}`]: () => (current = oauthServer({ revision: current.revision + 1 }, { scopes: ["repo", "read:org", "read:user", "gist"] })),
      }),
    );
    const { container } = renderApp(`${record}?tab=settings`);
    expect(await screen.findByLabelText("Replace client secret")).toHaveValue("");
    expect(screen.getByText("Stored encrypted. Leave empty to keep it. It's never shown again.")).toBeInTheDocument();
    expect(screen.getByText(/The stored one ends in c0ffee/)).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "Send identity token" })).not.toBeChecked();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("checkbox", { name: "gist" }));
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(1));
    const first = patches(calls)[0]!;
    expect(first.headers.get("If-Match")).toBe('"4"');
    expect((first.body as Schemas["McpServerUpdate"]).oauth).toEqual({ registration: "manual", sendResource: true, scopes: ["repo", "read:org", "read:user", "gist"] });
    expect(first.body).not.toHaveProperty("authMode");
    expect(first.body).not.toHaveProperty("sendIdentity");

    await u.type(screen.getByLabelText("Replace client secret"), "n3w-s3cret");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(2));
    expect((patches(calls)[1]!.body as Schemas["McpServerUpdate"]).oauth).toEqual({ registration: "manual", sendResource: true, clientSecret: "n3w-s3cret" });
    expect(patches(calls)[1]!.headers.get("If-Match")).toBe('"5"');
  });

  it("warns that switching a published server to OAuth sends it back to review, and drops the Authorization header and the requirement", async () => {
    const u = userEvent.setup();
    const published = mcpServer({ url: githubUrl, publishState: "published", requirement: serverRequirement() });
    const calls = mockApi(routes("editor", published, { [`POST ${base}/detect-auth`]: () => detectResult(), [`PATCH ${base}/${serverId}`]: () => oauthServer({ publishState: "pending", revision: 5 }) }));
    renderApp(`${record}?tab=settings`);
    expect(await screen.findByRole("radio", { name: /^Static credential/ })).toBeChecked();
    expect(screen.getByRole("radio", { name: "Sign-in with OAuth, per person" })).toHaveAttribute("aria-disabled", "true");
    await u.click(screen.getByRole("button", { name: "Detect sign-in" }));
    await waitFor(() => expect(screen.getByRole("radio", { name: "Sign-in with OAuth, per person" })).toBeChecked());
    expect(screen.getByText(/this is a switch to OAuth sign-in, so it's reviewed again/)).toBeInTheDocument();
    expect(screen.getByText(/Saving removes the requirement \(GitHub\)/)).toBeInTheDocument();
    expect(screen.getByText("Saving takes the server out of the catalog until it's reviewed again")).toBeInTheDocument();
    await u.type(screen.getByRole("textbox", { name: "Client ID" }), "Iv1.c0ffee");
    await u.type(screen.getByLabelText("Client secret"), "s3cret");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(1));
    expect(patches(calls)[0]!.body).toMatchObject({
      authMode: "oauth",
      credentials: [],
      requirement: null,
      oauth: { registration: "manual", clientId: "Iv1.c0ffee", clientSecret: "s3cret", tokenAuthMethod: "client_secret_post", scopes: ["repo", "read:org", "read:user"], sendResource: true },
    });
  });

  it("warns about a new scope on a published server, and that leaving OAuth deletes everyone's sign-ins", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("editor", oauthServer({ publishState: "published" }), { [`PATCH ${base}/${serverId}`]: () => mcpServer({ revision: 5 }) }));
    renderApp(`${record}?tab=settings`);
    await u.click(await screen.findByRole("checkbox", { name: "workflow" }));
    expect(screen.getByText(/this is a scope it didn't ask for before/)).toBeInTheDocument();
    await u.click(screen.getByRole("checkbox", { name: "workflow" }));
    expect(screen.queryByText(/a scope it didn't ask for before/)).toBeNull();
    await u.click(screen.getByRole("radio", { name: /^None/ }));
    expect(screen.getByText(/deletes the sign-ins of the 12 people signed in to GitHub MCP/)).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(1));
    expect(patches(calls)[0]!.body).toMatchObject({ authMode: "none" });
    expect(patches(calls)[0]!.body).not.toHaveProperty("oauth");
  });

  it("explains a refused save", async () => {
    const u = userEvent.setup();
    mockApi(routes("editor", oauthServer(), { [`PATCH ${base}/${serverId}`]: () => Reply.error(422, "client_required", "client required") }));
    renderApp(`${record}?tab=settings`);
    await u.click(await screen.findByRole("checkbox", { name: "gist" }));
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText(/Enter the client\. Enter the client ID and secret of the OAuth app/)).toBeInTheDocument();
  });
});

describe("Admin › OAuth servers", () => {
  const pending = oauthServer({ publishState: "pending", publishRequestedAt: "2026-10-15T10:00:00Z" });
  const adminRoutes = (extra: Record<string, Handler> = {}): Record<string, Handler> => ({
    ...shellRoutes("platform_admin", null),
    "GET /v1/admin/mcp-servers": () => page([pending, mcpServer({ id: "s2", name: "Wiki search", slug: "wiki" })]),
    [`GET /v1/admin/mcp-servers/${serverId}`]: () => pending,
    [`GET /v1/admin/mcp-servers/${serverId}/capabilities`]: () => capabilities,
    [`GET /v1/admin/mcp-servers/${serverId}/health-checks`]: () => [healthCheck()],
    "GET /v1/admin/teams": () => page([teamSummary()]),
    "GET /v1/admin/auth-providers": () => [],
    ...extra,
  });

  it("shows reviewers what the server receives: the sign-in, its authorization server, scopes, registration and identity", async () => {
    const u = userEvent.setup();
    mockApi(adminRoutes());
    renderApp(`/admin/servers/${serverId}`);
    await u.click(await screen.findByRole("button", { name: "Approve…" }));
    const dialog = await screen.findByRole("dialog");
    const what = within(dialog).getByRole("region", { name: "What the server receives" });
    expect(what).toHaveTextContent("Sign-in with OAuth, per person");
    expect(what).toHaveTextContent("https://github.com/login/oauth");
    expect(what).toHaveTextContent("Another host: github.com");
    expect(what).toHaveTextContent("A client ID and secret the team entered");
    expect(what).toHaveTextContent("repo, read:org, read:user");
    expect(what).toHaveTextContent("Sent: tokens work only for this server");
    expect(what).toHaveTextContent("Not sent: the server doesn't learn who's calling");
    expect(what).not.toHaveTextContent("On behalf of callers");
    expect(await axe(dialog)).toHaveNoViolations();
  });

  it("filters the list by authentication and badges OAuth servers", async () => {
    const calls = mockApi(adminRoutes());
    renderApp("/admin/servers?authMode=oauth");
    const table = await screen.findByRole("table", { name: "MCP servers" });
    const row = (await within(table).findByText("GitHub MCP")).closest("tr")!;
    expect(within(row).getByText("Sign-in per person")).toBeInTheDocument();
    expect(within(within(table).getByText("Wiki search").closest("tr")!).queryByText("Sign-in per person")).toBeNull();
    await waitFor(() => expect(calls.some((c) => c.url === "/v1/admin/mcp-servers" && c.search.get("authMode") === "oauth")).toBe(true));
  });
});
