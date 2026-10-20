/*
 * Browser-QA fixes in the registry: a refused URL clears once it's edited, a new URL sends a published server back
 * to review, rejected servers can be made private, Approve waits for the capabilities read from the current URL,
 * and the wording around tests, health checks, history and untrusted text.
 */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { Schemas } from "../api/client";
import { capabilities, healthCheck, mcpServer, page, serverId, team, teamPublishing } from "./fixtures";
import { type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

type McpServer = Schemas["McpServer"];
const base = `/v1/teams/${team.slug}/mcp-servers`;
const record = `/teams/${team.slug}/servers/${serverId}`;

/** The team's routes, serving whatever `get()` returns now. */
const routes = (role: Schemas["TeamRole"], get: () => McpServer, extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", role),
  [`GET ${base}`]: () => page([get()]),
  [`GET ${base}/${serverId}`]: () => get(),
  [`GET ${base}/${serverId}/capabilities`]: () => capabilities,
  [`GET ${base}/${serverId}/health-checks`]: () => [healthCheck()],
  [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing({ effective: get().effectivePublishPolicy }),
  ...extra,
});

const reviewed = { publishRequestedAt: "2026-10-11T10:00:00Z", publishReviewedAt: "2026-10-12T10:00:00Z", publishReviewedByName: "Ada Admin" };

describe("A refused URL", () => {
  it("clears on Add once the URL is edited, so the form can be sent again; the first read's result gives way to a test", async () => {
    const u = userEvent.setup();
    let refuse = true;
    const created: Schemas["McpServerCreated"] = { server: mcpServer(), refresh: { listed: 4, added: 4, changed: 0, gone: 0, capabilities }, refreshError: null };
    const calls = mockApi(
      routes("editor", () => mcpServer(), {
        [`POST ${base}`]: () => (refuse ? Reply.error(422, "url_not_allowed", "URL not allowed", { reason: "query" }) : new Reply(201, { data: created })),
        [`POST ${base}/${serverId}/test`]: (): Schemas["McpTestResult"] => ({ ok: true, latencyMs: 42 }),
      }),
    );
    renderApp(`/teams/${team.slug}/servers?form=new`);
    await u.type(await screen.findByRole("textbox", { name: "Name" }), "Service status");
    const url = screen.getByRole("textbox", { name: "URL" });
    await u.type(url, "https://status.example.com/mcp?token=1");
    await u.click(screen.getByRole("button", { name: "Add server" }));
    const refusal = "Remove the query (the part from ?) from the address. A key that belongs in the query is added as a query parameter part of the credential below instead.";
    expect(await screen.findByText(refusal)).toBeInTheDocument();

    await u.clear(url);
    await u.type(url, "https://status.example.com/mcp");
    expect(screen.queryByText(refusal)).toBeNull();
    refuse = false;
    await u.click(screen.getByRole("button", { name: "Add server" }));
    const added = await screen.findByText("Added. The first read found 4 capabilities");
    expect(calls.filter((c) => c.method === "POST" && c.url === base)).toHaveLength(2);

    // Its Dismiss is inside the alert; a later Test replaces it.
    expect(within(added.closest("[role=status]") as HTMLElement).getByRole("button", { name: "Dismiss" })).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Test connection" }));
    expect(await screen.findByText("Connected in 42 ms")).toBeInTheDocument();
    expect(screen.getByText(/The capabilities weren't changed/)).toBeInTheDocument();
    expect(screen.queryByText(/Nothing was saved/)).toBeNull();
    expect(screen.queryByText("Added. The first read found 4 capabilities")).toBeNull();
  });

  it("clears in Settings once edited; a new URL on a reviewed, published server warns and says it left the catalog", async () => {
    const u = userEvent.setup();
    let current = mcpServer({ publishState: "published", ...reviewed });
    let refuse = true;
    const calls = mockApi(
      routes("editor", () => current, {
        [`PATCH ${base}/${serverId}`]: (body) => {
          if (refuse) return Reply.error(422, "url_not_allowed", "URL not allowed", { reason: "private_address" });
          current = mcpServer({ ...reviewed, url: (body as { url: string }).url, publishState: "pending", publishRequestedAt: "2026-10-16T09:00:00Z", revision: 5 });
          return current;
        },
      }),
    );
    renderApp(`${record}?tab=settings`);
    const url = await screen.findByRole("textbox", { name: "URL" });
    expect(screen.queryByText("The server will leave the catalog")).toBeNull();
    await u.clear(url);
    await u.type(url, "https://10.0.0.1/mcp");
    expect(screen.getByText("The server will leave the catalog")).toBeInTheDocument();
    // Another host never keeps the stored value (F-1): it is entered again, or the save isn't sent.
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText(/The URL moves to another host, so enter this value again/)).toBeInTheDocument();
    expect(calls.some((c) => c.method === "PATCH")).toBe(false);
    await u.type(screen.getByLabelText("Replace value"), "Bearer again");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    const refusal = /Ask a platform admin to allow its network, or use the server's public address/;
    expect(await screen.findByText(refusal)).toBeInTheDocument();

    await u.clear(url);
    expect(screen.queryByText(refusal)).toBeNull();
    await u.type(url, "https://status2.example.com/mcp");
    refuse = false;
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(2));
    expect(await screen.findByText("Service status left the catalog until a platform admin reviews its new URL.")).toBeInTheDocument();

    // Overview: waiting for a review again, not "not in the catalog yet".
    await u.click(screen.getByRole("tab", { name: /Overview/ }));
    expect(await screen.findByText(/waiting for a platform admin to review it again/)).toBeInTheDocument();
    expect(screen.queryByText(/not in the company catalog yet/)).toBeNull();
  });
});

describe("A rejected server", () => {
  const rejected = () => mcpServer({ publishState: "rejected", ...reviewed, publishReviewNote: "Add a description." });

  it("can be made private from its Overview, which then shows no old request or review", async () => {
    const u = userEvent.setup();
    let current = rejected();
    const calls = mockApi(routes("owner", () => current, { [`POST ${base}/${serverId}/unpublish`]: () => (current = mcpServer({ ...reviewed, publishReviewNote: "Add a description." })) }));
    renderApp(record);
    expect(await screen.findByRole("button", { name: "Request review again…" })).toBeInTheDocument();
    expect(screen.getByText("Requested")).toBeInTheDocument();
    expect(screen.getByText("Reviewed")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Make private…" }));
    const ask = await screen.findByRole("alertdialog", { name: "Make Service status private?" });
    await u.click(within(ask).getByRole("button", { name: "Make private" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url.endsWith("/unpublish"))).toBe(true));
    expect(await screen.findByRole("button", { name: "Request review…" })).toBeInTheDocument();
    expect(screen.queryByText("Requested")).toBeNull();
    expect(screen.queryByText("Reviewed")).toBeNull();
  });

  it("offers Make private and Request review again in the row menu, to owners and admins only", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("admin", rejected, { [`POST ${base}/${serverId}/unpublish`]: () => mcpServer() }));
    const { unmount } = renderApp(`/teams/${team.slug}/servers`);
    await u.click(await screen.findByRole("button", { name: "Actions for Service status" }));
    expect(await screen.findByRole("menuitem", { name: "Request review again…" })).toBeInTheDocument();
    await u.click(screen.getByRole("menuitem", { name: "Make private…" }));
    await u.click(within(await screen.findByRole("alertdialog", { name: "Make Service status private?" })).getByRole("button", { name: "Make private" }));
    await waitFor(() => expect(calls.some((c) => c.url.endsWith("/unpublish"))).toBe(true));
    unmount();

    mockApi(routes("editor", rejected));
    renderApp(`/teams/${team.slug}/servers`);
    await u.click(await screen.findByRole("button", { name: "Actions for Service status" }));
    expect(await screen.findByRole("menuitem", { name: "Open" })).toBeInTheDocument();
    expect(screen.queryByRole("menuitem", { name: "Make private…" })).toBeNull();
  });
});

describe("Wording", () => {
  it("labels a self-published server's history Published, not Requested", async () => {
    mockApi(routes("owner", () => mcpServer({ publishState: "published", effectivePublishPolicy: "self_publish", publishRequestedAt: "2026-10-11T10:00:00Z" })));
    renderApp(record);
    expect(await screen.findByText("Policy")).toBeInTheDocument();
    expect(screen.queryByText("Requested")).toBeNull();
    expect(screen.getAllByText("Published").length).toBeGreaterThan(1);
  });

  it("tells only approvers to read capabilities before approving", async () => {
    mockApi(routes("member", () => mcpServer({ effectivePublishPolicy: "self_publish" })));
    const { unmount } = renderApp(`${record}?tab=capabilities`);
    expect(await screen.findByText("Untrusted text")).toBeInTheDocument();
    expect(screen.queryByText(/Read them before you approve/)).toBeNull();
    unmount();

    mockApi(routes("owner", () => mcpServer({ effectivePublishPolicy: "self_publish" })));
    renderApp(`${record}?tab=capabilities`);
    expect(await screen.findByText(/Read them before you approve/)).toBeInTheDocument();
  });

  it("names a check's trigger, and says a failure once", async () => {
    const failed = healthCheck({ checkedAt: "2026-10-16T06:55:00Z", ok: false, errorClass: "auth", httpStatus: 401, message: "The server refused the credentials (HTTP 401).", trigger: "manual" });
    mockApi(routes("member", () => mcpServer(), { [`GET ${base}/${serverId}/health-checks`]: () => [healthCheck(), failed] }));
    renderApp(`${record}?tab=health`);
    const table = await screen.findByRole("table", { name: "Recent checks" });
    expect(within(table).getByRole("columnheader", { name: /Trigger/ })).toBeInTheDocument();
    expect(await within(table).findByText("Manual")).toBeInTheDocument();
    expect(within(table).getByText("Scheduled")).toBeInTheDocument();
    expect(within(table).getByText("Credentials refused (HTTP 401)")).toBeInTheDocument();
    expect(within(table).queryByText(/refused the credentials/)).toBeNull();
  });
});

describe("Admin review", () => {
  const pending = (extra: Partial<McpServer> = {}) => mcpServer({ publishState: "pending", publishRequestedAt: "2026-10-15T10:00:00Z", ...extra });
  const adminRoutes = (server: McpServer, extra: Record<string, Handler> = {}, role: Schemas["PlatformRole"] = "platform_admin"): Record<string, Handler> => ({
    ...shellRoutes(role, null),
    "GET /v1/admin/mcp-servers": () => page([server]),
    [`GET /v1/admin/mcp-servers/${serverId}`]: () => server,
    [`GET /v1/admin/mcp-servers/${serverId}/capabilities`]: () => capabilities,
    [`GET /v1/admin/mcp-servers/${serverId}/health-checks`]: () => [healthCheck()],
    ...extra,
  });

  it("disables Approve until the capabilities were read from the current URL, and asks again after a new URL", async () => {
    mockApi(adminRoutes(pending({ ...reviewed, publishRequestedAt: "2026-10-16T09:00:00Z", refreshedAt: null })));
    renderApp(`/admin/servers/${serverId}`);
    expect(await screen.findByRole("button", { name: "Approve…" })).toBeDisabled();
    expect(screen.getByText(/To approve: its capabilities haven't been read from its current URL yet/)).toBeInTheDocument();
    expect(screen.getByText(/The team asked to publish this server again/)).toBeInTheDocument();
    // In the sidebar: how many wait for review.
    expect(await within(screen.getByRole("navigation", { name: "Main" })).findByRole("link", { name: /^MCP servers,\s*1\s*waiting for review$/ })).toBeInTheDocument();
  });

  it("warns when the endpoint was never checked, and explains a 409 not_refreshed", async () => {
    const u = userEvent.setup();
    mockApi(
      adminRoutes(pending({ health: { status: "unknown" } }), {
        [`POST /v1/admin/mcp-servers/${serverId}/review`]: () => Reply.error(409, "not_refreshed", "The server's capabilities haven't been read from its current URL"),
      }),
    );
    renderApp(`/admin/servers/${serverId}`);
    await u.click(await screen.findByRole("button", { name: "Approve…" }));
    const dialog = await screen.findByRole("dialog", { name: "Approve Service status for the catalog?" });
    expect(within(dialog).getByText("Not checked yet")).toBeInTheDocument();
    await u.click(within(dialog).getByRole("button", { name: "Approve and publish" }));
    expect(await within(dialog).findByText("Couldn't approve the server")).toBeInTheDocument();
    expect(within(dialog).getByText(/there's nothing reviewed to approve/)).toBeInTheDocument();
  });

  it("shows auditors no review count", async () => {
    mockApi(adminRoutes(pending(), {}, "platform_auditor"));
    renderApp(`/admin/servers/${serverId}`);
    await screen.findByRole("heading", { level: 1, name: "Service status" });
    expect(within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: "MCP servers" })).toBeInTheDocument();
  });
});
