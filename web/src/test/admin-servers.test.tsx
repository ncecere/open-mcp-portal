/* Admin → MCP servers (filters, the review count, reviews, approving changes), Publishing, and a team's publishing override. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { capabilities, capability, healthCheck, mcpServer, page, serverId, team, teamPublishing, teamSummary } from "./fixtures";
import { type Handler, mockApi, Reply, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const pending = mcpServer({ publishState: "pending", publishRequestedAt: "2026-10-15T10:00:00Z", publishRequestNote: "For on-call engineers." });

const routes = (role: "platform_admin" | "platform_auditor" = "platform_admin", server = pending, extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes(role, null),
  "GET /v1/admin/mcp-servers": (_b, call) => (call.search.get("publishState") === "pending" ? page([pending]) : page([server, mcpServer({ id: "s2", name: "Wiki search", slug: "wiki" })])),
  [`GET /v1/admin/mcp-servers/${serverId}`]: () => server,
  [`GET /v1/admin/mcp-servers/${serverId}/capabilities`]: () => capabilities,
  [`GET /v1/admin/mcp-servers/${serverId}/health-checks`]: () => [healthCheck()],
  "GET /v1/admin/teams": () => page([teamSummary()]),
  [`GET /v1/admin/teams/${team.slug}`]: () => teamSummary(),
  [`GET /v1/admin/teams/${team.slug}/publishing`]: () => teamPublishing(),
  "GET /v1/admin/settings/publishing": (): Schemas["PublishingSettings"] => ({ defaultPolicy: "approval_required", revision: 2, updatedAt: "2026-10-01T10:00:00Z" }),
  ...extra,
});

describe("Admin → MCP servers", () => {
  it("lists every team's servers with the number waiting for review, and filters on the server", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes());
    const { container } = renderApp("/admin/servers?team=platform-tools&changes=true");
    const table = await screen.findByRole("table", { name: "MCP servers" });
    const row = (await within(table).findByText("Service status")).closest("tr")!;
    expect(row).toHaveTextContent(team.name);
    expect(row).toHaveTextContent("Waiting for review");
    expect(within(row).getByRole("link", { name: "Service status" })).toHaveAttribute("href", `/admin/servers/${serverId}`);
    expect(await screen.findByText("1 server waiting for review")).toBeInTheDocument();
    await waitFor(() => expect(calls.some((c) => c.url === "/v1/admin/mcp-servers" && c.search.get("team") === "platform-tools" && c.search.get("changes") === "true")).toBe(true));
    expect(await axe(container)).toHaveNoViolations();

    await u.click(screen.getByRole("button", { name: "Show them" }));
    await waitFor(() => expect(calls.some((c) => c.search.get("publishState") === "pending" && c.search.get("team") === "platform-tools")).toBe(true));
  });

  it("approves a pending server with an optional note, from its record", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", pending, { [`POST /v1/admin/mcp-servers/${serverId}/review`]: () => mcpServer({ publishState: "published" }) }));
    const { container } = renderApp(`/admin/servers/${serverId}`);
    expect(await screen.findByRole("heading", { level: 1, name: "Service status" })).toBeInTheDocument();
    expect(screen.getByText(/The team asked to publish this server/)).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe("Service status · MCP servers · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Approve…" }));
    const dialog = await screen.findByRole("dialog", { name: "Approve Service status for the catalog?" });
    expect(dialog).toHaveTextContent("For on-call engineers.");
    await u.click(within(dialog).getByRole("button", { name: "Approve and publish" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/review"))?.body).toEqual({ decision: "approve", expectedDigest: "d".repeat(64) }));
  });

  // F-2: the approval names what the admin was shown when the dialog opened, not what a refetch shows later.
  it("approves the digest it was opened with, and says to reload when the server changed", async () => {
    const u = userEvent.setup();
    let current = pending;
    const calls = mockApi(
      routes("platform_admin", pending, {
        [`GET /v1/admin/mcp-servers/${serverId}`]: () => current,
        [`POST /v1/admin/mcp-servers/${serverId}/review`]: () => Reply.error(409, "changed_since_review", "Changed.", { currentDigest: "e".repeat(64) }),
      }),
    );
    renderApp(`/admin/servers/${serverId}`);
    await u.click(await screen.findByRole("button", { name: "Approve…" }));
    const dialog = await screen.findByRole("dialog", { name: "Approve Service status for the catalog?" });
    // The server is refreshed behind the open dialog (an editor refreshed it, the page refetched).
    current = mcpServer({ ...pending, reviewDigest: "e".repeat(64) });
    await u.click(within(dialog).getByRole("button", { name: "Approve and publish" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/review"))?.body).toEqual({ decision: "approve", expectedDigest: "d".repeat(64) }));
    expect(await within(dialog).findByText("This changed since you opened it. Reload and review it again.")).toBeInTheDocument();
    expect(screen.queryByText(/is in the catalog/)).toBeNull();
  });

  it("sends no digest with a reject", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", pending, { [`POST /v1/admin/mcp-servers/${serverId}/review`]: () => mcpServer({ publishState: "rejected" }) }));
    renderApp(`/admin/servers/${serverId}`);
    await u.click(await screen.findByRole("button", { name: "Reject…" }));
    const dialog = await screen.findByRole("dialog", { name: "Reject Service status?" });
    await u.type(within(dialog).getByRole("textbox", { name: /Note for the team/ }), "No.");
    await u.click(within(dialog).getByRole("button", { name: "Reject" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/review"))?.body).toEqual({ decision: "reject", note: "No." }));
  });

  it("needs a note to reject, and removes a published server with a reject", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", pending, { [`POST /v1/admin/mcp-servers/${serverId}/review`]: () => mcpServer({ publishState: "rejected" }) }));
    const { unmount } = renderApp(`/admin/servers/${serverId}`);
    await u.click(await screen.findByRole("button", { name: "Reject…" }));
    const dialog = await screen.findByRole("dialog", { name: "Reject Service status?" });
    await u.click(within(dialog).getByRole("button", { name: "Reject" }));
    expect(await within(dialog).findAllByText("Say why, so the team knows what to change.")).not.toHaveLength(0);
    expect(calls.some((c) => c.url.endsWith("/review"))).toBe(false);
    await u.type(within(dialog).getByRole("textbox", { name: /Note for the team/ }), "Needs a description.");
    await u.click(within(dialog).getByRole("button", { name: "Reject" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/review"))?.body).toEqual({ decision: "reject", note: "Needs a description." }));
    unmount();

    const calls2 = mockApi(routes("platform_admin", mcpServer({ publishState: "published" }), { [`POST /v1/admin/mcp-servers/${serverId}/review`]: () => mcpServer({ publishState: "rejected" }) }));
    renderApp(`/admin/servers/${serverId}`);
    await u.click(await screen.findByRole("button", { name: "Remove from catalog…" }));
    const remove = await screen.findByRole("dialog", { name: "Remove Service status from the catalog?" });
    await u.type(within(remove).getByRole("textbox", { name: /Note for the team/ }), "Leaks data.");
    await u.click(within(remove).getByRole("button", { name: "Remove from catalog" }));
    await waitFor(() => expect(calls2.find((c) => c.url.endsWith("/review"))?.body).toEqual({ decision: "reject", note: "Leaks data." }));
  });

  it("approves a changed capability through the admin API", async () => {
    const u = userEvent.setup();
    const changed = capability({ changed: true });
    const calls = mockApi(
      routes("platform_admin", mcpServer({ publishState: "published", pendingChanges: 1 }), {
        [`GET /v1/admin/mcp-servers/${serverId}/capabilities`]: () => [changed],
        [`PUT /v1/admin/mcp-servers/${serverId}/capabilities/${changed.id}/approval`]: () => ({ ...changed, changed: false, approved: true }),
      }),
    );
    renderApp(`/admin/servers/${serverId}?tab=capabilities`);
    await u.click(await screen.findByRole("button", { name: "Approve the change to get_status" }));
    await u.click(within(await screen.findByRole("alertdialog", { name: "Approve the change to get_status?" })).getByRole("button", { name: "Approve change" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PUT" && c.url === `/v1/admin/mcp-servers/${serverId}/capabilities/${changed.id}/approval`)).toBe(true));
    expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ expectedFingerprint: changed.fingerprint });
  });

  it("refuses to approve a capability that changed since it was read, and says to reload", async () => {
    const u = userEvent.setup();
    const changed = capability({ changed: true });
    const calls = mockApi(
      routes("platform_admin", mcpServer({ publishState: "published", pendingChanges: 1 }), {
        [`GET /v1/admin/mcp-servers/${serverId}/capabilities`]: () => [changed],
        [`PUT /v1/admin/mcp-servers/${serverId}/capabilities/${changed.id}/approval`]: () =>
          Reply.error(409, "changed_since_review", "Changed.", { currentFingerprint: "f".repeat(64) }),
      }),
    );
    renderApp(`/admin/servers/${serverId}?tab=capabilities`);
    await u.click(await screen.findByRole("button", { name: "Approve the change to get_status" }));
    const ask = await screen.findByRole("alertdialog", { name: "Approve the change to get_status?" });
    await u.click(within(ask).getByRole("button", { name: "Approve change" }));
    expect(await within(ask).findByText("This changed since you opened it. Reload and review it again.")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ expectedFingerprint: changed.fingerprint });
    expect(screen.queryByText("The change to get_status was approved")).toBeNull();
  });

  it("is read-only for auditors: no reviews, settings shown but not editable, health through the admin API", async () => {
    mockApi(routes("platform_auditor"));
    const { unmount } = renderApp(`/admin/servers/${serverId}`);
    await screen.findByRole("heading", { level: 1, name: "Service status" });
    expect(screen.queryByRole("button", { name: "Approve…" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Test connection" })).toBeNull();
    unmount();

    const calls = mockApi(routes("platform_auditor"));
    const health = renderApp(`/admin/servers/${serverId}?tab=health`);
    expect(await screen.findByRole("table", { name: "Recent checks" })).toBeInTheDocument();
    await waitFor(() => expect(calls.some((c) => c.url === `/v1/admin/mcp-servers/${serverId}/health-checks`)).toBe(true));
    expect(calls.some((c) => c.url.startsWith("/v1/teams/"))).toBe(false);
    health.unmount();

    mockApi(routes("platform_auditor"));
    renderApp(`/admin/servers/${serverId}?tab=settings`);
    expect(await screen.findByText("You can view these settings. The team's editors, admins and owners change them.")).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Name" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Delete server" })).toBeNull();
  });
});

describe("Admin → Publishing", () => {
  it("saves the default policy with If-Match, after confirming", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", pending, { "PUT /v1/admin/settings/publishing": () => ({ defaultPolicy: "self_publish", revision: 3, updatedAt: "2026-10-16T10:00:00Z" }) }));
    const { container } = renderApp("/admin/publishing");
    const self = await screen.findByRole("radio", { name: /Self-publish/ });
    expect(screen.getByRole("radio", { name: /Approval required/ })).toBeChecked();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(self);
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    const ask = await screen.findByRole("alertdialog", { name: "Make self-publish the default?" });
    expect(ask).toHaveTextContent("It applies to every team without its own policy.");
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
    await u.click(within(ask).getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ defaultPolicy: "self_publish" }));
    expect(calls.find((c) => c.method === "PUT")?.headers.get("If-Match")).toBe('"2"');
  });

  it("is read-only for auditors", async () => {
    mockApi(routes("platform_auditor"));
    renderApp("/admin/publishing");
    expect(await screen.findByText("You can view these settings. Only platform admins can change them.")).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /Self-publish/ })).toHaveAttribute("aria-disabled", "true");
  });

  it("sets a team's override after confirming, with If-Match on the team's revision", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", pending, { [`PUT /v1/admin/teams/${team.slug}/publishing`]: () => teamPublishing({ override: "self_publish", effective: "self_publish", revision: 4 }) }));
    renderApp(`/admin/teams/${team.slug}?tab=settings`);
    const select = await screen.findByRole("combobox", { name: "Publishing policy" });
    expect(within(select).getAllByRole("option").map((o) => o.textContent)).toEqual(["Follow the platform default (approval required)", "Approval required", "Self-publish"]);
    await u.selectOptions(select, "self_publish");
    const ask = await screen.findByRole("alertdialog", { name: "Set Platform Tools to self-publish?" });
    await u.click(within(ask).getByRole("button", { name: "Save policy" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ override: "self_publish" }));
    expect(calls.find((c) => c.method === "PUT")?.headers.get("If-Match")).toBe(`"${team.revision}"`);
  });
});
