/* Admin › Overview and the team overview's Attention card: grouping, wording, links, empty and all-clear states, truncation, errors, polling. */
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { mcpServer, page, serverId, team } from "./fixtures";
import { attentionItem, overview, teamAttention, teamRef } from "./fixtures-v02";
import { type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

const ago = (hours: number) => new Date(Date.now() - hours * 3_600_000).toISOString();
const failing = attentionItem({ severity: "critical", at: ago(30) });
const review = attentionItem({ kind: "review_pending", severity: "warning", summary: "3 servers pending", count: 3, at: ago(80), subject: null, team: null, link: { type: "review_queue" } });
const changed = attentionItem({ kind: "capabilities_changed", severity: "warning", count: 2, at: null, subject: { id: "s2", name: "Docs search", slug: "docs-search" }, link: { type: "server", id: "s2", teamSlug: team.slug } });
const personal = attentionItem({ kind: "personal_keys_expiring", severity: "info", count: 4, at: ago(-48), subject: null, team: null, link: null });
const rate = attentionItem({ kind: "rate_limited", severity: "info", count: 4, at: null, subject: null, team: null, link: { type: "usage" } });

const adminRoutes = (data: Schemas["AdminOverview"], role: Schemas["PlatformRole"] = "platform_admin", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes(role, null),
  "GET /v1/admin/overview": () => data,
  ...extra,
});

describe("Admin › Overview", () => {
  it("is the admin portal's first page, with the counts, the last 24 hours and what needs attention by severity", async () => {
    mockApi(adminRoutes(overview({ attention: [failing, review, changed, personal, rate], totals: { server_failing: 1, review_pending: 3, capabilities_changed: 1, personal_keys_expiring: 4, rate_limited: 4 } })));
    const { container, router } = renderApp("/admin");
    expect(await screen.findByRole("heading", { level: 1, name: "Overview" })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/admin");
    const counts = await screen.findByRole("group", { name: "Platform counts" });
    expect(within(counts).getByText("42")).toBeInTheDocument();
    expect(counts).toHaveTextContent("11 published");
    const strip = screen.getByRole("group", { name: "Last 24 hours" });
    expect(strip).toHaveTextContent("1,200");
    expect(strip).toHaveTextContent("2.5%");
    expect(strip).toHaveTextContent("30 errors");

    const critical = screen.getByRole("region", { name: "Critical" });
    expect(within(critical).getByText("Service status is failing its health checks")).toBeInTheDocument();
    expect(critical).toHaveTextContent("Platform Tools");
    expect(critical).toHaveTextContent("Failing since");
    expect(within(screen.getByRole("region", { name: "Warnings" })).getAllByRole("listitem")).toHaveLength(2);
    expect(screen.getByText("3 servers waiting for review")).toBeInTheDocument();
    expect(screen.getByText("Docs search has 2 capability changes held back from the catalog")).toBeInTheDocument();
    expect(screen.getByText("4 personal API keys expire within 14 days")).toBeInTheDocument();
    // Each item's button follows its link; personal keys have nowhere to go.
    expect(within(critical).getByRole("link", { name: /Open server/ })).toHaveAttribute("href", `/admin/servers/${serverId}`);
    expect(screen.getByRole("link", { name: /Open review queue/ })).toHaveAttribute("href", "/admin/publishing");
    expect(screen.getByRole("link", { name: /Open usage/ })).toHaveAttribute("href", "/admin/usage");
    expect(screen.queryByRole("link", { name: /personal API keys/ })).toBeNull();
    await waitFor(() => expect(document.title).toBe("Overview · Admin · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("links eligible exact-call attention to the private receipt, not to publishing review", async () => {
    const item = attentionItem({ kind: "approval_pending", severity: "info", subject: null, detail: "delete_message", count: 1, at: ago(1), link: { type: "approval", id: "approval1" } });
    mockApi(adminRoutes(overview({ attention: [item], totals: { approval_pending: 1 } })));
    renderApp("/admin");
    expect(await screen.findByText("delete_message needs your approval")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Review exact call/ })).toHaveAttribute("href", "/approvals/approval1");
    expect(screen.queryByRole("link", { name: /Open review queue/ })).toBeNull();
    expect(screen.queryByText("Redacted argument preview")).toBeNull();
  });

  it("says Nothing needs attention when there is nothing, and No calls without calls", async () => {
    mockApi(adminRoutes(overview({ last24h: { calls: 0, errors: 0, errorRate: null, rateLimited: 0, rolledUpTo: null } })));
    renderApp("/admin");
    expect(await screen.findByText("Nothing needs attention")).toBeInTheDocument();
    expect(screen.getByText("No calls")).toBeInTheDocument();
    expect(screen.getByText("No usage has been summed yet.")).toBeInTheDocument();
  });

  it("says how many more when a kind has more items than the list holds", async () => {
    const items = Array.from({ length: 20 }, (_, i) => attentionItem({ subject: { id: `s${i}`, name: `Server ${i}`, slug: `s${i}` }, link: { type: "server", id: `s${i}`, teamSlug: team.slug } }));
    mockApi(adminRoutes(overview({ attention: items, totals: { server_failing: 32 }, truncated: true })));
    renderApp("/admin");
    expect(await screen.findByText(/and 12 more failing servers/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Admin › MCP servers" })).toHaveAttribute("href", "/admin/servers");
  });

  it("is the same page, read-only, for auditors", async () => {
    mockApi(adminRoutes(overview({ attention: [failing] }), "platform_auditor"));
    renderApp("/admin");
    expect(await screen.findByText("Service status is failing its health checks")).toBeInTheDocument();
    expect(screen.getByText("Read-only")).toBeInTheDocument();
  });

  it("is refused for people without a platform role, and never asks for the overview", async () => {
    const calls = mockApi(shellRoutes("none", "member"));
    renderApp("/admin");
    expect(await screen.findByRole("heading", { level: 1, name: "No access" })).toBeInTheDocument();
    expect(calls.some((c) => c.url === "/v1/admin/overview")).toBe(false);
  });

  it("shows an inline error with Retry", async () => {
    const u = userEvent.setup();
    let fail = true;
    mockApi(adminRoutes(overview(), "platform_admin", { "GET /v1/admin/overview": () => (fail ? Reply.error(500, "internal", "boom") : overview()) }));
    renderApp("/admin");
    expect(await screen.findByText("Couldn't load the overview")).toBeInTheDocument();
    fail = false;
    await u.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Nothing needs attention")).toBeInTheDocument();
  });

  it("asks again every minute while visible", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const calls = mockApi(adminRoutes(overview()));
      renderApp("/admin");
      await screen.findByText("Nothing needs attention");
      const asked = () => calls.filter((c) => c.url === "/v1/admin/overview").length;
      const before = asked();
      await act(() => vi.advanceTimersByTimeAsync(60_000));
      await waitFor(() => expect(asked()).toBeGreaterThan(before));
    } finally {
      vi.useRealTimers();
    }
  });

  it("is the first item of the admin sidebar", async () => {
    mockApi(adminRoutes(overview()));
    renderApp("/admin");
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(within(nav).getAllByRole("link")[0]).toHaveTextContent("Overview");
    expect(within(nav).getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");
  });
});

describe("Team overview › Needs attention", () => {
  const teamRoutes = (data: Schemas["TeamAttention"], role: Schemas["TeamRole"] = "owner", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
    ...shellRoutes("none", role),
    [`GET /v1/teams/${team.slug}/attention`]: () => data,
    ...extra,
  });
  const keys = attentionItem({ kind: "service_account_keys_expiring", severity: "warning", count: 2, at: ago(-24 * 5), subject: null, link: { type: "service_accounts", teamSlug: team.slug } });
  const pending = attentionItem({ kind: "review_pending", severity: "info", count: 1, at: ago(10), subject: null, link: { type: "servers", teamSlug: team.slug } });

  it("lists the team's items with links to them", async () => {
    mockApi(teamRoutes(teamAttention({ attention: [failing, pending, keys], totals: { server_failing: 1, review_pending: 1, service_account_keys_expiring: 2 } })));
    const { container } = renderApp(`/teams/${team.slug}`);
    const card = (await screen.findByRole("heading", { name: "Needs attention" })).closest("section")!;
    expect(within(card).getByText("Service status is failing its health checks")).toBeInTheDocument();
    expect(within(card).getByText("2 service account keys of Platform Tools expire within 14 days")).toBeInTheDocument();
    expect(within(card).getByRole("link", { name: /Open server/ })).toHaveAttribute("href", `/teams/${team.slug}/servers/${serverId}`);
    expect(within(card).getByRole("link", { name: /See servers/ })).toHaveAttribute("href", `/teams/${team.slug}/servers?publishState=pending`);
    expect(within(card).getByRole("link", { name: /Open service accounts/ })).toHaveAttribute("href", `/teams/${team.slug}/service-accounts`);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("is hidden while empty for members and says All clear to owners and admins", async () => {
    for (const [role, clear] of [["member", false], ["editor", false], ["owner", true], ["admin", true]] as const) {
      const calls = mockApi(teamRoutes(teamAttention(), role));
      const { unmount } = renderApp(`/teams/${team.slug}`);
      await screen.findByRole("heading", { level: 1, name: team.name });
      await waitFor(() => expect(calls.some((c) => c.url.endsWith("/attention"))).toBe(true));
      if (clear) expect(await screen.findByText("All clear")).toBeInTheDocument();
      else {
        await new Promise((r) => setTimeout(r, 50));
        expect(screen.queryByRole("heading", { name: "Needs attention" })).toBeNull();
      }
      unmount();
    }
  });

  it("shows members what they can open, including a truncation line", async () => {
    const items = Array.from({ length: 20 }, (_, i) => attentionItem({ subject: { id: `s${i}`, name: `Server ${i}`, slug: `s${i}` }, team: teamRef, link: { type: "server", id: `s${i}`, teamSlug: team.slug } }));
    mockApi(teamRoutes(teamAttention({ attention: items, totals: { server_failing: 25 }, truncated: true }), "member"));
    renderApp(`/teams/${team.slug}`);
    expect(await screen.findByText(/and 5 more failing servers/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "the team's MCP servers" })).toHaveAttribute("href", `/teams/${team.slug}/servers`);
  });

  it("asks for nothing and shows nothing in an archived team", async () => {
    const calls = mockApi({ ...teamRoutes(teamAttention({ attention: [failing] })), [`GET /v1/teams/${team.slug}`]: () => ({ team: { ...team, status: "archived" }, role: "owner" }) });
    renderApp(`/teams/${team.slug}`);
    await screen.findByRole("heading", { level: 1, name: team.name });
    expect(screen.queryByRole("heading", { name: "Needs attention" })).toBeNull();
    expect(calls.some((c) => c.url.endsWith("/attention"))).toBe(false);
  });

  it("shows an inline error with Retry while the rest of the page works", async () => {
    const u = userEvent.setup();
    let fail = true;
    mockApi(teamRoutes(teamAttention(), "owner", { [`GET /v1/teams/${team.slug}/attention`]: () => (fail ? Reply.error(500, "internal", "boom") : teamAttention({ attention: [failing] })) }));
    renderApp(`/teams/${team.slug}`);
    expect(await screen.findByText("Couldn't load what needs attention")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: team.name })).toBeInTheDocument();
    fail = false;
    await u.click(screen.getByRole("button", { name: "Try again" }));
    expect(await screen.findByText("Service status is failing its health checks")).toBeInTheDocument();
  });
});

describe("Team servers ?publishState= (the link of servers waiting for review)", () => {
  it("lists only the servers in that catalog state", async () => {
    const pendingServer = mcpServer({ id: "p1", slug: "pending-one", name: "Pending one", publishState: "pending" });
    const privateServer = mcpServer({ id: "p2", slug: "private-one", name: "Private one", publishState: "private" });
    mockApi({ ...shellRoutes("none", "owner"), [`GET /v1/teams/${team.slug}/mcp-servers`]: () => page([pendingServer, privateServer]) });
    renderApp(`/teams/${team.slug}/servers?publishState=pending`);
    const table = await screen.findByRole("table", { name: "MCP servers" });
    expect(await within(table).findByText("Pending one")).toBeInTheDocument();
    expect(within(table).queryByText("Private one")).toBeNull();
  });
});
