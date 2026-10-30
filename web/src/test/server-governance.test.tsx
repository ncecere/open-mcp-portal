/* Server governance (decision 88): the card, its dialog, the banners, transfers and the review settings. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { ceilingText, raises, retirementText } from "../components/servers/governance";
import { wordsFor } from "../components/attention/wording";
import { catalogServer, capabilities, healthCheck, mcpServer, members, page, serverId, team, teamPublishing } from "./fixtures";
import { type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

type Gov = NonNullable<Schemas["McpServer"]["governance"]>;
const gov = (extra: Partial<Gov> = {}): Gov => ({
  ownerUserId: members[0]!.user.id,
  ownerName: "Una User",
  ownerless: false,
  oncallContact: "#status-oncall",
  sensitivity: "internal",
  lastReviewedAt: "2026-09-01T10:00:00Z",
  reviewDueAt: null,
  reviewOverdue: false,
  lifecycle: "active",
  ...extra,
});
const base = `/v1/teams/${team.slug}/mcp-servers/${serverId}`;
const record = `/teams/${team.slug}/servers/${serverId}`;
const routes = (role: "owner" | "admin" | "editor" | "member", server: () => Schemas["McpServer"], extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", role),
  [`GET ${base}`]: server,
  [`GET ${base}/capabilities`]: () => capabilities,
  [`GET ${base}/health-checks`]: () => [healthCheck()],
  [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing(),
  [`GET /v1/teams/${team.slug}/mcp-server-transfers`]: () => [],
  "GET /v1/catalog/servers": () => page([catalogServer()]),
  ...extra,
});

describe("Governance card", () => {
  it("shows owner, contact, sensitivity and next review, with the edit actions for owners and admins", async () => {
    mockApi(routes("admin", () => mcpServer({ publishState: "published", governance: gov({ sensitivity: "confidential", reviewDueAt: "2026-12-01T00:00:00Z" }) })));
    const { container } = renderApp(record);
    await screen.findByRole("heading", { name: "Governance" });
    const owner = screen.getByText("Owner", { selector: "dt" }).nextElementSibling!;
    expect(owner).toHaveTextContent("Una User");
    expect(screen.getByText("#status-oncall")).toBeInTheDocument();
    expect(screen.getByText("Confidential")).toBeInTheDocument();
    expect(screen.getByText("Next review")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Edit governance" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Offer to another team" })).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it.each(["oncall@example.com", "https://support.example.com/login", "tel:+123456789", "#status-oncall"])("is read-only for editors and renders contact %s as selectable text, never a link", async (oncallContact) => {
    mockApi(routes("editor", () => mcpServer({ governance: gov({ oncallContact }) })));
    renderApp(record);
    const contact = await screen.findByText(oncallContact);
    expect(contact.closest("a")).toBeNull();
    expect(screen.queryByRole("link", { name: oncallContact })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit governance" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Offer to another team" })).toBeNull();
  });

  it("warns that a published server has nobody accountable, and asks for an overdue review", async () => {
    const u = userEvent.setup();
    let published = mcpServer({ publishState: "published", governance: gov({ ownerUserId: undefined, ownerName: undefined, ownerless: true, reviewOverdue: true, reviewDueAt: "2026-10-01T00:00:00Z" }) });
    const calls = mockApi(routes("owner", () => published, { [`POST ${base}/publish`]: () => (published = mcpServer({ publishState: "pending", governance: gov() })) }));
    const { container } = renderApp(record);
    expect(await screen.findByText("Nobody is accountable for this server")).toBeInTheDocument();
    expect(screen.getByText("Its review is overdue")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Ask for a review" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url === `${base}/publish`)).toBe(true));
    await screen.findByText("Review requested");
  });

  it("shows a deprecation banner on every tab, with the sunset date and the replacement", async () => {
    mockApi(routes("member", () => mcpServer({ governance: gov({ lifecycle: "deprecated", sunsetAt: "2027-01-15T12:00:00Z", replacement: { id: "x", slug: "next", name: "Status next", teamSlug: team.slug, teamName: team.name } }) })));
    renderApp(`${record}?tab=health`);
    const banner = await screen.findByText("Service status is deprecated");
    expect(banner.closest("[role=status]")).toHaveTextContent(/stops being served on/);
    expect(banner.closest("[role=status]")).toHaveTextContent("Use Status next instead.");
  });

  it("says a sunset server is retired", async () => {
    mockApi(routes("member", () => mcpServer({ governance: gov({ lifecycle: "sunset", sunsetAt: "2026-10-01T12:00:00Z" }) })));
    renderApp(record);
    expect(await screen.findByText("Service status is retired")).toBeInTheDocument();
  });
});

describe("Edit governance", () => {
  it("sends only what changed, with the revision it opened with, and warns before a raise sends a published server back to review", async () => {
    const u = userEvent.setup();
    let current = mcpServer({ publishState: "published", governance: gov() });
    const calls = mockApi(
      routes("owner", () => current, {
        [`PATCH ${base}`]: () => (current = mcpServer({ publishState: "pending", revision: 5, governance: gov({ sensitivity: "restricted" }) })),
      }),
    );
    renderApp(record);
    await u.click(await screen.findByRole("button", { name: "Edit governance" }));
    const dialog = await screen.findByRole("dialog", { name: "Edit governance" });
    expect(screen.getByRole("button", { name: "Save governance" })).toBeDisabled();
    expect(await axe(dialog)).toHaveNoViolations();
    await u.selectOptions(within(dialog).getByRole("combobox", { name: "Sensitivity" }), "restricted");
    expect(within(dialog).getByText("It goes back to review")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Save governance" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ governance: { sensitivity: "restricted" } }));
    expect(calls.find((c) => c.method === "PATCH")?.headers.get("If-Match")).toBe('"4"');
    await screen.findByText("Governance saved");
  });

  it("lowering the sensitivity does not warn, owners are the team's editors and up, and clearing sends null", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("owner", () => mcpServer({ publishState: "published", governance: gov({ sensitivity: "restricted" }) }), { [`PATCH ${base}`]: () => mcpServer({ governance: gov() }) }));
    renderApp(record);
    await u.click(await screen.findByRole("button", { name: "Edit governance" }));
    const dialog = await screen.findByRole("dialog");
    await u.selectOptions(within(dialog).getByRole("combobox", { name: "Sensitivity" }), "public");
    expect(within(dialog).queryByText("It goes back to review")).toBeNull();
    const owner = within(dialog).getByRole("combobox", { name: /Owner/ });
    expect(within(owner).queryByRole("option", { name: /Drew Member/ })).toBeNull();
    expect(within(owner).getByRole("option", { name: /Casey Editor/ })).toBeInTheDocument();
    await u.selectOptions(owner, "");
    await u.clear(within(dialog).getByRole("textbox", { name: /On-call contact/ }));
    await u.click(screen.getByRole("button", { name: "Save governance" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ governance: { sensitivity: "public", ownerUserId: null, oncallContact: null } }));
  });

  it("deprecating offers a date and a replacement, and the API's refusal is in words", async () => {
    const u = userEvent.setup();
    mockApi(
      routes("owner", () => mcpServer({ governance: gov() }), {
        [`PATCH ${base}`]: () => Reply.error(422, "sunset_in_past", "Choose a sunset date in the future"),
      }),
    );
    renderApp(record);
    await u.click(await screen.findByRole("button", { name: "Edit governance" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).queryByLabelText(/Stops being served at/)).toBeNull();
    await u.selectOptions(within(dialog).getByRole("combobox", { name: "Lifecycle" }), "deprecated");
    expect(within(dialog).getByLabelText(/Stops being served at/)).toBeInTheDocument();
    expect(within(dialog).getByRole("combobox", { name: /Replacement/ })).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Save governance" }));
    expect(await within(dialog).findByText("Choose a sunset date in the future.")).toBeInTheDocument();
  });

  it("a change made elsewhere is told and never overwritten", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("owner", () => mcpServer({ governance: gov() }), { [`PATCH ${base}`]: () => Reply.error(412, "stale_revision", "stale") }));
    renderApp(record);
    await u.click(await screen.findByRole("button", { name: "Edit governance" }));
    const dialog = await screen.findByRole("dialog");
    await u.type(within(dialog).getByRole("textbox", { name: /On-call contact/ }), "x");
    await u.click(screen.getByRole("button", { name: "Save governance" }));
    expect(await within(dialog).findByText("Changed elsewhere")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save governance" })).toBeDisabled();
    expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1);
  });
});

describe("Server transfers", () => {
  it("offers a server to another team with an optional note, and says what stays with it", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes("admin", () => mcpServer({ governance: gov() }), {
        [`POST ${base}/transfer`]: () => ({ id: "t1", serverId, serverSlug: "service-status", serverName: "Service status", fromTeamSlug: team.slug, fromTeamName: team.name, toTeamSlug: "data", toTeamName: "Data", state: "pending", requestedAt: "2026-10-30T10:00:00Z", revision: 1 }),
      }),
    );
    renderApp(record);
    await u.click(await screen.findByRole("button", { name: "Offer to another team" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(/sealed|stored credentials/)).toBeInTheDocument();
    expect(await axe(dialog)).toHaveNoViolations();
    await u.type(within(dialog).getByRole("textbox", { name: "Receiving team" }), "data");
    await u.type(within(dialog).getByRole("textbox", { name: /Note/ }), "yours now");
    await u.click(screen.getByRole("button", { name: "Offer server" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST" && c.url.endsWith("/transfer"))?.body).toEqual({ toTeam: "data", note: "yours now" }));
  });

  it("shows the open transfer and lets the offering team withdraw it", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes("owner", () => mcpServer({ governance: gov({ pendingTransfer: { id: "t1", toTeamSlug: "data", toTeamName: "Data", requestedAt: "2026-10-30T10:00:00Z", revision: 3 } }) }), {
        [`DELETE /v1/teams/${team.slug}/mcp-server-transfers/t1`]: () => ({ id: "t1" }),
      }),
    );
    renderApp(record);
    expect(await screen.findByText("Offered to Data")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Offer to another team" })).toBeNull();
    await u.click(screen.getByRole("button", { name: "Withdraw transfer" }));
    await u.click(await screen.findByRole("button", { name: "Withdraw offer" }));
    await waitFor(() => expect(calls.find((c) => c.method === "DELETE")?.headers.get("If-Match")).toBe('"3"'));
  });

  const incoming = { id: "t9", serverId: "s9", serverSlug: "billing", serverName: "Billing", fromTeamSlug: "fin", fromTeamName: "Finance", toTeamSlug: team.slug, toTeamName: team.name, state: "pending", requestedByName: "Fia", note: "please take it", requestedAt: "2026-10-29T10:00:00Z", revision: 1 };

  it("shows the receiving team's owner what is offered and accepts with the transfer's revision", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes("owner", () => mcpServer(), {
        [`GET /v1/teams/${team.slug}/mcp-server-transfers`]: () => [incoming],
        [`GET /v1/teams/${team.slug}/mcp-servers`]: () => page([]),
        [`POST /v1/teams/${team.slug}/mcp-server-transfers/t9/accept`]: () => ({ ...incoming, state: "accepted", revision: 2 }),
      }),
    );
    const { container } = renderApp(`/teams/${team.slug}/servers`);
    expect(await screen.findByRole("list", { name: "Pending server transfers" })).toBeInTheDocument();
    expect(screen.getByText(/from Finance/)).toBeInTheDocument();
    expect(screen.getByText(/please take it/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Accept Billing" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST" && c.url.endsWith("/accept"))?.headers.get("If-Match")).toBe('"1"'));
    await screen.findByText("Billing is now this team's");
  });

  it("an admin can only decline, an editor sees nothing", async () => {
    mockApi(routes("admin", () => mcpServer(), { [`GET /v1/teams/${team.slug}/mcp-server-transfers`]: () => [incoming], [`GET /v1/teams/${team.slug}/mcp-servers`]: () => page([]) }));
    const { unmount } = renderApp(`/teams/${team.slug}/servers`);
    expect(await screen.findByRole("button", { name: "Decline" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Accept Billing" })).toBeNull();
    expect(screen.getByText("Only an owner of this team accepts a transfer.")).toBeInTheDocument();
    unmount();
    const calls = mockApi(routes("editor", () => mcpServer(), { [`GET /v1/teams/${team.slug}/mcp-server-transfers`]: () => [incoming], [`GET /v1/teams/${team.slug}/mcp-servers`]: () => page([]) }));
    renderApp(`/teams/${team.slug}/servers`);
    await screen.findByRole("heading", { level: 1, name: /servers/i });
    expect(screen.queryByRole("list", { name: "Pending server transfers" })).toBeNull();
    expect(calls.some((c) => c.url.endsWith("mcp-server-transfers"))).toBe(false);
  });
});

describe("Catalog", () => {
  it("shows the sensitivity and a deprecation banner with the replacement, never the owner or contact", async () => {
    const server = catalogServer({ governance: { sensitivity: "confidential", lifecycle: "deprecated", sunsetAt: "2027-02-01T00:00:00Z", replacement: { id: "r", slug: "next", name: "Status next", teamSlug: "ops", teamName: "Ops" } } });
    mockApi({ ...shellRoutes("none", null), [`GET /v1/catalog/servers/${serverId}`]: () => ({ server, capabilities: [] }) });
    const { container } = renderApp(`/catalog/${serverId}`);
    expect(await screen.findByText("Service status is deprecated")).toBeInTheDocument();
    expect(screen.getByText(/Use Status next instead/)).toBeInTheDocument();
    expect(screen.getByText("Confidential")).toBeInTheDocument();
    expect(screen.queryByText(/On call|Owner/)).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });
});

describe("Words", () => {
  it("orders the labels and says what a ceiling does", () => {
    expect(raises("internal", "confidential")).toBe(true);
    expect(raises("confidential", "internal")).toBe(false);
    expect(raises("public", "public")).toBe(false);
    expect(ceilingText(undefined)).toMatch(/No ceiling/);
    expect(ceilingText("internal")).toMatch(/internal or lower/);
    expect(retirementText({ lifecycle: "sunset" })).toMatch(/No gateway serves it any more/);
    expect(retirementText({ lifecycle: "deprecated" })).toMatch(/no date is set/);
  });

  it("words the three new attention kinds", () => {
    const item = (kind: Schemas["AttentionKind"], extra: Partial<Schemas["AttentionItem"]> = {}): Schemas["AttentionItem"] => ({ kind, severity: "warning", summary: "s", subject: { id: "1", name: "Billing" }, team: { id: "t", slug: "fin", name: "Finance" }, ...extra });
    expect(wordsFor(item("review_due")).title).toBe("The review of Billing of Finance is overdue");
    expect(wordsFor(item("server_ownerless")).title).toBe("Billing of Finance has nobody accountable for it");
    expect(wordsFor(item("server_transfer_pending", { count: 2 })).title).toBe("2 server transfers waiting for your team's owners to accept");
  });
});
