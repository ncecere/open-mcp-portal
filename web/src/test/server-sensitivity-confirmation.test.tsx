/*
 * The sensitivity confirmation (decision 88 follow-up): a server's label is Internal until someone says otherwise, so
 * the card and the edit dialog say Internal is only a default until an owner or admin confirms it, the attention list
 * asks for it, and saving other changes never confirms it. The marker is optional in the API: a server that omits it
 * (every older fixture) shows nothing.
 */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { moreNouns, wordsFor } from "../components/attention/wording";
import { capabilities, catalogServer, healthCheck, mcpServer, members, page, serverId, team, teamPublishing } from "./fixtures";
import { attentionItem, overview } from "./fixtures-v02";
import { type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

type Gov = NonNullable<Schemas["McpServer"]["governance"]>;
const gov = (extra: Partial<Gov> = {}): Gov => ({
  ownerUserId: members[0]!.user.id,
  ownerName: "Una User",
  ownerless: false,
  oncallContact: "#status-oncall",
  sensitivity: "internal",
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
const unconfirmed = (extra: Partial<Gov> = {}) => gov({ sensitivityConfirmed: false, ...extra });

describe("Unconfirmed sensitivity on the Governance card", () => {
  it("warns that Internal is only a default, and an owner or admin confirms it with the revision shown", async () => {
    const u = userEvent.setup();
    let current = mcpServer({ publishState: "published", governance: unconfirmed() });
    const calls = mockApi(
      routes("admin", () => current, {
        [`PATCH ${base}`]: () => (current = mcpServer({ publishState: "published", revision: 5, governance: gov({ sensitivityConfirmed: true }) })),
      }),
    );
    const { container } = renderApp(record);
    const alert = (await screen.findByText("Sensitivity not confirmed")).closest("[role=status],[role=alert]")!;
    expect(alert).toHaveTextContent("Internal is only the default until someone checks it");
    expect(alert).toHaveTextContent("changes nothing about what gateways serve");
    expect(screen.getByText("Not confirmed")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    // Nothing is sent until the person asks; then only the label shown, bound to the revision shown.
    expect(calls.some((c) => c.method === "PATCH")).toBe(false);
    await u.click(screen.getByRole("button", { name: "Confirm sensitivity" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ governance: { sensitivity: "internal" } }));
    expect(calls.find((c) => c.method === "PATCH")?.headers.get("If-Match")).toBe('"4"');
    await screen.findByText("Sensitivity confirmed");
    await waitFor(() => expect(screen.queryByText("Sensitivity not confirmed")).toBeNull());
    expect(screen.queryByText("Not confirmed")).toBeNull();
    expect(screen.getByText("Internal")).toBeInTheDocument();
  });

  it("reports a change made elsewhere instead of confirming over it", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("owner", () => mcpServer({ governance: unconfirmed() }), { [`PATCH ${base}`]: () => Reply.error(412, "revision_conflict", "Someone else changed this since you loaded it.") }));
    renderApp(record);
    await u.click(await screen.findByRole("button", { name: "Confirm sensitivity" }));
    expect(await screen.findByText("Couldn't confirm the sensitivity")).toBeInTheDocument();
    expect(calls.filter((c) => c.method === "PATCH")).toHaveLength(1);
  });

  it.each(["editor", "member"] as const)("is read-only for a %s: the warning, no button", async (role) => {
    mockApi(routes(role, () => mcpServer({ publishState: "published", governance: unconfirmed() })));
    const { container } = renderApp(record);
    const alert = (await screen.findByText("Sensitivity not confirmed")).closest("[role=status],[role=alert]")!;
    expect(alert).toHaveTextContent("A team owner or admin confirms it.");
    expect(screen.queryByRole("button", { name: "Confirm sensitivity" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit governance" })).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows nothing for a confirmed label (Internal included), and nothing when the API omits the marker", async () => {
    mockApi(routes("owner", () => mcpServer({ publishState: "published", governance: gov({ sensitivityConfirmed: true }) })));
    const { unmount } = renderApp(record);
    await screen.findByRole("heading", { name: "Governance" });
    expect(screen.getByText("Internal")).toBeInTheDocument();
    expect(screen.queryByText("Sensitivity not confirmed")).toBeNull();
    expect(screen.queryByRole("button", { name: "Confirm sensitivity" })).toBeNull();
    unmount();
    mockApi(routes("owner", () => mcpServer({ publishState: "published", governance: gov() })));
    renderApp(record);
    await screen.findByRole("heading", { name: "Governance" });
    expect(screen.queryByText("Sensitivity not confirmed")).toBeNull();
  });

  it("names a label other than Internal that nobody confirmed", async () => {
    mockApi(routes("owner", () => mcpServer({ publishState: "published", governance: unconfirmed({ sensitivity: "confidential" }) })));
    renderApp(record);
    const alert = (await screen.findByText("Sensitivity not confirmed")).closest("[role=status],[role=alert]")!;
    expect(alert).toHaveTextContent("Nobody on the team has confirmed the label Confidential");
  });
});

describe("Edit governance and the confirmation", () => {
  const open = async (u: ReturnType<typeof userEvent.setup>, governance: Gov) => {
    const calls = mockApi(routes("owner", () => mcpServer({ publishState: "published", governance }), { [`PATCH ${base}`]: () => mcpServer({ governance: gov({ sensitivityConfirmed: true }) }) }));
    renderApp(record);
    await u.click(await screen.findByRole("button", { name: "Edit governance" }));
    return { calls, dialog: await screen.findByRole("dialog", { name: "Edit governance" }) };
  };

  it("does not confirm the label when other fields are saved, and says so", async () => {
    const u = userEvent.setup();
    const { calls, dialog } = await open(u, unconfirmed());
    const box = within(dialog).getByRole("checkbox", { name: "Internal is the right label for this server" });
    expect(box).not.toBeChecked();
    expect(dialog).toHaveTextContent("Saving other changes doesn't confirm it.");
    expect(await axe(dialog)).toHaveNoViolations();
    expect(screen.getByRole("button", { name: "Save governance" })).toBeDisabled();
    await u.type(within(dialog).getByRole("textbox", { name: /On-call contact/ }), "x");
    await u.click(screen.getByRole("button", { name: "Save governance" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ governance: { oncallContact: "#status-oncallx" } }));
  });

  it("confirms the unchanged Internal label when the person ticks the box, alone or with other changes", async () => {
    const u = userEvent.setup();
    const { calls, dialog } = await open(u, unconfirmed());
    await u.click(within(dialog).getByRole("checkbox", { name: "Internal is the right label for this server" }));
    const save = screen.getByRole("button", { name: "Save governance" });
    expect(save).toBeEnabled();
    await u.type(within(dialog).getByRole("textbox", { name: /On-call contact/ }), "x");
    await u.click(save);
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ governance: { sensitivity: "internal", oncallContact: "#status-oncallx" } }));
    expect(calls.find((c) => c.method === "PATCH")?.headers.get("If-Match")).toBe('"4"');
  });

  it("confirms just the label when only the box is ticked", async () => {
    const u = userEvent.setup();
    const { calls, dialog } = await open(u, unconfirmed());
    await u.click(within(dialog).getByRole("checkbox", { name: "Internal is the right label for this server" }));
    await u.click(screen.getByRole("button", { name: "Save governance" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ governance: { sensitivity: "internal" } }));
  });

  it("choosing another label says saving it confirms it", async () => {
    const u = userEvent.setup();
    const { calls, dialog } = await open(u, unconfirmed());
    await u.selectOptions(within(dialog).getByRole("combobox", { name: "Sensitivity" }), "confidential");
    const box = within(dialog).getByRole("checkbox", { name: "Confidential is the right label for this server" });
    expect(box).toBeChecked();
    expect(box).toHaveAttribute("aria-disabled", "true");
    expect(dialog).toHaveTextContent("Saving a different label confirms it.");
    await u.click(screen.getByRole("button", { name: "Save governance" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ governance: { sensitivity: "confidential" } }));
  });

  it("has no confirmation box for a label that is confirmed or a server that omits the marker", async () => {
    const u = userEvent.setup();
    const { dialog } = await open(u, gov({ sensitivityConfirmed: true }));
    expect(within(dialog).queryByRole("checkbox")).toBeNull();
  });
});

describe("The unlabelled-server attention item", () => {
  const item = (extra: Partial<Schemas["AttentionItem"]> = {}): Schemas["AttentionItem"] =>
    attentionItem({ kind: "server_unlabelled", severity: "info", at: null, summary: "Service status (Platform Tools) is published with the sensitivity label \"internal\" that nobody has confirmed", ...extra });

  it("is worded for a server, a team and its action", () => {
    const words = wordsFor(item());
    expect(words.title).toBe("Service status of Platform Tools is published with a sensitivity label nobody has confirmed");
    expect(words.action).toBe("Confirm sensitivity");
    expect(words.atLabel).toBeUndefined();
    expect(wordsFor(item({ team: null, subject: null })).title).toBe("A server is published with a sensitivity label nobody has confirmed");
    expect(moreNouns.server_unlabelled).toBe("servers with an unconfirmed sensitivity label");
  });

  it("shows in the platform overview under information, links to the server and says how many more", async () => {
    const items = Array.from({ length: 20 }, (_, i) => item({ subject: { id: `s${i}`, name: `Server ${i}`, slug: `s${i}` }, link: { type: "server", id: `s${i}`, teamSlug: team.slug } }));
    mockApi({ ...shellRoutes("platform_admin", null), "GET /v1/admin/overview": () => overview({ attention: items, totals: { server_unlabelled: 25 }, truncated: true }) });
    const { container } = renderApp("/admin");
    const info = await screen.findByRole("region", { name: "For your information" });
    expect(within(info).getAllByRole("listitem")).toHaveLength(20);
    expect(within(info).getByText("Server 3 of Platform Tools is published with a sensitivity label nobody has confirmed")).toBeInTheDocument();
    expect(within(info).getAllByRole("link", { name: /Confirm sensitivity/ })[3]).toHaveAttribute("href", `/admin/servers/s3`);
    expect(screen.getByText(/and 5 more servers with an unconfirmed sensitivity label/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Admin › MCP servers" })).toHaveAttribute("href", "/admin/servers");
    expect(await axe(container)).toHaveNoViolations();
  });
});
