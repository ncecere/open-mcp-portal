/* A gateway's rate limit and "Record call contents" switch, a server's switch (owners and admins), and where callers are told contents are recorded. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import {
  capabilities,
  catalogServer,
  gateway,
  gatewayCapabilities,
  gatewayCapability,
  gatewayId,
  healthCheck,
  mcpServer,
  myGateway,
  page,
  serverId,
  team,
  teamPublishing,
} from "./fixtures";
import { teamLimits, teamRetention } from "./fixtures-operations";
import { type Call, type Handler, Reply, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

type Role = Schemas["TeamRole"];
const teamApi = `/v1/teams/${team.slug}`;
const gwRecord = `/teams/${team.slug}/gateways/${gatewayId}`;
const serverRecord = `/teams/${team.slug}/servers/${serverId}`;

const gatewayRoutes = (role: Role, g: () => Schemas["Gateway"], extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", role),
  [`GET ${teamApi}/gateways/${gatewayId}`]: g,
  [`GET ${teamApi}/gateways/${gatewayId}/capabilities`]: () => gatewayCapabilities(),
  [`GET ${teamApi}/limits`]: () => teamLimits(),
  [`GET ${teamApi}/retention`]: () => teamRetention(),
  "GET /v1/me/gateways": () => [myGateway()],
  ...extra,
});

const patches = (calls: Call[]) => calls.filter((c) => c.method === "PATCH");

describe("Gateway › Settings: rate limit and recording", () => {
  it("sets the gateway's own limit within the ceiling, shows what applies, and sends only what changed", async () => {
    const u = userEvent.setup();
    let current = gateway({ capturePayloads: false, rateLimitPerMinute: null, effectiveRateLimitPerMinute: 2000 });
    const calls = mockApi(
      gatewayRoutes("owner", () => current, {
        [`PATCH ${teamApi}/gateways/${gatewayId}`]: (body) => (current = gateway({ ...current, ...(body as object), effectiveRateLimitPerMinute: 1500, revision: 8 })),
      }),
    );
    const { container } = renderApp(`${gwRecord}?tab=settings`);
    const mode = await screen.findByRole("combobox", { name: "Limit" });
    expect(await screen.findByText("Inherit: 2,000 per minute, the team's default.")).toBeInTheDocument();
    expect(screen.getByText("Applies now: 2,000 per minute.")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();

    await u.selectOptions(mode, "custom");
    expect(screen.getByText("At most 3,000 (the platform's ceiling).")).toBeInTheDocument();
    expect(screen.getByText("Applies now: 2,000 per minute. Your change applies after saving.")).toBeInTheDocument();
    const rate = screen.getByRole("textbox", { name: "Requests per minute" });
    await u.type(rate, "4000");
    expect(screen.getByText("At most the ceiling, 3,000 per minute.")).toBeInTheDocument();
    expect(screen.getByText("Not saved: fix the highlighted field")).toBeInTheDocument();
    // An invalid value is never previewed.
    expect(screen.getByText("Applies now: 2,000 per minute. Your change applies after saving.")).toBeInTheDocument();
    await u.clear(rate);
    await u.type(rate, "1500");
    expect(screen.getByText("Applies now: 2,000 per minute. After saving: 1,500 per minute.")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(1));
    expect(patches(calls)[0]?.body).toEqual({ name: "Support tools", description: gateway().description, enabled: true, rateLimitPerMinute: 1500 });
    expect(patches(calls)[0]?.headers.get("If-Match")).toBe('"7"');
    expect(await screen.findByText("Rate limit now: 1,500 per minute.")).toBeInTheDocument();
    expect(await screen.findByText("Applies now: 1,500 per minute.")).toBeInTheDocument();
  });

  it("previews going back to the inherited limit before saving", async () => {
    const u = userEvent.setup();
    mockApi(gatewayRoutes("owner", () => gateway({ capturePayloads: false, rateLimitPerMinute: 500, effectiveRateLimitPerMinute: 500 })));
    renderApp(`${gwRecord}?tab=settings`);
    const mode = await screen.findByRole("combobox", { name: "Limit" });
    expect(screen.getByText("Applies now: 500 per minute.")).toBeInTheDocument();
    await u.selectOptions(mode, "inherit");
    expect(await screen.findByText("Applies now: 500 per minute. After saving: 2,000 per minute.")).toBeInTheDocument();
  });

  it("explains recording and asks before turning it on", async () => {
    const u = userEvent.setup();
    let current = gateway({ capturePayloads: false, rateLimitPerMinute: null, effectiveRateLimitPerMinute: 2000 });
    const calls = mockApi(
      gatewayRoutes("owner", () => current, {
        [`PATCH ${teamApi}/gateways/${gatewayId}`]: (body) => (current = gateway({ ...current, ...(body as object), revision: 8 })),
      }),
    );
    renderApp(`${gwRecord}?tab=settings`);
    const sw = await screen.findByRole("switch", { name: /Record call contents/ });
    expect(await screen.findByText(/Readable by Platform Tools's owners and admins and by platform admins and auditors\..*Kept for 30 days, then deleted\./)).toBeInTheDocument();
    await u.click(sw);
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    const ask = await screen.findByRole("alertdialog", { name: "Record what's sent through Support tools?" });
    expect(ask).toHaveTextContent("[REDACTED]");
    expect(ask).toHaveTextContent("every view is audited");
    expect(ask).toHaveTextContent("Kept for 30 days, then deleted.");
    expect(patches(calls)).toHaveLength(0);
    await u.click(within(ask).getByRole("button", { name: "Cancel" }));
    expect(patches(calls)).toHaveLength(0);

    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await u.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Record call contents" }));
    await waitFor(() => expect(patches(calls)[0]?.body).toMatchObject({ capturePayloads: true }));
    expect(patches(calls)[0]?.body).not.toHaveProperty("rateLimitPerMinute");
    // The record says so at the top, and Overview shows it.
    expect(await screen.findByText("It records call contents from the next call.")).toBeInTheDocument();
    expect(screen.getAllByText("Records call contents").length).toBeGreaterThan(0);
  });

  it("turning recording off saves without asking; members read the settings", async () => {
    const u = userEvent.setup();
    let current = gateway({ capturePayloads: true, rateLimitPerMinute: 500, effectiveRateLimitPerMinute: 500 });
    const calls = mockApi(gatewayRoutes("owner", () => current, { [`PATCH ${teamApi}/gateways/${gatewayId}`]: (body) => (current = gateway({ ...current, ...(body as object), revision: 8 })) }));
    const { unmount } = renderApp(`${gwRecord}?tab=settings`);
    await u.click(await screen.findByRole("switch", { name: /Record call contents/ }));
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)[0]?.body).toMatchObject({ capturePayloads: false }));
    expect(screen.queryByRole("alertdialog")).toBeNull();
    unmount();

    mockApi(gatewayRoutes("member", () => gateway({ capturePayloads: true, rateLimitPerMinute: 500, effectiveRateLimitPerMinute: 500 })));
    renderApp(`${gwRecord}?tab=settings`);
    expect(await screen.findByRole("switch", { name: /Record call contents/ })).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByRole("combobox", { name: "Limit" })).toBeDisabled();
  });

  it("shows the limit and recording on the Overview", async () => {
    mockApi(gatewayRoutes("owner", () => gateway({ capturePayloads: true, rateLimitPerMinute: null, effectiveRateLimitPerMinute: 2000 })));
    renderApp(gwRecord);
    expect(await screen.findByText("2,000 per minute (inherited)")).toBeInTheDocument();
    expect(screen.getByText("Recorded")).toBeInTheDocument();
  });
});

describe("Server › Settings: recording", () => {
  const serverRoutes = (role: Role, s: () => Schemas["McpServer"], extra: Record<string, Handler> = {}): Record<string, Handler> => ({
    ...shellRoutes("none", role),
    [`GET ${teamApi}/mcp-servers/${serverId}`]: s,
    [`GET ${teamApi}/mcp-servers/${serverId}/capabilities`]: () => capabilities,
    [`GET ${teamApi}/mcp-servers/${serverId}/health-checks`]: () => [healthCheck()],
    [`GET ${teamApi}/publishing`]: () => teamPublishing(),
    [`GET ${teamApi}/retention`]: () => teamRetention(),
    ...extra,
  });

  it("lets owners turn it on after confirming, and keeps it read-only for editors", async () => {
    const u = userEvent.setup();
    let current = mcpServer({ capturePayloads: false });
    const calls = mockApi(serverRoutes("owner", () => current, { [`PATCH ${teamApi}/mcp-servers/${serverId}`]: (body) => (current = mcpServer({ ...(body as object), capturePayloads: true, revision: 5 })) }));
    const { unmount, container } = renderApp(`${serverRecord}?tab=settings`);
    const sw = await screen.findByRole("switch", { name: /Record call contents/ });
    expect(await axe(container)).toHaveNoViolations();
    await u.click(sw);
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    const ask = await screen.findByRole("alertdialog", { name: "Record what's sent to Service status?" });
    expect(ask).toHaveTextContent("including other teams' gateways");
    expect(ask).toHaveTextContent("Kept for 30 days, then deleted.");
    await u.click(within(ask).getByRole("button", { name: "Record call contents" }));
    await waitFor(() => expect(patches(calls)[0]?.body).toMatchObject({ capturePayloads: true }));
    expect(await screen.findByText("Records call contents")).toBeInTheDocument();
    unmount();

    const editorCalls = mockApi(serverRoutes("editor", () => mcpServer({ capturePayloads: false }), { [`PATCH ${teamApi}/mcp-servers/${serverId}`]: () => mcpServer({ revision: 5 }) }));
    renderApp(`${serverRecord}?tab=settings`);
    const locked = await screen.findByRole("switch", { name: /Record call contents/ });
    expect(locked).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByText(/Only the team's owners and admins can change it\./)).toBeInTheDocument();
    // An editor's other changes never carry the switch (403 capture_role otherwise).
    const name = screen.getByRole("textbox", { name: "Name" });
    await u.clear(name);
    await u.type(name, "Status");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(editorCalls)).toHaveLength(1));
    expect(patches(editorCalls)[0]?.body).not.toHaveProperty("capturePayloads");
  });

  it("shows a refusal (403 capture_role) like any other save error", async () => {
    const u = userEvent.setup();
    mockApi(serverRoutes("owner", () => mcpServer({ capturePayloads: false }), { [`PATCH ${teamApi}/mcp-servers/${serverId}`]: () => Reply.error(403, "capture_role", "Only owners and admins can change capture.") }));
    renderApp(`${serverRecord}?tab=settings`);
    await u.click(await screen.findByRole("switch", { name: /Record call contents/ }));
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await u.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Record call contents" }));
    expect((await screen.findAllByText("Only owners and admins can change capture.")).length).toBeGreaterThan(0);
  });
});

describe("Telling callers that contents are recorded", () => {
  it("My gateways marks a recording gateway and its page says what that means", async () => {
    mockApi({
      ...shellRoutes("none", "member"),
      "GET /v1/me/gateways": () => [myGateway({ capturesPayloads: true })],
      [`GET /v1/me/gateways/${gatewayId}`]: () => ({ gateway: myGateway({ capturesPayloads: true }), capabilities: [gatewayCapability({ serverCapturesPayloads: true })] }),
      "GET /v1/me/connections": () => [],
    });
    const { unmount } = renderApp("/gateways");
    const table = await screen.findByRole("table", { name: "My gateways" });
    expect(await within(table).findByText("Records what you send")).toBeInTheDocument();
    unmount();

    const { container } = renderApp(`/gateways/${gatewayId}`);
    expect(await screen.findByText("This gateway records what you send")).toBeInTheDocument();
    expect(screen.getByText(/Its owners can read what you send through it/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("a gateway that doesn't record says nothing about it", async () => {
    mockApi({
      ...shellRoutes("none", "member"),
      [`GET /v1/me/gateways/${gatewayId}`]: () => ({ gateway: myGateway({ capturesPayloads: false }), capabilities: [gatewayCapability()] }),
      "GET /v1/me/connections": () => [],
    });
    renderApp(`/gateways/${gatewayId}`);
    expect(await screen.findByRole("heading", { level: 1, name: "Support tools" })).toBeInTheDocument();
    expect(screen.queryByText("This gateway records what you send")).toBeNull();
  });

  it("the catalog marks a server whose team records contents", async () => {
    mockApi({
      ...shellRoutes("none", null),
      "GET /v1/catalog/servers": () => page([catalogServer({ capturePayloads: true }), catalogServer({ id: "srv_quiet", name: "Quiet server", capturePayloads: false })]),
      [`GET /v1/catalog/servers/${serverId}`]: () => ({ server: catalogServer({ capturePayloads: true }), capabilities: [] }),
    });
    // The list carries the same badge as the page, only on the server that records.
    const { unmount } = renderApp("/catalog");
    const table = await screen.findByRole("table", { name: "Published MCP servers" });
    const recording = (await within(table).findByRole("link", { name: catalogServer().name })).closest("tr");
    const quiet = within(table).getByRole("link", { name: "Quiet server" }).closest("tr");
    expect(recording && within(recording).getByText("Records call contents")).toBeInTheDocument();
    expect(quiet && within(quiet).queryByText("Records call contents")).toBeNull();
    unmount();

    renderApp(`/catalog/${serverId}`);
    expect(await screen.findByText("This server's team records call contents")).toBeInTheDocument();
    expect(screen.getByText("Records call contents")).toBeInTheDocument();
  });
});
