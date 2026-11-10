/* A server's Overview tab: the MCP protocol version last negotiated (modern, legacy, or not yet). */
import { screen, within } from "@testing-library/react";
import { capabilities, healthCheck, mcpServer, page, serverId, team, teamPublishing } from "./fixtures";
import { type Handler, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";
import type { Schemas } from "../api/client";

const base = `/v1/teams/${team.slug}/mcp-servers`;
const routes = (server: Schemas["McpServer"]): Record<string, Handler> => ({
  ...shellRoutes("none", "member"),
  [`GET ${base}`]: () => page([server]),
  [`GET ${base}/${serverId}`]: () => server,
  [`GET ${base}/${serverId}/capabilities`]: () => capabilities,
  [`GET ${base}/${serverId}/health-checks`]: () => [healthCheck()],
  [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing(),
});
const open = () => renderApp(`/teams/${team.slug}/servers/${serverId}`);

describe("Server Overview › protocol", () => {
  it("shows the negotiated version, its era and when", async () => {
    mockApi(routes(mcpServer({ protocol: { era: "modern", version: "2026-07-28", negotiatedAt: new Date(Date.now() - 3 * 3_600_000).toISOString() } })));
    open();
    const row = (await screen.findByText("Upstream")).closest("div")!;
    expect(row).toHaveTextContent(/Protocol 2026-07-28 \(modern\), negotiated 3 hours ago/);
    expect(within(row).getByTitle(/Modern: protocol version 2026-07-28 or later/)).toBeInTheDocument();
  });

  it("calls the older era legacy", async () => {
    mockApi(routes(mcpServer({ protocol: { era: "legacy", version: "2025-11-25", negotiatedAt: "2026-10-16T07:55:00Z" } })));
    open();
    expect((await screen.findByText("Upstream")).closest("div")).toHaveTextContent("Protocol 2025-11-25 (legacy), negotiated");
  });

  it("says Not negotiated yet when there is none (null, or absent on an older server)", async () => {
    mockApi(routes(mcpServer({ protocol: null })));
    const first = open();
    expect((await screen.findByText("Upstream")).closest("div")).toHaveTextContent("Not negotiated yet");
    first.unmount();
    mockApi(routes(mcpServer()));
    open();
    expect((await screen.findByText("Upstream")).closest("div")).toHaveTextContent("Not negotiated yet");
  });
});
