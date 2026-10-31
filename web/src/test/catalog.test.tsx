/* The Catalog: published servers for everyone signed in (no team needed), and a server's approved capabilities. */
import { screen, waitFor, within } from "@testing-library/react";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { catalogServer, page, serverId, team } from "./fixtures";
import { type Handler, mockApi, renderApp, shellRoutes } from "./harness";

const detail: Schemas["CatalogServerDetail"] = {
  server: catalogServer(),
  capabilities: [
    { id: "c1", kind: "tool", name: "get_status", title: "Get status", description: "Returns the status of a service.", definition: { name: "get_status", inputSchema: { type: "object" } }, requires: null },
    { id: "c2", kind: "prompt", name: "incident_summary", title: "", description: "Summarise an incident.", definition: { name: "incident_summary" }, requires: null },
  ],
};

const routes = (teamRole: Schemas["TeamRole"] | null = null, extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", teamRole),
  "GET /v1/catalog/servers": () => page([catalogServer()]),
  [`GET /v1/catalog/servers/${serverId}`]: () => detail,
  ...extra,
});

describe("Catalog", () => {
  it("lists published servers with their team, what they offer and their health, for someone without a team", async () => {
    const calls = mockApi(routes(null));
    const { container } = renderApp("/catalog?q=status");
    expect(await screen.findByRole("heading", { level: 1, name: "Catalog" })).toBeInTheDocument();
    expect(screen.getByText(/To use its tools, people connect through a gateway, which is where access is granted/)).toBeInTheDocument();
    expect(screen.queryByText(/coming next/)).toBeNull();
    const table = await screen.findByRole("table", { name: "Published MCP servers" });
    const row = (await within(table).findByText("Service status")).closest("tr")!;
    expect(row).toHaveTextContent(team.name);
    expect(row).toHaveTextContent("2 tools · 1 resource · 1 prompt");
    expect(row).toHaveTextContent("Healthy");
    expect(within(row).getByRole("link", { name: "Service status" })).toHaveAttribute("href", `/catalog/${serverId}`);
    await waitFor(() => expect(calls.some((c) => c.url === "/v1/catalog/servers" && c.search.get("q") === "status")).toBe(true));
    // In the sidebar for everyone.
    expect(within(screen.getByRole("navigation", { name: "Main" })).getByRole("link", { name: "Catalog" })).toHaveAttribute("aria-current", "page");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("finds a server from an approved capability and links to its catalog detail", async () => {
    const calls = mockApi(routes(null, {
      "GET /v1/catalog/servers": (_body, call) =>
        call.search.get("q") === "check_outage" ? page([catalogServer({ name: "Operations", description: "<img src=x onerror=alert(1)>" })]) : page([]),
    }));
    renderApp("/catalog?q=check_outage");
    expect(await screen.findByRole("link", { name: "Operations" })).toHaveAttribute("href", `/catalog/${serverId}`);
    expect(screen.getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(screen.queryByRole("img")).toBeNull();
    expect(screen.getByRole("searchbox", { name: "Search the catalog" })).toHaveAttribute("placeholder", "Server, team or approved capability");
    await waitFor(() => expect(calls.some((c) => c.search.get("q") === "check_outage")).toBe(true));
  });

  it("shows the filtered empty state without capability snippets", async () => {
    mockApi(routes(null, { "GET /v1/catalog/servers": () => page([]) }));
    renderApp("/catalog?q=hidden_capability");
    expect(await screen.findByText(/No results for “hidden_capability”/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Service status" })).toBeNull();
  });

  it("says when nothing is published yet", async () => {
    mockApi(routes(null, { "GET /v1/catalog/servers": () => page([]) }));
    renderApp("/catalog");
    expect(await screen.findByText("Nothing in the catalog yet.")).toBeInTheDocument();
  });

  it("shows a server's approved capabilities by kind, with their definitions", async () => {
    mockApi(routes(null));
    const { container } = renderApp(`/catalog/${serverId}`);
    expect(await screen.findByRole("heading", { level: 1, name: "Service status" })).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Tools" })).toHaveTextContent("get_status");
    expect(screen.getByRole("list", { name: "Prompts" })).toHaveTextContent("incident_summary");
    expect(screen.queryByRole("list", { name: "Resources" })).toBeNull();
    expect(screen.getAllByRole("button", { name: /Definition/ })).toHaveLength(2);
    // Not on the owning team: no link to its page.
    expect(screen.queryByRole("link", { name: /Open in your team/ })).toBeNull();
    await waitFor(() => expect(document.title).toBe("Service status · Catalog · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("links the owning team's members to their record", async () => {
    mockApi(routes("member"));
    renderApp(`/catalog/${serverId}`);
    expect(await screen.findByRole("link", { name: /Open in your team/ })).toHaveAttribute("href", `/teams/${team.slug}/servers/${serverId}`);
  });
});
