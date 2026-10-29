import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { endpointFormsOf, endpointsBody, endpointProblems, endpointReviewChanged } from "../components/servers/endpoints";
import { capabilities, healthCheck, mcpServer, serverId, team, teamPublishing } from "./fixtures";
import { teamRetention } from "./fixtures-operations";
import { type Handler, mockApi, renderApp, shellRoutes } from "./harness";

const base = `/v1/teams/${team.slug}/mcp-servers/${serverId}`;
const record = `/teams/${team.slug}/servers/${serverId}?tab=settings`;
const replica = { id: "10000000-0000-0000-0000-000000000001", position: 1, url: "https://replica.example/mcp", enabled: true, authMode: "none" as const, credentials: [] };
const noAuth = () => mcpServer({ authMode: "none", hasAuth: false, authHeaderName: undefined, authValueHint: "", credentials: [], endpoints: [replica] });
function routes(role: "owner" | "editor", current: () => ReturnType<typeof mcpServer>, extra: Record<string, Handler> = {}): Record<string, Handler> {
  return { ...shellRoutes("none", role), [`GET ${base}`]: current, [`GET ${base}/capabilities`]: () => capabilities, [`GET ${base}/health-checks`]: () => [healthCheck()],
    [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing(), [`GET /v1/teams/${team.slug}/retention`]: () => teamRetention(), ...extra };
}

describe("Additional server endpoints", () => {
  it("saves destinations with revision and explains primary-only governed calls", async () => {
    const u = userEvent.setup(); let current = noAuth();
    const calls = mockApi(routes("owner", () => current, { [`PATCH ${base}`]: (body) => (current = mcpServer({ ...current, ...(body as object), revision: current.revision + 1 })) }));
    const { container } = renderApp(record);
    const url = await screen.findByRole("textbox", { name: "Additional endpoint 1 URL" });
    expect(screen.getByText(/Governed and NoReplay calls always use the primary/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await u.clear(url); await u.type(url, "https://second.example/mcp");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toMatchObject({ endpoints: [{ id: replica.id, url: "https://second.example/mcp", enabled: true, credentials: [] }] }));
    expect(calls.find((c) => c.method === "PATCH")?.headers.get("If-Match")).toBe('"4"');
  });

  it("clears all extras explicitly without silently modifying the primary", async () => {
    const u = userEvent.setup(); let current = noAuth();
    const calls = mockApi(routes("owner", () => current, { [`PATCH ${base}`]: (body) => (current = mcpServer({ ...current, ...(body as object), revision: current.revision + 1 })) }));
    renderApp(record); await screen.findByRole("textbox", { name: "Additional endpoint 1 URL" });
    await u.click(screen.getByRole("button", { name: "Remove all endpoints" }));
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toMatchObject({ endpoints: [], url: current.url }));
  });

  it("lets editors change metadata but never emits endpoint settings", async () => {
    const u = userEvent.setup(); let current = noAuth();
    const calls = mockApi(routes("editor", () => current, { [`PATCH ${base}`]: (body) => (current = mcpServer({ ...current, ...(body as object), revision: current.revision + 1 })) }));
    renderApp(record); expect(await screen.findByRole("textbox", { name: "Additional endpoint 1 URL" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Add endpoint" })).not.toBeInTheDocument();
    await u.type(screen.getByRole("textbox", { name: "Name" }), " edited"); await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    expect(calls.find((c) => c.method === "PATCH")?.body).not.toHaveProperty("endpoints");
  });

  it("requires static values again on an origin change, never primary inheritance", async () => {
    const u = userEvent.setup();
    const ep = { ...replica, authMode: "static_header" as const, credentials: [{ kind: "header" as const, name: "X-Replica-Key", hint: "8842" }] };
    let current = mcpServer({ authMode: "static_header", endpoints: [ep] });
    const calls = mockApi(routes("owner", () => current, { [`PATCH ${base}`]: (body) => (current = mcpServer({ ...current, ...(body as object), endpoints: [ep], revision: current.revision + 1 })) }));
    renderApp(record); const url = await screen.findByRole("textbox", { name: "Additional endpoint 1 URL" });
    await u.clear(url); await u.type(url, "https://new-origin.example/mcp"); await u.click(screen.getByRole("button", { name: "Save settings" }));
    expect(screen.getByText("The URL moves to another host, so enter this value again, or remove the part.")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "PATCH")).toBe(false);
    const endpoint = screen.getByRole("group", { name: "Additional endpoint 1" });
    await u.type(within(endpoint).getByLabelText("Replace value"), "new-independent-secret"); await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toMatchObject({ endpoints: [{ id: ep.id, credentials: [{ kind: "header", name: "X-Replica-Key", value: "new-independent-secret" }] }] }));
  });

  it("checks duplicate destinations, mode restrictions and stable secret-free retention", () => {
    const server = noAuth(); const forms = endpointFormsOf(server);
    expect(endpointsBody(forms, server, "none")).toBeUndefined(); expect(endpointReviewChanged(forms, server)).toBe(false);
    const changed = forms.map((e) => ({ ...e, url: server.url })); expect(Object.keys(endpointProblems(changed, server, "none", false, false))).toHaveLength(1);
    expect(Object.keys(endpointProblems(forms, server, "oauth", false, true))).toHaveLength(1);
    expect(endpointsBody([], server, "none")).toEqual([]);
  });
});
