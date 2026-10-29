import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { protectionBody, protectionProblems } from "../components/servers/protection-fields";
import { capabilities, healthCheck, mcpServer, serverId, team, teamPublishing } from "./fixtures";
import { teamRetention } from "./fixtures-operations";
import { type Handler, mockApi, renderApp, shellRoutes } from "./harness";

const base = `/v1/teams/${team.slug}/mcp-servers/${serverId}`;
const record = `/teams/${team.slug}/servers/${serverId}?tab=settings`;
function routes(role: "owner" | "editor", current: () => ReturnType<typeof mcpServer>, extra: Record<string, Handler> = {}): Record<string, Handler> {
  return {
    ...shellRoutes("none", role),
    [`GET ${base}`]: current,
    [`GET ${base}/capabilities`]: () => capabilities,
    [`GET ${base}/health-checks`]: () => [healthCheck()],
    [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing(),
    [`GET /v1/teams/${team.slug}/retention`]: () => teamRetention(),
    ...extra,
  };
}

describe("Upstream protection settings", () => {
  it("saves nullable limits with the existing server revision and explains replica-local scope", async () => {
    const u = userEvent.setup();
    let current = mcpServer({ rateLimitPerMinute: null, maxConcurrent: null });
    const calls = mockApi(routes("owner", () => current, { [`PATCH ${base}`]: (body) => (current = mcpServer({ ...current, ...(body as object), revision: current.revision + 1 })) }));
    const { container } = renderApp(record);
    const rate = await screen.findByRole("textbox", { name: "Forwarded attempts per minute" });
    const cap = screen.getByRole("textbox", { name: "Concurrent forwarded operations" });
    expect(rate).toHaveValue("");
    expect(cap).toHaveValue("");
    expect(screen.getByText(/No queue or distributed lease/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await u.type(rate, "120");
    await u.type(cap, "3");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toMatchObject({ rateLimitPerMinute: 120, maxConcurrent: 3 }));
    expect(calls.find((c) => c.method === "PATCH")?.headers.get("If-Match")).toBe('"4"');
    await screen.findByText("Server settings saved");
  });

  it("returns explicit null when the owner clears the fields", async () => {
    const u = userEvent.setup();
    let current = mcpServer({ rateLimitPerMinute: 10, maxConcurrent: 1 });
    const calls = mockApi(routes("owner", () => current, { [`PATCH ${base}`]: (body) => (current = mcpServer({ ...current, ...(body as object), revision: current.revision + 1 })) }));
    renderApp(record);
    await u.clear(await screen.findByRole("textbox", { name: "Forwarded attempts per minute" }));
    await u.clear(screen.getByRole("textbox", { name: "Concurrent forwarded operations" }));
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toMatchObject({ rateLimitPerMinute: null, maxConcurrent: null }));
  });

  it("lets editors change metadata without sending owner-only fields", async () => {
    const u = userEvent.setup();
    let current = mcpServer({ rateLimitPerMinute: 10, maxConcurrent: 1 });
    const calls = mockApi(routes("editor", () => current, { [`PATCH ${base}`]: (body) => (current = mcpServer({ ...current, ...(body as object), revision: current.revision + 1 })) }));
    renderApp(record);
    expect(await screen.findByRole("textbox", { name: "Forwarded attempts per minute" })).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Concurrent forwarded operations" })).toBeDisabled();
    await u.type(screen.getByRole("textbox", { name: "Name" }), " edited");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    const body = calls.find((c) => c.method === "PATCH")?.body;
    expect(body).not.toHaveProperty("maxConcurrent");
    expect(body).not.toHaveProperty("rateLimitPerMinute");
  });

  it("checks bounds without converting invalid values into inheritance", () => {
    for (const value of ["0", "-1", "1.5", "NaN", "1000001"]) expect(protectionProblems({ rate: value, concurrent: "" }).rate).toBeTruthy();
    expect(protectionProblems({ rate: "", concurrent: "10001" }).concurrent).toBeTruthy();
    expect(protectionProblems({ rate: "1000000", concurrent: "10000" })).toEqual({});
    expect(protectionBody({ rate: "", concurrent: "" }, { rate: "1", concurrent: "2" })).toEqual({ rateLimitPerMinute: null, maxConcurrent: null });
  });
});
