import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { agentLine } from "../components/gateways/calls-table";
import { mcpCall, page, serviceAccount, serviceAccountId, team } from "./fixtures";
import { type Handler, mockApi, renderApp, shellRoutes } from "./harness";

const base = `/v1/teams/${team.slug}/service-accounts`;
const record = `/teams/${team.slug}/service-accounts/${serviceAccountId}`;
const retired = serviceAccount({ retired: true, enabled: false, activeKeyCount: 0 });
const routes = (): Record<string, Handler> => ({
  ...shellRoutes("platform_admin", "owner"),
  [`GET ${base}`]: () => [retired],
  [`GET ${base}/${serviceAccountId}`]: () => retired,
  [`GET ${base}/${serviceAccountId}/keys`]: () => [],
  [`GET ${base}/${serviceAccountId}/gateways`]: () => [],
});

describe("External-platform retirement", () => {
  it("explains a retired account, offers no relay controls and cannot enable it or create keys", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes());
    const { container } = renderApp(record);
    expect(await screen.findByText("Permanently retired")).toBeInTheDocument();
    expect(screen.getByText(/Create a new ordinary service account and key explicitly/)).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Trusted agent platforms" })).toBeNull();
    expect(screen.queryByRole("combobox", { name: "Agent platform" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Mark as a relay" })).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("tab", { name: "Settings" }));
    expect(await screen.findByRole("switch", { name: "Enabled" })).toHaveAttribute("aria-disabled", "true");
    await u.click(screen.getByRole("tab", { name: /Keys/ }));
    expect(await screen.findByText(/Permanently retired. Create a new ordinary service account and key/)).toBeInTheDocument();
    expect(calls.some((c) => c.url.includes("agent-platforms") || c.method === "PATCH" || c.method === "POST")).toBe(false);
  });

  it("marks retained legacy accounts as retired in the list", async () => {
    mockApi(routes());
    renderApp(`/teams/${team.slug}/service-accounts`);
    const table = await screen.findByRole("table", { name: "Service accounts" });
    expect((await within(table).findByText(retired.name)).closest("tr")).toHaveTextContent("Retired");
  });
});

// Historical attribution remains readable; these fixtures cannot create trust.
const agentCall = (extra: Partial<Schemas["AgentCall"]> = {}): Schemas["AgentCall"] => ({
  platformId: "21212121-2121-4121-8121-212121212121",
  platformName: "Pi Durable Platform",
  agentId: "old-agent",
  agentName: "Mail assistant",
  personPresent: true,
  person: { userId: "10101010-1010-4101-8101-101010101010", email: "una@example.com", displayName: "Una User" },
  ...extra,
});

describe("Retained historical attribution", () => {
  const historical = mcpCall({
    id: 601,
    exposedName: "service-status__restart",
    principal: { kind: "service_account", displayName: "pdp-relay", apiKeyName: "pdp", serviceAccountId, serviceAccountTeamSlug: team.slug, serviceAccountExists: true },
    agent: agentCall(),
  });
  const historyRoutes = (): Record<string, Handler> => ({
    ...shellRoutes("platform_admin", null),
    "GET /v1/admin/calls": () => page([historical]),
    "GET /v1/admin/calls/601": () => historical,
    "GET /v1/admin/gateways": () => page([]),
    "GET /v1/admin/mcp-servers": () => page([]),
    "GET /v1/admin/users": () => page([]),
    "GET /v1/admin/teams": () => page([]),
    "GET /v1/admin/service-accounts": () => page([]),
  });
  it("still shows the original platform, agent and person on old calls", async () => {
    mockApi(historyRoutes());
    renderApp("/admin/calls/601");
    expect(await screen.findByText("Mail assistant via Pi Durable Platform")).toBeInTheDocument();
    expect(screen.getByText("Una User · una@example.com · present")).toBeInTheDocument();
    expect(agentLine({ agent: agentCall() })).toBe("Mail assistant via Pi Durable Platform · for Una User");
  });
});
