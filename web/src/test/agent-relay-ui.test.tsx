/*
 * Agent platform relays in the team and server pages (decisions 65 and 66): the relay mark on service accounts (read
 * by everyone who reads the account, changed by platform admins only), "requires a present person" on a server and
 * its capabilities (editors; relaxing it says the server goes back to review), and how the call log shows an agent's
 * call and its refusals.
 */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { agentLine } from "../components/gateways/calls-table";
import { callErrorLabel } from "../components/gateways/labels";
import { capabilities, capability, healthCheck, mcpCall, mcpServer, page, serverId, serviceAccount, serviceAccountId, team, teamPublishing } from "./fixtures";
import { agentCall, agentPlatform, platformId } from "./fixtures-agents";
import { type Call, type Handler, mockApi, renderApp, shellRoutes } from "./harness";

type McpServer = Schemas["McpServer"];
const saBase = `/v1/teams/${team.slug}/service-accounts`;
const record = `/teams/${team.slug}/service-accounts/${serviceAccountId}`;
const relay = { relayPlatform: { id: platformId, name: "Pi Durable Platform" } };

const saRoutes = (teamRole: Schemas["TeamRole"] | null, sa: Schemas["ServiceAccount"], platformRole: Schemas["PlatformRole"] = "none", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes(platformRole, teamRole),
  [`GET ${saBase}`]: () => [sa],
  [`GET ${saBase}/${serviceAccountId}`]: () => sa,
  [`GET ${saBase}/${serviceAccountId}/keys`]: () => [],
  [`GET ${saBase}/${serviceAccountId}/gateways`]: () => [],
  "GET /v1/admin/agent-platforms": () => [agentPlatform(), agentPlatform({ id: "22222222-2222-4222-8222-222222222222", name: "Off platform", enabled: false })],
  ...extra,
});

describe("Service accounts that relay for an agent platform", () => {
  it("marks the account in the list and on its page, for everyone who reads it", async () => {
    mockApi(saRoutes("member", serviceAccount(relay)));
    renderApp(`/teams/${team.slug}/service-accounts`);
    const table = await screen.findByRole("table", { name: "Service accounts" });
    expect((await within(table).findByText("ci-release-bot")).closest("tr")).toHaveTextContent("Relay for Pi Durable Platform");
  });

  it("tells a team owner about the mark without a control to change it", async () => {
    mockApi(saRoutes("owner", serviceAccount(relay)));
    const { container } = renderApp(record);
    expect(await screen.findByRole("heading", { level: 2, name: "Agent platform relay" })).toBeInTheDocument();
    expect(screen.getByText(/Calls with this account's keys may carry Pi Durable Platform's identity token/)).toBeInTheDocument();
    expect(screen.getByText(/using that person's own connections/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove the relay mark" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Mark as a relay" })).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows nothing about relays on an ordinary account to a team owner", async () => {
    mockApi(saRoutes("owner", serviceAccount()));
    renderApp(record);
    expect(await screen.findByRole("heading", { level: 2, name: "Access" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Agent platform relay" })).toBeNull();
  });

  it("lets a platform admin mark an account for a platform that is on, and remove the mark", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      saRoutes("owner", serviceAccount(), "platform_admin", {
        [`PUT /v1/admin/agent-platforms/${platformId}/relays/${serviceAccountId}`]: () => ({ serviceAccountId, name: "ci-release-bot", teamId: team.id, teamSlug: team.slug, teamName: team.name, role: "member", enabled: true }),
        [`DELETE /v1/admin/agent-platforms/${platformId}/relays/${serviceAccountId}`]: () => ({ ok: true }),
      }),
    );
    renderApp(record);
    const choice = await screen.findByRole("combobox", { name: "Agent platform" });
    // A platform that is off can't be chosen.
    expect(within(choice).queryByRole("option", { name: "Off platform" })).toBeNull();
    await u.selectOptions(choice, platformId);
    await u.click(screen.getByRole("button", { name: "Mark as a relay" }));
    await waitFor(() => expect(calls.filter((c: Call) => c.method === "PUT" && c.url.endsWith(`/relays/${serviceAccountId}`))).toHaveLength(1));
  });

  it("removes a mark after a confirmation", async () => {
    const u = userEvent.setup();
    const calls = mockApi(saRoutes("owner", serviceAccount(relay), "platform_admin", { [`DELETE /v1/admin/agent-platforms/${platformId}/relays/${serviceAccountId}`]: () => ({ ok: true }) }));
    renderApp(record);
    await u.click(await screen.findByRole("button", { name: "Remove the relay mark" }));
    const dialog = await screen.findByRole("alertdialog", { name: "Remove the relay mark from ci-release-bot?" });
    expect(calls.filter((c) => c.method === "DELETE")).toHaveLength(0);
    await u.click(within(dialog).getByRole("button", { name: "Remove the mark" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "DELETE")).toHaveLength(1));
  });
});

const base = `/v1/teams/${team.slug}/mcp-servers`;
const recordPath = `/teams/${team.slug}/servers/${serverId}`;
const patches = (calls: Call[]) => calls.filter((c) => c.method === "PATCH" && c.url === `${base}/${serverId}`);

const serverRoutes = (role: Schemas["TeamRole"], server: McpServer, caps: Schemas["McpCapability"][] = capabilities, extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", role),
  [`GET ${base}`]: () => page([server]),
  [`GET ${base}/${serverId}`]: () => server,
  [`GET ${base}/${serverId}/capabilities`]: () => caps,
  [`GET ${base}/${serverId}/health-checks`]: () => [healthCheck()],
  [`GET /v1/teams/${team.slug}/publishing`]: () => teamPublishing({ effective: server.effectivePublishPolicy }),
  "GET /v1/auth-providers": () => [],
  [`PATCH ${base}/${serverId}`]: (body) => ({ ...server, ...(body as object), revision: server.revision + 1 }),
  ...extra,
});

const switchName = /Require a present person for calls from agents/;

describe("Requires a present person", () => {
  it("is a switch in the server's settings for editors, saved with the server (If-Match)", async () => {
    const u = userEvent.setup();
    const calls = mockApi(serverRoutes("editor", mcpServer()));
    const { container } = renderApp(`${recordPath}?tab=settings`);
    const sw = await screen.findByRole("switch", { name: switchName });
    expect(sw).not.toBeChecked();
    expect(screen.getByText(/Recommended for tools that send mail, post or spend/)).toBeInTheDocument();
    await u.click(sw);
    // Turning it on never sends a published server back to review.
    expect(screen.queryByText("The server will leave the catalog")).toBeNull();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(1));
    expect(patches(calls)[0]!.body).toMatchObject({ requiresPresentPerson: true });
    expect(patches(calls)[0]!.headers.get("If-Match")).toBe('"4"');
  });

  it("is read-only for members", async () => {
    mockApi(serverRoutes("member", mcpServer({ requiresPresentPerson: true })));
    renderApp(`${recordPath}?tab=settings`);
    const sw = await screen.findByRole("switch", { name: switchName });
    expect(sw).toBeChecked();
    expect(sw).toHaveAttribute("aria-disabled", "true");
  });

  it("warns that turning it off sends a published server back to review, when some capability follows the switch", async () => {
    const u = userEvent.setup();
    const caps = [capability({ presentPerson: { mode: "inherit", effective: true } })];
    const calls = mockApi(serverRoutes("editor", mcpServer({ publishState: "published", requiresPresentPerson: true }), caps));
    renderApp(`${recordPath}?tab=settings`);
    const sw = await screen.findByRole("switch", { name: switchName });
    await u.click(sw);
    expect(await screen.findByText("The server will leave the catalog")).toBeInTheDocument();
    expect(screen.getByText(/lets agents call some capabilities when nobody is present/)).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(patches(calls)).toHaveLength(1));
    expect(patches(calls)[0]!.body).toMatchObject({ requiresPresentPerson: false });
  });

  it("is overridden per capability: inherit, required or not required, with the server's revision", async () => {
    const u = userEvent.setup();
    const caps = [capability({ presentPerson: { mode: "inherit", effective: true } }), capability({ id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", name: "restart", presentPerson: { mode: "not_required", effective: false } })];
    const put = `${base}/${serverId}/capabilities/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/present-person`;
    const calls = mockApi(serverRoutes("editor", mcpServer({ requiresPresentPerson: true }), caps, { [`PUT ${put}`]: () => capability({ presentPerson: { mode: "not_required", effective: false } }) }));
    renderApp(`${recordPath}?tab=capabilities`);
    const first = (await screen.findByLabelText("tool: get_status")).closest("li")!;
    expect(first).toHaveTextContent("Needs a present person");
    expect(screen.getByLabelText("tool: restart")).not.toHaveTextContent("Needs a present person");
    await u.click(within(first).getByRole("button", { name: /Change whether get_status needs a present person \(now: same as the server\)/ }));
    const dialog = await screen.findByRole("dialog", { name: "Present person for get_status" });
    expect(within(dialog).getByText(/The server requires a present person, so this capability does too/)).toBeInTheDocument();
    await u.click(within(dialog).getByRole("radio", { name: /Doesn't need a present person/ }));
    await u.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PUT" && c.url === put)).toHaveLength(1));
    const sent = calls.find((c) => c.method === "PUT" && c.url === put)!;
    expect(sent.body).toEqual({ mode: "not_required" });
    expect(sent.headers.get("If-Match")).toBe('"4"');
  });

  it("warns, on a published server, that relaxing one capability sends it back to review", async () => {
    const u = userEvent.setup();
    const caps = [capability({ presentPerson: { mode: "inherit", effective: true } })];
    mockApi(serverRoutes("editor", mcpServer({ publishState: "published", requiresPresentPerson: true }), caps));
    renderApp(`${recordPath}?tab=capabilities`);
    const row = (await screen.findByLabelText("tool: get_status")).closest("li")!;
    await u.click(within(row).getByRole("button", { name: /Change whether get_status needs a present person/ }));
    const dialog = await screen.findByRole("dialog", { name: "Present person for get_status" });
    expect(within(dialog).queryByText("The server will leave the catalog")).toBeNull();
    await u.click(within(dialog).getByRole("radio", { name: /Doesn't need a present person/ }));
    expect(await within(dialog).findByText("The server will leave the catalog")).toBeInTheDocument();
  });

  it("is not offered to members", async () => {
    mockApi(serverRoutes("member", mcpServer(), [capability({ presentPerson: { mode: "inherit", effective: false } })]));
    renderApp(`${recordPath}?tab=capabilities`);
    const row = (await screen.findByLabelText("tool: get_status")).closest("li")!;
    expect(within(row).queryByRole("button", { name: /present person/ })).toBeNull();
  });
});

describe("Calls from agents in the call log", () => {
  const relayed = mcpCall({
    id: 601,
    exposedName: "service-status__restart",
    principal: { kind: "service_account", displayName: "pdp-relay", apiKeyName: "pdp", serviceAccountId, serviceAccountTeamSlug: team.slug, serviceAccountExists: true },
    agent: agentCall(),
  });
  const absent = mcpCall({
    id: 602,
    exposedName: "service-status__send",
    outcome: "denied",
    errorClass: "person_not_present",
    principal: relayed.principal,
    agent: agentCall({ personPresent: false }),
  });
  const connect = mcpCall({
    id: 603,
    exposedName: "service-status__mail",
    outcome: "needs_authorization",
    errorClass: "needs_connection",
    principal: relayed.principal,
    agent: agentCall(),
  });
  const own = mcpCall({ id: 604, exposedName: "service-status__own", principal: relayed.principal, agent: agentCall({ person: null, personPresent: null }) });
  const calls = [relayed, absent, connect, own];
  const routes = (): Record<string, Handler> => ({
    ...shellRoutes("platform_admin", null),
    "GET /v1/admin/calls": () => page(calls),
    "GET /v1/admin/calls/601": () => relayed,
    "GET /v1/admin/gateways": () => page([]),
    "GET /v1/admin/mcp-servers": () => page([]),
    "GET /v1/admin/users": () => page([]),
    "GET /v1/admin/teams": () => page([]),
    "GET /v1/admin/service-accounts": () => page([]),
  });

  it("says which agent called, through which platform, for whom, and whether they were present", async () => {
    mockApi(routes());
    const { container } = renderApp("/admin/calls");
    const table = await screen.findByRole("table", { name: "Calls" });
    const row = async (name: string) => (await within(table).findByText(name)).closest("tr")!;
    const r = await row("service-status__restart");
    expect(r).toHaveTextContent("pdp-relay");
    expect(r).toHaveTextContent("Mail assistant via Pi Durable Platform · for Una User");
    expect(r).not.toHaveTextContent("not present");
    const a = await row("service-status__send");
    expect(a).toHaveTextContent("for Una User (not present)");
    expect(a).toHaveTextContent("Needs a present person");
    expect(await row("service-status__mail")).toHaveTextContent("Needs a connection (an agent call: no link was given)");
    expect(await row("service-status__own")).toHaveTextContent("Mail assistant via Pi Durable Platform · no person named");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows the agent and the person on the call's page", async () => {
    mockApi(routes());
    renderApp("/admin/calls/601");
    expect(await screen.findByText("Mail assistant via Pi Durable Platform")).toBeInTheDocument();
    expect(screen.getByText("Una User · una@example.com · present")).toBeInTheDocument();
  });

  it("words the refusals and the agent line", () => {
    expect(callErrorLabel("person_no_account")).toBe("The person has no active account");
    expect(callErrorLabel("person_suspended")).toBe("The person is suspended");
    expect(agentLine({ agent: null })).toBeUndefined();
    expect(agentLine({ agent: agentCall({ agentName: null }) })).toBe("0e6a3d4c-5f1b-4f0e-9b8e-2d7c1a9f3b21 via Pi Durable Platform · for Una User");
  });
});
