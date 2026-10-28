/*
 * "Needs GitHub (repo)" wherever capabilities are shown (a gateway's Capabilities tab and picker, the catalog, My
 * gateways with connected or not and Connect), calls that needed a connection, and the Phase 5 audit words.
 */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { auditChange, changedRows } from "../components/audit/changes";
import { actionLabel, areaOf, targetTypeLabel } from "../components/audit/labels";
import { callErrorLabel, outcomeLabels } from "../components/gateways/labels";
import { redirectTo } from "../components/providers/labels";
import { neededAccounts } from "../components/providers/needed-accounts";
import { catalogServer, gateway, gatewayCapabilities, gatewayCapability, gatewayId, gatewayOption, mcpCall, myGateway, optionsPage, page, serverId, team } from "./fixtures";
import { googleId, providerId, providerSummaries, requires } from "./fixtures-providers";
import { type Handler, mockApi, renderApp, shellRoutes } from "./harness";

afterEach(() => vi.restoreAllMocks());

const restart = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const needsGithub = gatewayCapability({ requires: requires() });
const plain = gatewayCapability({ capabilityId: restart, name: "restart", exposedName: "service-status__restart", requires: null });

describe("Requires badges", () => {
  it("show on a gateway's Capabilities tab and in the picker, with the service-account note", async () => {
    const u = userEvent.setup();
    const base = `/v1/teams/${team.slug}/gateways`;
    mockApi({
      ...shellRoutes("none", "owner"),
      [`GET ${base}/${gatewayId}`]: () => gateway(),
      [`GET ${base}/${gatewayId}/capabilities`]: () => gatewayCapabilities([needsGithub, plain]),
      [`GET /v1/teams/${team.slug}/gateway-options`]: (_b, call) => optionsPage([gatewayOption({ requires: requires() })], call.search),
    });
    const { container } = renderApp(`/teams/${team.slug}/gateways/${gatewayId}?tab=capabilities`);
    const row = await screen.findByRole("listitem", { name: "tool: service-status__get_status" });
    expect(within(row).getByText("Needs GitHub (repo)")).toHaveAttribute("title", "Service accounts need an active team service connection assigned to them and explicitly allowed for this server and its scopes.");
    expect(within(screen.getByRole("listitem", { name: "tool: service-status__restart" })).queryByText(/Needs/)).toBeNull();
    expect(screen.getByText(/Each person connects the accounts marked Needs once/)).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await u.click(screen.getByRole("button", { name: "Edit selection" }));
    const option = (await screen.findByRole("checkbox", { name: "service-status__get_status" })).closest("li")!;
    expect(within(option).getByText("Needs GitHub (repo)")).toBeInTheDocument();
  });

  it("show in the catalog", async () => {
    mockApi({
      ...shellRoutes("none", null),
      [`GET /v1/catalog/servers/${serverId}`]: (): Schemas["CatalogServerDetail"] => ({
        server: catalogServer(),
        capabilities: [{ id: "c1", kind: "tool", name: "create_issue", title: "", description: "Creates an issue.", definition: { name: "create_issue" }, requires: requires() }],
      }),
    });
    renderApp(`/catalog/${serverId}`);
    const item = await screen.findByRole("listitem", { name: "tool: create_issue" });
    expect(within(item).getByText("Needs GitHub (repo)")).toBeInTheDocument();
  });
});

describe("My gateways › accounts", () => {
  const caps = [
    gatewayCapability({ requires: requires({ connected: true }) }),
    gatewayCapability({ capabilityId: restart, name: "create_issue", exposedName: "github-tools__create_issue", requires: requires({ scopes: ["repo", "admin:org"], connected: false }) }),
    gatewayCapability({
      capabilityId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      name: "read_doc",
      exposedName: "drive__read_doc",
      requires: requires({ providerId: googleId, providerSlug: "google", providerName: "Google", scopes: [], connected: true }),
    }),
  ];

  it("say per provider whether the person is connected, and Connect asks for what's needed and comes back here", async () => {
    const u = userEvent.setup();
    const go = vi.spyOn(redirectTo, "go").mockImplementation(() => {});
    const authorizeUrl = "https://github.com/login/oauth/authorize?state=s1";
    const calls = mockApi({
      ...shellRoutes("none", "member"),
      [`GET /v1/me/gateways/${gatewayId}`]: () => ({ gateway: myGateway(), capabilities: caps }),
      "POST /v1/me/connections/start": () => ({ authorizeUrl, scopes: ["repo", "admin:org"], expiresAt: "2026-10-16T08:10:00Z" }),
    });
    const { container } = renderApp(`/gateways/${gatewayId}`);
    const table = await screen.findByRole("table", { name: "Accounts this gateway needs" });
    const github = within(table).getByText("GitHub").closest("tr")!;
    expect(github).toHaveTextContent("2 capabilities");
    expect(github).toHaveTextContent("repo, admin:org");
    expect(github).toHaveTextContent("Not connected");
    const google = within(table).getByText("Google").closest("tr")!;
    expect(google).toHaveTextContent("Connected");
    expect(within(google).queryByRole("button")).toBeNull();
    const issue = screen.getByRole("listitem", { name: "tool: github-tools__create_issue" });
    expect(within(issue).getByText("Needs GitHub (repo, admin:org)")).toBeInTheDocument();
    expect(within(issue).getByText("Not connected")).toBeInTheDocument();
    expect(within(screen.getByRole("listitem", { name: "tool: service-status__get_status" })).getByText("Connected")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();

    await u.click(within(github).getByRole("button", { name: "Connect GitHub" }));
    await waitFor(() => expect(go).toHaveBeenCalledWith(authorizeUrl));
    expect(calls.find((c) => c.url === "/v1/me/connections/start")!.body).toEqual({ providerId, scopes: ["repo", "admin:org"], returnTo: `/gateways/${gatewayId}` });
  });

  it("aren't shown when nothing needs an account", async () => {
    mockApi({ ...shellRoutes("none", "member"), [`GET /v1/me/gateways/${gatewayId}`]: () => ({ gateway: myGateway(), capabilities: [plain] }) });
    renderApp(`/gateways/${gatewayId}`);
    await screen.findByRole("listitem", { name: "tool: service-status__restart" });
    expect(screen.queryByRole("table", { name: "Accounts this gateway needs" })).toBeNull();
  });

  it("group needs by provider", () => {
    const out = neededAccounts(caps);
    expect(out.map((a) => [a.providerName, a.scopes, a.connected, a.uses])).toEqual([
      ["GitHub", ["repo", "admin:org"], false, 2],
      ["Google", [], true, 1],
    ]);
  });
});

describe("Calls that needed a connection", () => {
  const needed = mcpCall({ id: 9, outcome: "needs_authorization", errorClass: "missing_scopes", providerSlug: "github", exposedName: "github-tools__create_issue" });
  const routes: Record<string, Handler> = {
    ...shellRoutes("platform_admin", null),
    "GET /v1/admin/calls": () => page([needed, mcpCall()]),
    "GET /v1/admin/gateways": () => page([gateway()]),
    "GET /v1/admin/teams": () => page([]),
    "GET /v1/admin/service-accounts": () => page([]),
  };

  it("say so, with why and the provider", async () => {
    mockApi(routes);
    const { container } = renderApp("/admin/calls");
    const table = await screen.findByRole("table", { name: /Calls/ });
    const row = (await within(table).findByText("github-tools__create_issue")).closest("tr")!;
    expect(row).toHaveTextContent("Needed a connection");
    expect(row).toHaveTextContent("Account lacks the scopes needed");
    expect(row).toHaveTextContent("Account: github");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("name the provider when it's one people can connect, else its recorded slug", async () => {
    mockApi({ ...routes, "GET /v1/auth-providers": () => providerSummaries });
    renderApp("/admin/calls");
    const table = await screen.findByRole("table", { name: /Calls/ });
    const row = (await within(table).findByText("github-tools__create_issue")).closest("tr")!;
    await waitFor(() => expect(row).toHaveTextContent("Account: GitHub"));
    expect(row).not.toHaveTextContent("Account: github");
  });

  it("name a server-bound provider (an OAuth-protected server's own sign-in) after the call's server", async () => {
    const signIn = mcpCall({
      id: 10,
      providerSlug: "mcp-2924980d301c",
      exposedName: "code-search__search_code",
      server: { id: "3d6d2600-e03c-48a8-8f6d-1b9ac1d13b23", slug: "code-search", name: "Code search", exists: true },
    });
    mockApi({ ...routes, "GET /v1/admin/calls": () => page([signIn]), "GET /v1/auth-providers": () => providerSummaries });
    renderApp("/admin/calls");
    const table = await screen.findByRole("table", { name: /Calls/ });
    const row = (await within(table).findByText("code-search__search_code")).closest("tr")!;
    await waitFor(() => expect(row).toHaveTextContent("Account: Code search"));
    expect(row).not.toHaveTextContent("mcp-2924980d301c");
  });

  it("have words for every Phase 5 outcome and class", () => {
    expect(outcomeLabels.needs_authorization).toBe("Needed a connection");
    expect(callErrorLabel("not_connected")).toBe("Account not connected");
    expect(callErrorLabel("needs_reconsent")).toBe("Account needs reconnecting");
    expect(callErrorLabel("service_account")).toBe("Service accounts can't use it");
    expect(callErrorLabel("provider_disabled")).toBe("Auth provider turned off");
    expect(callErrorLabel("provider_unavailable")).toBe("Auth provider unavailable");
  });
});

describe("Phase 5 audit words", () => {
  it("name the actions, areas and targets", () => {
    expect(actionLabel("auth_provider.create")).toBe("Added auth provider");
    expect(actionLabel("auth_provider.update")).toBe("Changed auth provider");
    expect(actionLabel("auth_provider.delete")).toBe("Deleted auth provider");
    expect(actionLabel("provider_connection.create")).toBe("Connected account");
    expect(actionLabel("provider_connection.refresh_failed")).toBe("Account needs reconnecting");
    expect(actionLabel("provider_connection.revoke", { metadata: { reason: "admin" } })).toBe("Disconnected account by a platform admin");
    expect(actionLabel("provider_connection.revoke", { metadata: { reason: "provider_deleted" } })).toBe("Disconnected account when its provider was deleted");
    expect(actionLabel("mcp_capability.requirement_set")).toBe("Changed capability's account requirement");
    expect(areaOf("auth_provider.update")).toBe("Auth providers");
    expect(areaOf("provider_connection.revoke")).toBe("Connected accounts");
    expect(targetTypeLabel("auth_provider")).toBe("Auth provider");
    expect(targetTypeLabel("provider_connection")).toBe("Connected account");
  });

  it("show a provider's change in words, never a secret", () => {
    const e = { action: "auth_provider.update", before: { enabled: true, extraAuthorizeParams: {} }, after: { enabled: false, extraAuthorizeParams: { access_type: "offline" } } };
    expect(changedRows(auditChange(e))).toEqual([
      { field: "Enabled", before: "On", after: "Off" },
      { field: "Extra authorization parameters", before: [], after: ["access_type=offline"] },
    ]);
  });
});
