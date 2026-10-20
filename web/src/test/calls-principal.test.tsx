/* Who made a call, by kind (a person's API key, a person via a connected app, a team's service account), the Service account filter, and the Phase 4 audit words. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import { auditChange, changedRows } from "../components/audit/changes";
import { actionLabel, areaOf, areaOptions, targetTypeLabel } from "../components/audit/labels";
import { principalDetail, principalName } from "../components/gateways/calls-table";
import { gateway, gatewayCapabilities, gatewayId, mcpCall, myGateway, page, serviceAccount, serviceAccountId, team, user } from "./fixtures";
import { type Handler, mockApi, renderApp, shellRoutes } from "./harness";

const viaApp = mcpCall({
  id: 2,
  exposedName: "service-status__restart",
  principal: { kind: "oauth", userId: user().id, displayName: "Una User", email: "una@example.com", oauthClientName: "Claude Code" },
});
const bySa = mcpCall({
  id: 3,
  exposedName: "service-status__incident_summary",
  principal: {
    kind: "service_account",
    displayName: "ci-release-bot",
    apiKeyName: "GitHub Actions",
    serviceAccountId,
    serviceAccountTeamSlug: team.slug,
    serviceAccountExists: true,
  },
});
const viaSelfRegistered = mcpCall({
  id: 4,
  exposedName: "service-status__list_incidents",
  principal: { kind: "oauth", userId: user().id, displayName: "Una User", email: "una@example.com", oauthClientName: "Helper", oauthClientVerified: false },
});
const byDeletedSa = mcpCall({
  id: 5,
  exposedName: "service-status__close_incident",
  principal: {
    kind: "service_account",
    displayName: "old-bot",
    apiKeyName: "Nightly",
    serviceAccountId: "17171717-1717-4171-8171-171717171717",
    serviceAccountTeamSlug: team.slug,
    serviceAccountExists: false,
  },
});
const calls = [mcpCall(), viaApp, bySa, viaSelfRegistered, byDeletedSa];

const adminRoutes = (extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("platform_admin", null),
  "GET /v1/admin/calls": () => page(calls),
  "GET /v1/admin/gateways": () => page([gateway()]),
  "GET /v1/admin/mcp-servers": () => page([]),
  "GET /v1/admin/users": () => page([user()]),
  "GET /v1/admin/teams": () => page([{ team, memberCount: 4, ownerCount: 1, ownerInvites: 0 }]),
  "GET /v1/admin/service-accounts": (_, call) =>
    page(call.search.get("team") === "other" ? [] : [serviceAccount(), serviceAccount({ id: "18181818-1818-4181-8181-181818181818", name: "deploy-bot", teamSlug: "data-team" })]),
  ...extra,
});

describe("calls by principal", () => {
  it("shows a person's key, a person via a connected app, and a service account with its team and key, linked", async () => {
    mockApi(adminRoutes());
    const { container } = renderApp("/admin/calls");
    const table = await screen.findByRole("table", { name: "Calls" });
    const row = async (name: string) => (await within(table).findByText(name)).closest("tr")!;
    expect(await row("service-status__get_status")).toHaveTextContent("Una User API key: Claude Code on my laptop");
    expect(await row("service-status__restart")).toHaveTextContent("Una User via Claude Code");
    expect(await row("service-status__restart")).not.toHaveTextContent("unverified");
    const sa = await row("service-status__incident_summary");
    expect(sa).toHaveTextContent(`Service account · ${team.slug} · Key: GitHub Actions`);
    expect(within(sa).getByRole("link", { name: "ci-release-bot" })).toHaveAttribute("href", `/teams/${team.slug}/service-accounts/${serviceAccountId}`);
    expect(await axe(container)).toHaveNoViolations();
  });

  it("marks an app that registered itself as unverified, and a deleted service account as plain text", async () => {
    mockApi(adminRoutes());
    renderApp("/admin/calls");
    const table = await screen.findByRole("table", { name: "Calls" });
    const row = async (name: string) => (await within(table).findByText(name)).closest("tr")!;
    expect(await row("service-status__list_incidents")).toHaveTextContent("Una User via Helper (unverified)");
    const gone = await row("service-status__close_incident");
    expect(gone).toHaveTextContent(`old-bot`);
    expect(gone).toHaveTextContent(`Deleted service account · ${team.slug} · Key: Nightly`);
    expect(within(gone).queryByRole("link", { name: "old-bot" })).toBeNull();
  });

  it("filters Admin › Calls by any team's service account, searchable, without choosing a team first", async () => {
    const u = userEvent.setup();
    const made = mockApi(adminRoutes());
    renderApp("/admin/calls");
    await screen.findByRole("table", { name: "Calls" });
    await waitFor(() => expect(made.some((c) => c.url === "/v1/admin/service-accounts" && !c.search.has("team"))).toBe(true));
    await u.click(screen.getByRole("combobox", { name: "Service account" }));
    await u.type(screen.getByRole("combobox", { name: "Service account" }), "deploy");
    await u.click(await screen.findByRole("option", { name: /deploy-bot \(data-team\)/ }));
    await waitFor(() => expect(made.some((c) => c.url === "/v1/admin/calls" && c.search.get("serviceAccount") === "18181818-1818-4181-8181-181818181818")).toBe(true));
    expect(screen.queryByText("Choose a team first")).toBeNull();
  });

  it("filters Admin › Calls by a service account of the chosen team", async () => {
    const made = mockApi(adminRoutes());
    renderApp(`/admin/calls?team=${team.slug}&serviceAccount=${serviceAccountId}`);
    await screen.findByRole("table", { name: "Calls" });
    await waitFor(() => expect(made.some((c) => c.url === "/v1/admin/calls" && c.search.get("serviceAccount") === serviceAccountId && c.search.get("team") === team.slug)).toBe(true));
    // The options are the chosen team's service accounts.
    await waitFor(() => expect(made.some((c) => c.url === "/v1/admin/service-accounts" && c.search.get("team") === team.slug)).toBe(true));
  });

  it("filters a team gateway's Activity by the team's service account", async () => {
    const base = `/v1/teams/${team.slug}/gateways`;
    const made = mockApi({
      ...shellRoutes("none", "owner"),
      [`GET ${base}/${gatewayId}`]: () => gateway(),
      [`GET ${base}/${gatewayId}/capabilities`]: () => gatewayCapabilities(),
      [`GET /v1/teams/${team.slug}/calls`]: () => page([bySa]),
      [`GET /v1/teams/${team.slug}/service-accounts`]: () => [serviceAccount()],
      "GET /v1/me/gateways": () => [myGateway()],
    });
    renderApp(`/teams/${team.slug}/gateways/${gatewayId}?tab=activity&serviceAccount=${serviceAccountId}`);
    const table = await screen.findByRole("table", { name: "Calls" });
    expect(await within(table).findByRole("link", { name: "ci-release-bot" })).toBeInTheDocument();
    await waitFor(() => expect(made.some((c) => c.url.endsWith("/calls") && c.search.get("serviceAccount") === serviceAccountId && c.search.get("gateway") === gatewayId)).toBe(true));
  });

  it("names every kind in words", () => {
    expect(principalName(bySa.principal)).toBe("ci-release-bot");
    expect(principalDetail(viaApp.principal)).toBe("via Claude Code");
    expect(principalDetail(viaSelfRegistered.principal)).toBe("via Helper (unverified)");
    expect(principalDetail({ kind: "oauth", displayName: "Una", oauthClientName: "Claude", oauthClientVerified: true })).toBe("via Claude");
    expect(principalDetail({ kind: "oauth", displayName: "Una" })).toBe("via a connected app");
    expect(principalDetail({ kind: "service_account", displayName: "bot" })).toBe("Service account");
    expect(principalDetail(bySa.principal)).toBe(`Service account · ${team.slug} · Key: GitHub Actions`);
    expect(principalDetail(byDeletedSa.principal)).toBe(`Deleted service account · ${team.slug} · Key: Nightly`);
    expect(principalName({ kind: "api_key", displayName: "", email: "una@example.com" })).toBe("una@example.com");
  });
});

describe("Phase 4 audit words", () => {
  it("names the OAuth, trusted-client and service account actions and their areas", () => {
    expect(actionLabel("oauth.consent")).toBe("Allowed connected app");
    expect(actionLabel("oauth.client_register")).toBe("Registered OAuth client");
    expect(actionLabel("oauth.token_issue")).toBe("Issued tokens to an app");
    expect(actionLabel("oauth.revoke")).toBe("Disconnected app");
    expect(actionLabel("oauth.revoke", { metadata: { reason: "refresh_reuse" } })).toBe("Disconnected app after a refresh token was reused");
    expect(actionLabel("oauth.revoke", { metadata: { reason: "admin" } })).toBe("Disconnected app by a platform admin");
    expect(actionLabel("oauth.revoke", { metadata: { reason: "expired_absolute" } })).toBe("Disconnected app after its sign-in expired");
    expect(actionLabel("oauth.revoke", { metadata: { reason: "something_new" } })).toBe("Disconnected app");
    expect(actionLabel("oauth.grant_confirmed")).toBe("Confirmed connected app");
    expect(areaOf("oauth.grant_confirmed")).toBe("Connected apps");
    expect(actionLabel("settings.oauth_clients_update")).toBe("Changed trusted clients");
    expect(actionLabel("service_account.create")).toBe("Created service account");
    expect(actionLabel("service_account_key.revoke")).toBe("Revoked service account key");
    expect(areaOf("oauth.consent")).toBe("Connected apps");
    expect(areaOf("settings.oauth_clients_update")).toBe("Platform settings");
    expect(areaOf("service_account.update")).toBe("Service accounts");
    expect(areaOf("service_account_key.create")).toBe("Service account keys");
    expect(targetTypeLabel("service_account")).toBe("Service account");
    expect(targetTypeLabel("service_account_key")).toBe("Service account key");
    // The team's log offers the service account areas, not the platform-only connected apps.
    const teamAreas = areaOptions(false).map((o) => o.value);
    expect(teamAreas).toContain("service_account.");
    expect(teamAreas).not.toContain("oauth.");
    expect(areaOptions(true).map((o) => o.value)).toContain("oauth.");
  });

  it("shows trusted clients and a service account's role and switch in words", () => {
    const clients = { action: "settings.oauth_clients_update", before: { clients: [] }, after: { clients: [{ clientId: "https://vscode.dev/oauth/client-metadata.json", label: "VS Code" }] } };
    expect(changedRows(auditChange(clients))).toEqual([{ field: "Trusted clients", before: [], after: ["VS Code (https://vscode.dev/oauth/client-metadata.json)"] }]);
    const registration = { action: "settings.oauth_clients_update", before: { clients: [], openRegistration: true }, after: { clients: [], openRegistration: false } };
    expect(changedRows(auditChange(registration))).toEqual([{ field: "Open client registration", before: "On", after: "Off" }]);
    const sa = { action: "service_account.update", before: { role: "member", enabled: true }, after: { role: "editor", enabled: false } };
    expect(changedRows(auditChange(sa))).toEqual([
      { field: "Role", before: "Member", after: "Editor" },
      { field: "Enabled", before: "On", after: "Off" },
    ]);
  });
});
