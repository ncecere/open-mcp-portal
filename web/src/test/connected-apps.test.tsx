/* Connected apps: the person's own (Account) and anyone's on Admin › Users › person, with Disconnect after confirming; auditors read. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { oauthClient, oauthGrant, registeredClient, team, user } from "./fixtures";
import { type Handler, mockApi, renderApp, shellRoutes } from "./harness";

const grants = [
  oauthGrant(),
  oauthGrant({ id: "g2", client: registeredClient(), gateway: { id: "old", slug: "old", name: "Old gateway", exists: false }, lastUsedAt: null }),
];

describe("Account › Connected apps", () => {
  it("lists the person's apps per gateway with host, verification, connected and last used", async () => {
    mockApi({ ...shellRoutes("none", "member"), "GET /v1/me/oauth-grants": () => grants });
    const { container } = renderApp("/settings/connected-apps");
    expect(await screen.findByRole("heading", { level: 1, name: "Connected apps" })).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Your connected apps" });
    const verified = (await within(table).findByText("Claude Code")).closest("tr")!;
    expect(verified).toHaveTextContent("claude.ai");
    expect(within(verified).queryByText("Unverified")).toBeNull();
    expect(within(verified).getByRole("link", { name: "Support tools" })).toHaveAttribute("href", "/gateways/77777777-7777-4777-8777-777777777777");
    const unverified = within(table).getByText("Handy MCP Helper").closest("tr")!;
    expect(within(unverified).getByText("Unverified")).toBeInTheDocument();
    expect(unverified).toHaveTextContent("It registered itself");
    expect(unverified).toHaveTextContent("Old gateway");
    expect(unverified).toHaveTextContent("Deleted");
    expect(unverified).toHaveTextContent("Not used yet");
    await waitFor(() => expect(document.title).toBe("Connected apps · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("says when each app's sign-in expires, and that it already has", async () => {
    const old = oauthGrant({ id: "g3", client: registeredClient(), expiresAt: "2020-01-01T00:00:00Z" });
    mockApi({ ...shellRoutes("none", "member"), "GET /v1/me/oauth-grants": () => [oauthGrant({ expiresAt: "2099-04-08T10:00:00Z" }), oauthGrant({ id: "g2", client: oauthClient({ id: "https://cursor.com/oauth/client.json", name: "Cursor", host: "cursor.com" }), expiresAt: null }), old] });
    renderApp("/settings/connected-apps");
    const table = await screen.findByRole("table", { name: "Your connected apps" });
    expect(within(table).getByRole("columnheader", { name: /Sign-in expires/ })).toBeInTheDocument();
    const limited = (await within(table).findByText("Claude Code")).closest("tr")!;
    expect(limited.querySelector("time[datetime='2099-04-08T10:00:00Z']")).not.toBeNull();
    expect(within(limited).queryByText("Expired")).toBeNull();
    expect(within(table).getByText("No limit")).toBeInTheDocument();
    // Only the one past its date says so.
    expect(within(table).getAllByText("Expired")).toHaveLength(1);
    expect(within(within(table).getByText("Handy MCP Helper").closest("tr")!).getByText("Expired")).toBeInTheDocument();
  });

  it("disconnects an app only after confirming", async () => {
    const u = userEvent.setup();
    const calls = mockApi({ ...shellRoutes("none", "member"), "GET /v1/me/oauth-grants": () => grants, [`DELETE /v1/me/oauth-grants/${grants[0]!.id}`]: () => ({ ok: true }) });
    renderApp("/settings/connected-apps");
    await u.click(await screen.findByRole("button", { name: "Actions for Claude Code on Support tools" }));
    await u.click(await screen.findByRole("menuitem", { name: "Disconnect…" }));
    const ask = await screen.findByRole("alertdialog", { name: "Disconnect Claude Code?" });
    expect(ask).toHaveTextContent("It loses access to Support tools at once");
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    await u.click(within(ask).getByRole("button", { name: "Disconnect" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url === `/v1/me/oauth-grants/${grants[0]!.id}`)).toBe(true));
    expect(await screen.findByText("Claude Code was disconnected from Support tools")).toBeInTheDocument();
  });

  it("says what shows up here when there's nothing yet", async () => {
    mockApi({ ...shellRoutes("none", null), "GET /v1/me/oauth-grants": () => [] });
    renderApp("/settings/connected-apps");
    expect(await screen.findByText("No connected apps.")).toBeInTheDocument();
  });

  it("is in the account menu after API keys, and in the command palette", async () => {
    const u = userEvent.setup();
    mockApi({ ...shellRoutes("none", "member"), "GET /v1/me/oauth-grants": () => [] });
    renderApp("/");
    await u.click(await screen.findByRole("button", { name: /Una User/ }));
    const items = (await screen.findAllByRole("menuitem")).map((i) => i.textContent);
    expect(items.indexOf("Connected apps")).toBe(items.indexOf("API keys") + 1);
    await u.keyboard("{Escape}");
    await u.click(screen.getByRole("button", { name: /Search or jump to/ }));
    await u.type(await screen.findByRole("combobox"), "disconnect");
    expect(await screen.findByRole("option", { name: /Connected apps/ })).toBeInTheDocument();
  });
});

describe("Admin › Users › person › Connected apps", () => {
  const person = user({ id: "99999999-0000-4000-8000-000000000001", email: "drew@example.com", displayName: "Drew Member" });
  const routes = (role: Schemas["PlatformRole"], extra: Record<string, Handler> = {}): Record<string, Handler> => ({
    ...shellRoutes(role, null),
    [`GET /v1/admin/users/${person.id}`]: (): Schemas["UserDetail"] => ({ user: person, teams: [{ id: team.id, slug: team.slug, name: team.name, status: "active", role: "member" }] }),
    [`GET /v1/admin/users/${person.id}/oauth-grants`]: () => grants,
    "GET /v1/admin/audit": () => ({ items: [], nextCursor: null }),
    ...extra,
  });

  it("lets platform admins disconnect a person's app after confirming", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes("platform_admin", { [`DELETE /v1/admin/users/${person.id}/oauth-grants/${grants[0]!.id}`]: () => ({ ok: true }) }));
    const { container } = renderApp(`/admin/users/${person.id}`);
    const table = await screen.findByRole("table", { name: "Apps Drew Member connected" });
    expect(await within(table).findByRole("link", { name: "Support tools" })).toHaveAttribute("href", "/admin/gateways/77777777-7777-4777-8777-777777777777");
    expect(await axe(container)).toHaveNoViolations();
    await u.click(within(table).getByRole("button", { name: "Actions for Claude Code on Support tools" }));
    await u.click(await screen.findByRole("menuitem", { name: "Disconnect…" }));
    const ask = await screen.findByRole("alertdialog", { name: "Disconnect Claude Code?" });
    expect(ask).toHaveTextContent("Drew Member can connect it again");
    await u.click(within(ask).getByRole("button", { name: "Disconnect" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE" && c.url === `/v1/admin/users/${person.id}/oauth-grants/${grants[0]!.id}`)).toBe(true));
  });

  it("is read-only for auditors", async () => {
    mockApi(routes("platform_auditor"));
    renderApp(`/admin/users/${person.id}`);
    const table = await screen.findByRole("table", { name: "Apps Drew Member connected" });
    expect(await within(table).findByText("Claude Code")).toBeInTheDocument();
    expect(within(table).queryByRole("button", { name: /Actions for/ })).toBeNull();
  });
});
