/* v0.2's pages in the palette and breadcrumbs, and the account's API keys pointing at automation tokens. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { destination, automationToken } from "./fixtures-v02";
import { apiKey, myGateway, team } from "./fixtures";
import { mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

async function palette(u: ReturnType<typeof userEvent.setup>, query: string) {
  await u.click(await screen.findByRole("button", { name: /Search or jump to/ }));
  await u.type(await screen.findByRole("combobox"), query);
}

describe("command palette", () => {
  it("finds the inbox and account notifications for everyone", async () => {
    const u = userEvent.setup();
    mockApi(shellRoutes("none", "member"));
    const { router } = renderApp("/");
    await palette(u, "inbox");
    await u.click(await screen.findByRole("option", { name: /Inbox/ }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/notifications"));
    await palette(u, "preferences");
    await u.click(await screen.findByRole("option", { name: /Notifications/ }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/settings/notifications"));
  });

  it("finds the team's Notifications and Automation tokens tabs", async () => {
    const u = userEvent.setup();
    mockApi({ ...shellRoutes("none", "owner"), [`GET /v1/teams/${team.slug}/notification-destinations`]: () => [destination()], [`GET /v1/teams/${team.slug}/automation-tokens`]: () => [automationToken()] });
    const { router } = renderApp(`/teams/${team.slug}`);
    await screen.findByRole("heading", { level: 1, name: team.name });
    await palette(u, "webhook");
    await u.click(await screen.findByRole("option", { name: /Notifications/ }));
    await waitFor(() => expect(router.state.location.search).toMatchObject({ tab: "notifications" }));
    await palette(u, "omppub");
    await u.click(await screen.findByRole("option", { name: /Automation tokens/ }));
    await waitFor(() => expect(router.state.location.search).toMatchObject({ tab: "automation-tokens" }));
  });

  it("gives admins Overview, Automation tokens and Notifications", async () => {
    const u = userEvent.setup();
    mockApi(shellRoutes("platform_admin", null));
    const { router } = renderApp("/admin/users");
    await palette(u, "attention");
    await u.click(await screen.findByRole("option", { name: /Overview/ }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/admin"));
    await palette(u, "ompadm");
    expect(await screen.findByRole("option", { name: /Automation tokens/ })).toBeInTheDocument();
  });
});

describe("breadcrumbs and titles", () => {
  it("name the inbox, the account's notifications, the admin overview and the team settings tabs", async () => {
    mockApi({ ...shellRoutes("platform_admin", "owner"), [`GET /v1/teams/${team.slug}/notification-destinations`]: () => [destination()], [`GET /v1/teams/${team.slug}/automation-tokens`]: () => [] });
    const { router } = renderApp("/notifications");
    await waitFor(() => expect(document.title).toBe("Inbox · Open MCP Portal"));
    await router.navigate({ to: "/settings/notifications" });
    await waitFor(() => expect(document.title).toBe("Notifications · Open MCP Portal"));
    await router.navigate({ to: "/admin" });
    await waitFor(() => expect(document.title).toBe("Overview · Admin · Open MCP Portal"));
    await router.navigate({ to: "/teams/$team/settings", params: { team: team.slug }, search: { tab: "notifications" } });
    await waitFor(() => expect(document.title).toBe("Notifications · Team settings · Open MCP Portal"));
    const crumbs = screen.getByRole("navigation", { name: /breadcrumb/i });
    expect(within(crumbs).getByText("Notifications")).toBeInTheDocument();
  });
});

describe("API keys", () => {
  it("says automation tokens are made by team admins", async () => {
    mockApi({ ...shellRoutes("none", "member"), "GET /v1/me/api-keys": () => [apiKey()], "GET /v1/me/gateways": () => [myGateway()] });
    renderApp("/settings/api-keys");
    expect(await screen.findByText("Automation (CI) tokens are made by team admins under Team settings.")).toBeInTheDocument();
  });
});
