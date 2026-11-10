/* The notification bell (count, polling, popover, mark read), the Inbox page and Account › Notifications. */
import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { team } from "./fixtures";
import { notification, notificationPage, preferences } from "./fixtures-v02";
import { type Handler, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const unread = notification({ id: 501 });
const read = notification({ id: 502, title: "Service status recovered", event: "server.recovered", readAt: "2026-10-17T11:45:00Z", link: null });

/** The shell, plus the bell's routes with a count that tests can change. */
function routes(extra: Record<string, Handler> = {}, state = { count: 3 }): Record<string, Handler> {
  return {
    ...shellRoutes("none", "member"),
    "GET /v1/me/notifications/unread-count": () => ({ count: state.count }),
    "GET /v1/me/notifications": () => notificationPage([unread, read], state.count),
    ...extra,
  };
}

describe("notification bell", () => {
  it("shows the unread count in the top bar, named for screen readers", async () => {
    mockApi(routes());
    const { container } = renderApp("/");
    const bell = await screen.findByRole("button", { name: "Notifications, 3 unread" });
    expect(bell).toHaveTextContent("3");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("shows no count at zero and says nothing when the count can't load", async () => {
    mockApi(routes({}, { count: 0 }));
    const { unmount } = renderApp("/");
    expect(await screen.findByRole("button", { name: "Notifications" })).toHaveTextContent("");
    unmount();
    mockApi({ ...routes(), "GET /v1/me/notifications/unread-count": () => new Response("{}", { status: 500 }) });
    renderApp("/");
    expect(await screen.findByRole("button", { name: "Notifications" })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("polls the count every minute and announces only a change, never the first load", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const state = { count: 1 };
      const calls = mockApi(routes({}, state));
      renderApp("/");
      await screen.findByRole("button", { name: "Notifications, 1 unread" });
      const live = () => document.querySelector('[role="status"][aria-live="polite"]');
      expect(live()).toHaveTextContent("");
      const polls = () => calls.filter((c) => c.url === "/v1/me/notifications/unread-count").length;
      const before = polls();
      // Nothing changed: asked again, still nothing announced.
      await act(() => vi.advanceTimersByTimeAsync(60_000));
      await waitFor(() => expect(polls()).toBeGreaterThan(before));
      expect(live()).toHaveTextContent("");
      state.count = 4;
      await act(() => vi.advanceTimersByTimeAsync(60_000));
      expect(await screen.findByRole("button", { name: "Notifications, 4 unread" })).toBeInTheDocument();
      await waitFor(() => expect(live()).toHaveTextContent("4 unread notifications"));
    } finally {
      vi.useRealTimers();
    }
  });

  it("asks again when the window regains focus", async () => {
    const state = { count: 1 };
    const calls = mockApi(routes({}, state));
    renderApp("/");
    await screen.findByRole("button", { name: "Notifications, 1 unread" });
    const polls = () => calls.filter((c) => c.url === "/v1/me/notifications/unread-count").length;
    const before = polls();
    state.count = 2;
    act(() => {
      window.dispatchEvent(new Event("visibilitychange"));
      window.dispatchEvent(new Event("focus"));
    });
    await screen.findByRole("button", { name: "Notifications, 2 unread" });
    expect(polls()).toBeGreaterThan(before);
  });

  it("opens a popover with the latest items, opens one and marks it read, and returns focus to the bell", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes({ "POST /v1/me/notifications/501/read": () => ({ ok: true }) }));
    const { router } = renderApp("/");
    const bell = await screen.findByRole("button", { name: "Notifications, 3 unread" });
    await u.click(bell);
    const popup = await screen.findByRole("dialog", { name: "Notifications" });
    const list = await within(popup).findByRole("list", { name: "Latest notifications" });
    expect(calls.find((c) => c.url === "/v1/me/notifications")?.search.get("limit")).toBe("8");
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
    expect(within(list).getByText("Unread:")).toBeInTheDocument();
    await u.click(within(popup).getByRole("link", { name: /Service status is failing/ }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url === "/v1/me/notifications/501/read")).toBe(true));
    await waitFor(() => expect(router.state.location.pathname).toBe(`/teams/${team.slug}/servers/${unread.link?.id}`));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Notifications" })).toBeNull());

    // Escape closes it from the keyboard and focus goes back to the bell.
    await router.navigate({ to: "/" });
    const again = await screen.findByRole("button", { name: /^Notifications/ });
    await u.click(again);
    await screen.findByRole("dialog", { name: "Notifications" });
    await u.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Notifications" })).toBeNull());
    expect(screen.getByRole("button", { name: /^Notifications/ })).toHaveFocus();
  });

  it("marks one read with its own button and all read with Mark all read", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes({ "POST /v1/me/notifications/501/read": () => ({ ok: true }), "POST /v1/me/notifications/read-all": () => ({ marked: 1 }) }));
    renderApp("/");
    await u.click(await screen.findByRole("button", { name: "Notifications, 3 unread" }));
    const popup = await screen.findByRole("dialog", { name: "Notifications" });
    // Only the unread row has the button.
    expect(within(popup).getAllByRole("button", { name: /Mark “.*” as read/ })).toHaveLength(1);
    await u.click(await within(popup).findByRole("button", { name: "Mark “Service status is failing” as read" }));
    await waitFor(() => expect(calls.some((c) => c.url === "/v1/me/notifications/501/read")).toBe(true));
    await u.click(within(popup).getByRole("button", { name: "Mark all read" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.url === "/v1/me/notifications/read-all")).toBe(true));
    // The bell and the list were asked again.
    await waitFor(() => expect(calls.filter((c) => c.url === "/v1/me/notifications/unread-count").length).toBeGreaterThan(2));
  });

  it("says when everything is read, and links to the inbox and the settings", async () => {
    const u = userEvent.setup();
    mockApi(routes({ "GET /v1/me/notifications": () => notificationPage([], 0) }, { count: 0 }));
    const { router } = renderApp("/");
    await u.click(await screen.findByRole("button", { name: "Notifications" }));
    const popup = await screen.findByRole("dialog", { name: "Notifications" });
    expect(await within(popup).findByText("You're all caught up.")).toBeInTheDocument();
    expect(within(popup).getByRole("button", { name: "Mark all read" })).toBeDisabled();
    await u.click(within(popup).getByRole("link", { name: "View all" }));
    await waitFor(() => expect(router.state.location.pathname).toBe("/notifications"));
  });

  it("explains a failure to load the latest items, with Try again", async () => {
    const u = userEvent.setup();
    mockApi(routes({ "GET /v1/me/notifications": () => new Response(JSON.stringify({ error: { code: "internal", message: "boom" } }), { status: 500 }) }));
    renderApp("/");
    await u.click(await screen.findByRole("button", { name: /^Notifications/ }));
    const popup = await screen.findByRole("dialog", { name: "Notifications" });
    expect(await within(popup).findByText("Couldn't load notifications")).toBeInTheDocument();
    expect(within(popup).getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });
});

describe("Inbox", () => {
  it("lists the notifications, newest first, with cursor paging", async () => {
    const u = userEvent.setup();
    const second = notification({ id: 400, title: "Older one", createdAt: "2026-10-16T09:00:00Z", readAt: "2026-10-16T10:00:00Z" });
    const calls = mockApi(
      routes({
        "GET /v1/me/notifications": (_b, call) => (call.search.get("cursor") === "c2" ? notificationPage([second], 3) : notificationPage([unread, read], 3, "c2")),
      }),
    );
    const { container } = renderApp("/notifications");
    expect(await screen.findByRole("heading", { level: 1, name: "Inbox" })).toBeInTheDocument();
    const list = await screen.findByRole("list", { name: "Notifications" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
    expect(within(list).getByText("Service status is failing")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Load more" }));
    expect(await within(list).findByText("Older one")).toBeInTheDocument();
    expect(calls.filter((c) => c.url === "/v1/me/notifications").map((c) => c.search.get("cursor"))).toContain("c2");
    expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
    await waitFor(() => expect(document.title).toBe("Inbox · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("filters to unread (kept in the address), opens an item and marks it read", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes({ "POST /v1/me/notifications/501/read": () => ({ ok: true }) }));
    const { router } = renderApp("/notifications");
    await screen.findByRole("list", { name: "Notifications" });
    await u.click(screen.getByRole("switch", { name: "Unread only" }));
    await waitFor(() => expect(router.state.location.search).toMatchObject({ unread: true }));
    await screen.findByRole("list", { name: "Unread notifications" });
    expect(calls.filter((c) => c.url === "/v1/me/notifications").some((c) => c.search.get("unread") === "true")).toBe(true);
    await u.click(screen.getByRole("link", { name: /Service status is failing/ }));
    await waitFor(() => expect(calls.some((c) => c.url === "/v1/me/notifications/501/read")).toBe(true));
    await waitFor(() => expect(router.state.location.pathname).toContain("/servers/"));
  });

  it("marks everything read, and shows the empty and error states", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes({ "POST /v1/me/notifications/read-all": () => ({ marked: 3 }) }));
    renderApp("/notifications");
    await u.click(await screen.findByRole("button", { name: "Mark all read (3)" }));
    await waitFor(() => expect(calls.some((c) => c.url === "/v1/me/notifications/read-all")).toBe(true));
  });

  it("has an empty state and an error state with Retry", async () => {
    mockApi(routes({ "GET /v1/me/notifications": () => notificationPage([], 0) }, { count: 0 }));
    const first = renderApp("/notifications");
    expect(await screen.findByText("No notifications yet.")).toBeInTheDocument();
    first.unmount();
    mockApi(routes({ "GET /v1/me/notifications": () => new Response(JSON.stringify({ error: { code: "internal", message: "boom" } }), { status: 500 }) }));
    renderApp("/notifications");
    expect(await screen.findByText("Couldn't load your notifications")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });
});

describe("Account › Notifications", () => {
  const prefRoutes = (email = true, extra: Record<string, Handler> = {}) => routes({ "GET /v1/me/notification-preferences": () => preferences({ emailAvailable: email }), ...extra });

  it("lists the events the person can receive with who gets each, and the address email goes to", async () => {
    mockApi(prefRoutes());
    const { container } = renderApp("/settings/notifications");
    expect(await screen.findByRole("heading", { level: 1, name: "Notifications" })).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Notification preferences" });
    const row = within(table).getByText("A server is failing").closest("tr")!;
    expect(row).toHaveTextContent("Team owners, admins and editors");
    // The events the API didn't list (publish.requested: platform admins) aren't shown.
    expect(within(table).queryByText("A server is waiting for review")).toBeNull();
    expect(screen.getByText("una@example.com", { selector: "strong" })).toBeInTheDocument();
    expect(within(row).getByRole("switch", { name: "A server is failing in the portal" })).toBeChecked();
    expect(within(row).getByRole("switch", { name: "A server is failing by email" })).toBeChecked();
    const changed = within(table).getByText("A published server's capabilities changed").closest("tr")!;
    expect(within(changed).getByRole("switch", { name: /by email/ })).not.toBeChecked();
    expect(await axe(container)).toHaveNoViolations();
  });

  it("saves each switch at once, one event and channel per request", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      prefRoutes(true, {
        "PUT /v1/me/notification-preferences": (body) => {
          const change = (body as Schemas["NotificationPreferencesUpdate"]).items[0]!;
          return preferences({ items: preferences().items.map((i) => (i.event === change.event ? { ...i, ...change, custom: true } : i)) });
        },
      }),
    );
    renderApp("/settings/notifications");
    const toggle = await screen.findByRole("switch", { name: "A server recovered in the portal" });
    await u.click(toggle);
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ items: [{ event: "server.recovered", inApp: false }] }));
    await waitFor(() => expect(screen.getByRole("switch", { name: "A server recovered in the portal" })).not.toBeChecked());
    await u.click(screen.getByRole("switch", { name: "A server recovered by email" }));
    await waitFor(() => expect(calls.filter((c) => c.method === "PUT").at(-1)?.body).toEqual({ items: [{ event: "server.recovered", email: false }] }));
  });

  it("turns the Email switches off, with the reason, when the operator hasn't set up email", async () => {
    mockApi(prefRoutes(false));
    renderApp("/settings/notifications");
    expect(await screen.findByText("Email isn't set up on this portal")).toBeInTheDocument();
    for (const sw of await screen.findAllByRole("switch", { name: /by email/ })) expect(sw).toHaveAttribute("aria-disabled", "true");
    for (const sw of screen.getAllByRole("switch", { name: /in the portal/ })) expect(sw).not.toHaveAttribute("aria-disabled", "true");
  });

  it("shows a refused save and the old state again", async () => {
    const u = userEvent.setup();
    mockApi(
      prefRoutes(true, {
        "PUT /v1/me/notification-preferences": () => new Response(JSON.stringify({ error: { code: "not_receivable", message: "no" } }), { status: 422 }),
      }),
    );
    renderApp("/settings/notifications");
    await u.click(await screen.findByRole("switch", { name: "A server recovered in the portal" }));
    expect(await screen.findByText("Couldn't save that choice")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("switch", { name: "A server recovered in the portal" })).toBeChecked());
  });

  it("is in the account menu and the command palette", async () => {
    const u = userEvent.setup();
    mockApi(prefRoutes());
    renderApp("/");
    await u.click(await screen.findByRole("button", { name: /Una User/ }));
    expect((await screen.findAllByRole("menuitem")).map((i) => i.textContent)).toContain("Notifications");
    await u.keyboard("{Escape}");
    await u.click(screen.getByRole("button", { name: /Search or jump to/ }));
    await u.type(await screen.findByRole("combobox"), "unread");
    expect(await screen.findByRole("option", { name: /Inbox/ })).toBeInTheDocument();
  });
});
