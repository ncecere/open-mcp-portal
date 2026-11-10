/* Admin › Notifications: email status and test email, the delivery loop, platform destinations, roles. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { destination, notificationSettings } from "./fixtures-v02";
import { type Handler, Reply, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const platformDestination = (extra: Partial<Schemas["NotificationDestination"]> = {}) =>
  destination({ id: "plat-1", scope: "platform", team: null, name: "Platform pager", events: ["publish.requested"], ...extra });

const routes = (extra: Record<string, Handler> = {}, role: Schemas["PlatformRole"] = "platform_admin"): Record<string, Handler> => ({
  ...shellRoutes(role, null),
  "GET /v1/admin/settings/notifications": () => notificationSettings(),
  "GET /v1/admin/notification-destinations": () => [platformDestination()],
  ...extra,
});

describe("Admin › Notifications", () => {
  it("shows the email status without credentials, the delivery loop and the platform destinations", async () => {
    mockApi(routes());
    const { container } = renderApp("/admin/notifications");
    expect(await screen.findByRole("heading", { level: 1, name: "Notifications" })).toBeInTheDocument();
    const email = (await screen.findByRole("heading", { name: "Email" })).closest("section")!;
    expect(within(email).getByText("Email is set up")).toBeInTheDocument();
    expect(email).toHaveTextContent("Open MCP Portal <portal@example.org>");
    expect(email).toHaveTextContent("smtp.example.org:587");
    expect(email).toHaveTextContent("STARTTLS (required)");
    expect(email).toHaveTextContent("12 sent, 0 failed");
    expect(email).toHaveTextContent("Yes (user name and password are set in the deployment)");
    const delivery = screen.getByRole("heading", { name: "Delivery" }).closest("section")!;
    expect(delivery).toHaveTextContent("Dispatcher last ran");
    expect(screen.getByText("Platform pager")).toBeInTheDocument();
    await waitFor(() => expect(document.title).toBe("Notifications · Admin · Open MCP Portal"));
    expect(await axe(container)).toHaveNoViolations();
  });

  it("says email isn't set up, with what to do, and disables the test", async () => {
    mockApi(routes({ "GET /v1/admin/settings/notifications": () => notificationSettings({ email: { configured: false, authenticated: false, sentLast24h: 0, failedLast24h: 0 } }) }));
    renderApp("/admin/notifications");
    expect(await screen.findByText("Email isn't set up")).toBeInTheDocument();
    expect(screen.getByText(/SMTP_HOST/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Send test email" })).toBeDisabled();
  });

  it("sends a test email to the admin's own address and shows the result, or why it failed", async () => {
    const u = userEvent.setup();
    let answer: unknown = { ok: true, durationMs: 220, message: "The mail server accepted it." };
    const calls = mockApi(routes({ "POST /v1/admin/settings/notifications/test-email": () => (answer instanceof Reply ? answer : answer) }));
    renderApp("/admin/notifications");
    await u.click(await screen.findByRole("button", { name: "Send test email" }));
    const dialog = await screen.findByRole("dialog", { name: "Send a test email" });
    // No address is typed: it always goes to the caller's own.
    expect(within(dialog).queryByRole("textbox")).toBeNull();
    await u.click(within(dialog).getByRole("button", { name: "Send test email" }));
    expect(await within(dialog).findByText("The mail server accepted the test email")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST")?.body).toBeUndefined();
    answer = { ok: false, errorClass: "auth", durationMs: 90, message: "Login refused." };
    await u.click(within(dialog).getByRole("button", { name: "Send again" }));
    expect(await within(dialog).findByText("The test email failed")).toBeInTheDocument();
    expect(within(dialog).getByText(/Sign-in to the mail server was refused/)).toBeInTheDocument();
    answer = Reply.error(429, "rate_limited", "5 tests an hour");
    await u.click(within(dialog).getByRole("button", { name: "Send again" }));
    expect(await within(dialog).findByText("Too many requests")).toBeInTheDocument();
  });

  it("explains a 409 email_not_configured in words", async () => {
    const u = userEvent.setup();
    mockApi(routes({ "POST /v1/admin/settings/notifications/test-email": () => Reply.error(409, "email_not_configured", "SMTP_HOST is unset") }));
    renderApp("/admin/notifications");
    await u.click(await screen.findByRole("button", { name: "Send test email" }));
    const dialog = await screen.findByRole("dialog", { name: "Send a test email" });
    await u.click(within(dialog).getByRole("button", { name: "Send test email" }));
    expect(await within(dialog).findByText("Email isn't set up")).toBeInTheDocument();
  });

  it("flags a stalled delivery loop, failed email and stopped destinations", async () => {
    const old = new Date(Date.now() - 3_600_000).toISOString();
    mockApi(
      routes({
        "GET /v1/admin/settings/notifications": () =>
          notificationSettings({
            email: { ...notificationSettings().email, failedLast24h: 4 },
            webhooks: { teamDestinations: 2, platformDestinations: 1, stopped: 2 },
            queue: { pending: 31, failedLast24h: 5, oldestPendingAt: old, lastRunAt: old, intervalSeconds: 15 },
          }),
      }),
    );
    renderApp("/admin/notifications");
    expect(await screen.findByText("The delivery loop hasn't run for a while")).toBeInTheDocument();
    expect(screen.getByText("2 destinations were stopped after repeated failures")).toBeInTheDocument();
    expect(screen.getByText("4 emails failed in the last 24 hours")).toBeInTheDocument();
    expect(screen.getByText("31")).toBeInTheDocument();
  });

  it("lets platform admins add a destination: the team events switch widens the choice of events", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes({ "POST /v1/admin/notification-destinations": () => new Reply(201, { data: { destination: platformDestination({ name: "All teams" }), secret: null } }) }));
    renderApp("/admin/notifications");
    await u.click(await screen.findByRole("button", { name: "Add destination" }));
    const dialog = await screen.findByRole("dialog", { name: "Add a webhook destination" });
    expect(within(dialog).getByRole("checkbox", { name: /waiting for review/ })).toBeChecked();
    expect(within(dialog).queryByRole("checkbox", { name: /A server is failing/ })).toBeNull();
    await u.click(within(dialog).getByRole("switch", { name: /Also receive every team's events/ }));
    expect(await within(dialog).findByRole("checkbox", { name: /A server is failing/ })).toBeInTheDocument();
    // The events of every team are never personal ones.
    expect(within(dialog).queryByRole("checkbox", { name: /connected account/ })).toBeNull();
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "All teams");
    await u.click(within(dialog).getByRole("radio", { name: /Slack/ }));
    await u.type(within(dialog).getByRole("textbox", { name: /URL/ }), "https://hooks.slack.com/services/x");
    await u.click(within(dialog).getByRole("button", { name: "Add destination" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toMatchObject({ name: "All teams", format: "slack", teamEvents: true, events: ["publish.requested"] }));
  });

  it("is read-only for auditors: status and list, no test email, no changes", async () => {
    const u = userEvent.setup();
    mockApi(routes({}, "platform_auditor"));
    renderApp("/admin/notifications");
    expect(await screen.findByText("Email is set up")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Send test email" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Add destination" })).toBeNull();
    expect(screen.queryByRole("switch", { name: "On-call webhook enabled" })).toBeNull();
    expect(screen.getAllByText(/Only platform admins can change them/).length).toBeGreaterThan(0);
    await u.click(await screen.findByRole("button", { name: "Actions for On-call webhook" }).catch(() => screen.findByRole("button", { name: "Actions for Platform pager" })));
    expect((await screen.findAllByRole("menuitem")).map((m) => m.textContent)).toEqual(["Delivery log"]);
  });

  it("shows an error with Retry when the status can't load", async () => {
    mockApi(routes({ "GET /v1/admin/settings/notifications": () => Reply.error(500, "internal", "boom") }));
    renderApp("/admin/notifications");
    expect(await screen.findByText("Couldn't load the notification status")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
    // The platform destinations still show.
    expect(await screen.findByText("Platform pager")).toBeInTheDocument();
  });

  it("is refused for people without a platform role", async () => {
    mockApi(shellRoutes("none", "member"));
    renderApp("/admin/notifications");
    expect(await screen.findByRole("heading", { level: 1, name: "No access" })).toBeInTheDocument();
  });
});
