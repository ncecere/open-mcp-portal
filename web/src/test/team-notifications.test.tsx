/* Team settings › Notifications: webhook destinations (roles, create, the secret once, rotate, test, toggle, delete, delivery log). */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { team } from "./fixtures";
import { delivery, destination } from "./fixtures-v02";
import { type Handler, Reply, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const base = `/v1/teams/${team.slug}/notification-destinations`;
const secret = "ompwhs_" + "k".repeat(43);

const routes = (extra: Record<string, Handler> = {}, role: Schemas["TeamRole"] | null = "owner", platform: Schemas["PlatformRole"] = "none"): Record<string, Handler> => ({
  ...shellRoutes(platform, role),
  [`GET ${base}`]: () => [destination()],
  ...extra,
});

const open = () => renderApp(`/teams/${team.slug}/settings?tab=notifications`);

async function rowMenu(u: ReturnType<typeof userEvent.setup>, name: string, item: string) {
  await u.click(await screen.findByRole("button", { name: `Actions for ${name}` }));
  await u.click(await screen.findByRole("menuitem", { name: item }));
}

describe("Team settings › Notifications", () => {
  it("lists the destinations for owners and admins with health and host only, and no URL or secret anywhere", async () => {
    const failing = { state: "failing", consecutiveFailures: 3, lastErrorClass: "connect", lastFailureAt: "2026-10-17T11:00:00Z", lastSuccessAt: null } as const;
    const slack = destination({ id: "d2", name: "Chat", format: "slack", urlDisplay: "https://hooks.slack.com/...", hasSecret: false, secretHint: "", health: failing });
    mockApi(routes({ [`GET ${base}`]: () => [destination(), slack] }));
    const { container } = open();
    const table = await screen.findByRole("table", { name: "Webhook destinations" });
    const row = (await within(table).findByText("On-call webhook")).closest("tr")!;
    expect(row).toHaveTextContent("https://hooks.example.com/...");
    expect(row).toHaveTextContent("Healthy");
    expect(row).toHaveTextContent("2 events");
    const chat = within(table).getByText("Chat").closest("tr")!;
    expect(chat).toHaveTextContent("Slack");
    expect(chat).toHaveTextContent("Failing");
    expect(chat).toHaveTextContent("3 in a row: Couldn't connect");
    expect(screen.getByRole("button", { name: "Add destination" })).toBeEnabled();
    expect(document.body.textContent).not.toContain("ompwhs_");
    expect(await axe(container)).toHaveNoViolations();
  });

  it("tells editors and members who manages webhooks, without asking for the list", async () => {
    for (const role of ["editor", "member"] as const) {
      const calls = mockApi(routes({}, role));
      const { unmount } = open();
      expect(await screen.findByText("Only the team's owners and admins manage webhooks.")).toBeInTheDocument();
      expect(screen.getByRole("link", { name: "your notification settings" })).toHaveAttribute("href", "/settings/notifications");
      expect(screen.queryByRole("button", { name: "Add destination" })).toBeNull();
      expect(calls.some((c) => c.url === base)).toBe(false);
      unmount();
    }
  });

  it("is read-only for platform staff who aren't on the team: the list and the log, nothing that changes", async () => {
    const u = userEvent.setup();
    mockApi(routes({ [`GET ${base}/${destination().id}/deliveries`]: () => [delivery()] }, null, "platform_auditor"));
    open();
    const row = (await screen.findByText("On-call webhook")).closest("tr")!;
    expect(screen.queryByRole("button", { name: "Add destination" })).toBeNull();
    expect(within(row).queryByRole("switch")).toBeNull();
    expect(screen.getByText("You're viewing this team as platform staff: destinations can be read, not changed.")).toBeInTheDocument();
    await u.click(within(row).getByRole("button", { name: "Actions for On-call webhook" }));
    expect((await screen.findAllByRole("menuitem")).map((m) => m.textContent)).toEqual(["Delivery log"]);
  });

  it("can't change anything in an archived team", async () => {
    mockApi({ ...routes(), [`GET /v1/teams/${team.slug}`]: () => ({ team: { ...team, status: "archived" }, role: "owner" }) });
    open();
    expect(await screen.findByText("On-call webhook")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add destination" })).toBeNull();
    expect(screen.getByText(/The team is archived, so its destinations can't be changed/)).toBeInTheDocument();
  });

  it("adds a JSON destination, shows the signing secret once and never again", async () => {
    const u = userEvent.setup();
    const created = destination({ id: "new", name: "Pager", events: ["server.unhealthy"] });
    const calls = mockApi(routes({ [`POST ${base}`]: () => new Reply(201, { data: { destination: created, secret } satisfies Schemas["NotificationDestinationCreated"] }) }));
    open();
    await u.click(await screen.findByRole("button", { name: "Add destination" }));
    const dialog = await screen.findByRole("dialog", { name: "Add a webhook destination" });
    // Only the events a team destination can receive are offered.
    expect(within(dialog).getByRole("checkbox", { name: /A server is failing/ })).toBeChecked();
    expect(within(dialog).queryByRole("checkbox", { name: /waiting for review/ })).toBeNull();
    expect(within(dialog).queryByRole("switch", { name: /every team/ })).toBeNull();
    await u.click(within(dialog).getByRole("button", { name: "Add destination" }));
    expect(await within(dialog).findByText("Enter a name.")).toBeInTheDocument();
    expect(within(dialog).getByText("Enter the URL to send to.")).toBeInTheDocument();
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "Pager");
    await u.type(within(dialog).getByRole("textbox", { name: /URL/ }), "https://hooks.example.com/abc?token=1");
    await u.click(within(dialog).getByRole("checkbox", { name: /A server recovered/ }));
    await u.click(within(dialog).getByRole("button", { name: "Add destination" }));
    await waitFor(() =>
      expect(calls.find((c) => c.method === "POST")?.body).toEqual({
        name: "Pager",
        format: "json",
        url: "https://hooks.example.com/abc?token=1",
        events: ["server.unhealthy"],
        teamEvents: false,
        enabled: true,
      }),
    );

    const shown = await screen.findByRole("dialog", { name: "Pager was added" });
    expect(within(shown).getByText("Copy this signing secret now.")).toBeInTheDocument();
    expect(within(shown).getByText(secret)).toBeInTheDocument();
    expect(within(shown).getByText(/X-OMP-Signature: v1=/)).toBeInTheDocument();
    await u.click(within(shown).getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.body.textContent).not.toContain(secret);
    // The list never carries it either.
    expect(JSON.stringify(calls.filter((c) => c.method === "GET").map((c) => c.url))).not.toContain("secret");
  });

  it("adds a Slack destination without a secret", async () => {
    const u = userEvent.setup();
    const created = { destination: destination({ name: "Chat", format: "slack", hasSecret: false }), secret: null } satisfies Schemas["NotificationDestinationCreated"];
    const calls = mockApi(routes({ [`POST ${base}`]: () => new Reply(201, { data: created }) }));
    open();
    await u.click(await screen.findByRole("button", { name: "Add destination" }));
    const dialog = await screen.findByRole("dialog", { name: "Add a webhook destination" });
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "Chat");
    await u.click(within(dialog).getByRole("radio", { name: /Slack/ }));
    await u.type(within(dialog).getByRole("textbox", { name: /URL/ }), "https://hooks.slack.com/services/T/B/x");
    await u.click(within(dialog).getByRole("button", { name: "Add destination" }));
    await waitFor(() => expect(calls.find((c) => c.method === "POST")?.body).toMatchObject({ format: "slack" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(screen.queryByText("Copy this signing secret now.")).toBeNull();
  });

  it("explains a URL the portal refuses", async () => {
    const u = userEvent.setup();
    mockApi(routes({ [`POST ${base}`]: () => Reply.error(422, "url_not_allowed", "no", { reason: "private_address" }) }));
    open();
    await u.click(await screen.findByRole("button", { name: "Add destination" }));
    const dialog = await screen.findByRole("dialog", { name: "Add a webhook destination" });
    await u.type(within(dialog).getByRole("textbox", { name: "Name" }), "Internal");
    await u.type(within(dialog).getByRole("textbox", { name: /URL/ }), "https://10.0.0.5/hook");
    await u.click(within(dialog).getByRole("button", { name: "Add destination" }));
    expect(await within(dialog).findByText(/the operator can allow a network with NOTIFY_WEBHOOK_ALLOWED_NETWORKS/)).toBeInTheDocument();
  });

  it("changes a destination without asking for the URL again, and sends a new one only when typed", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes({ [`PATCH ${base}/${destination().id}`]: () => destination({ name: "Renamed", revision: 2 }) }));
    open();
    await rowMenu(u, "On-call webhook", "Change…");
    const dialog = await screen.findByRole("dialog", { name: "Change On-call webhook" });
    expect(within(dialog).getByText(/Currently https:\/\/hooks\.example\.com\/\.\.\./)).toBeInTheDocument();
    expect(within(dialog).getByRole("textbox", { name: /URL/ })).toHaveValue("");
    expect(within(dialog).getByRole("radio", { name: /JSON/ })).toHaveAttribute("aria-disabled", "true");
    const name = within(dialog).getByRole("textbox", { name: "Name" });
    await u.clear(name);
    await u.type(name, "Renamed");
    await u.click(within(dialog).getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ name: "Renamed", events: ["server.unhealthy", "server.recovered"] }));
    expect(calls.find((c) => c.method === "PATCH")?.headers.get("If-Match")).toBe('"1"');
  });

  it("turns a destination off and on with its switch", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes({ [`PATCH ${base}/${destination().id}`]: () => destination({ enabled: false, revision: 2 }) }));
    open();
    await u.click(await screen.findByRole("switch", { name: "On-call webhook enabled" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ enabled: false }));
  });

  it("shows a stopped destination with a banner and turns it back on", async () => {
    const u = userEvent.setup();
    const stopped = destination({ enabled: false, disabledReason: "failures", health: { state: "failing", consecutiveFailures: 20, lastErrorClass: "timeout", lastFailureAt: "2026-10-17T11:00:00Z", lastSuccessAt: null } });
    const calls = mockApi(routes({ [`GET ${base}`]: () => [stopped], [`PATCH ${base}/${stopped.id}`]: () => destination() }));
    open();
    expect(await screen.findByText("On-call webhook was stopped")).toBeInTheDocument();
    expect(screen.getByText("Stopped: repeated failures")).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Turn back on" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ enabled: true }));
  });

  it("sends a test and shows the outcome, or why it was refused", async () => {
    const u = userEvent.setup();
    let answer: unknown = { ok: false, errorClass: "connect", httpStatus: null, durationMs: 31, message: "The receiver could not be reached." } satisfies Schemas["NotificationTestResult"];
    mockApi(routes({ [`POST ${base}/${destination().id}/test`]: () => (answer instanceof Reply ? answer : { ...(answer as object) }) }));
    open();
    await rowMenu(u, "On-call webhook", "Send test…");
    const dialog = await screen.findByRole("dialog", { name: "Send a test to On-call webhook" });
    await u.click(within(dialog).getByRole("button", { name: "Send test" }));
    expect(await within(dialog).findByText("The test failed")).toBeInTheDocument();
    expect(within(dialog).getByText("The receiver could not be reached.")).toBeInTheDocument();
    expect(within(dialog).getByText(/Couldn't connect/)).toBeInTheDocument();
    answer = new Reply(200, { data: { ok: true, httpStatus: 200, durationMs: 12, message: "Delivered." } });
    await u.click(within(dialog).getByRole("button", { name: "Send again" }));
    expect(await within(dialog).findByText("The destination accepted the test")).toBeInTheDocument();
    answer = Reply.error(429, "rate_limited", "Too many tests", undefined, { "Retry-After": "60" });
    await u.click(within(dialog).getByRole("button", { name: "Send again" }));
    expect(await within(dialog).findByText("Too many requests")).toBeInTheDocument();
  });

  it("rotates a JSON secret after asking, with the grace period, and shows the new one once", async () => {
    const u = userEvent.setup();
    const next = "ompwhs_" + "n".repeat(43);
    const calls = mockApi(
      routes({
        [`POST ${base}/${destination().id}/rotate-secret`]: () =>
          ({ destination: destination({ previousSecretExpiresAt: new Date(Date.now() + 86_400_000).toISOString() }), secret: next }) satisfies Schemas["NotificationDestinationSecret"],
      }),
    );
    open();
    await rowMenu(u, "On-call webhook", "Rotate secret…");
    const ask = await screen.findByRole("alertdialog", { name: /Rotate the signing secret of On-call webhook/ });
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    await u.click(within(ask).getByRole("button", { name: "Rotate secret" }));
    await waitFor(() => expect(calls.find((c) => c.url.endsWith("/rotate-secret"))?.body).toEqual({ graceHours: 24 }));
    const shown = await screen.findByRole("dialog", { name: "New signing secret for On-call webhook" });
    expect(within(shown).getByText(next)).toBeInTheDocument();
    expect(within(shown).getByText("Both secrets sign for now")).toBeInTheDocument();
    await u.click(within(shown).getByRole("button", { name: "Done" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.body.textContent).not.toContain(next);
  });

  it("has no Rotate secret for a Slack destination", async () => {
    const u = userEvent.setup();
    mockApi(routes({ [`GET ${base}`]: () => [destination({ format: "slack", hasSecret: false })] }));
    open();
    await u.click(await screen.findByRole("button", { name: "Actions for On-call webhook" }));
    expect((await screen.findAllByRole("menuitem")).map((m) => m.textContent)).not.toContain("Rotate secret…");
  });

  it("deletes after asking", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes({ [`DELETE ${base}/${destination().id}`]: () => ({ ok: true }) }));
    open();
    await rowMenu(u, "On-call webhook", "Delete…");
    const ask = await screen.findByRole("alertdialog", { name: "Delete On-call webhook?" });
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    await u.click(within(ask).getByRole("button", { name: "Delete destination" }));
    await waitFor(() => expect(calls.some((c) => c.method === "DELETE")).toBe(true));
  });

  it("shows the delivery log with outcomes and error text, never a payload", async () => {
    const u = userEvent.setup();
    mockApi(
      routes({
        [`GET ${base}/${destination().id}/deliveries`]: () => [
          delivery(),
          delivery({ id: 9002, state: "failed", attempts: 6, httpStatus: 502, errorClass: "server_error", sentAt: null }),
          delivery({ id: 9003, state: "pending", attempts: 1, nextAttemptAt: "2026-10-17T12:30:00Z", httpStatus: null, sentAt: null, errorClass: "timeout" }),
        ],
      }),
    );
    open();
    await rowMenu(u, "On-call webhook", "Delivery log");
    const dialog = await screen.findByRole("dialog", { name: "Delivery log: On-call webhook" });
    const table = await within(dialog).findByRole("table", { name: "Deliveries to On-call webhook" });
    expect(within(table).getAllByRole("row")).toHaveLength(4);
    expect(within(table).getByText("Delivered")).toBeInTheDocument();
    expect(within(table).getByText("The destination had an error (5xx)")).toBeInTheDocument();
    expect(within(table).getByText("502")).toBeInTheDocument();
    expect(within(table).getByText("Waiting")).toBeInTheDocument();
    expect(await axe(dialog)).toHaveNoViolations();
  });
});
