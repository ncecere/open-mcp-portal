/* The gateway's sensitivity ceiling, the unavailable reasons and Admin › Publishing's review settings (decision 88). */
import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { unavailableHelp, unavailableLabels } from "../components/gateways/labels";
import { allEvents, eventDescriptions, eventLabels, eventRecipients } from "../components/notifications/events";
import { gateway, gatewayCapabilities, gatewayId, gatewayOptions, mcpCall, myGateway, optionsPage, page, team } from "./fixtures";
import { type Handler, Reply, mockApi, renderApp, shellRoutes } from "./harness";

const base = `/v1/teams/${team.slug}/gateways`;
const record = `/teams/${team.slug}/gateways/${gatewayId}?tab=settings`;

const gwRoutes = (role: "owner" | "editor", g: () => Schemas["Gateway"], extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes("none", role),
  [`GET ${base}`]: () => page([g()]),
  [`GET ${base}/${gatewayId}`]: g,
  [`GET ${base}/${gatewayId}/capabilities`]: () => gatewayCapabilities(),
  [`GET /v1/teams/${team.slug}/gateway-options`]: (_b, call) => optionsPage(gatewayOptions, call.search),
  [`GET /v1/teams/${team.slug}/calls`]: () => page([mcpCall()]),
  "GET /v1/me/gateways": () => [myGateway()],
  ...extra,
});

describe("Gateway sensitivity ceiling", () => {
  it("defaults to no ceiling and saves only a changed ceiling, warning when it lowers", async () => {
    const u = userEvent.setup();
    let current = gateway({ unavailableCount: 0 });
    const calls = mockApi(gwRoutes("owner", () => current, { [`PATCH ${base}/${gatewayId}`]: () => (current = gateway({ maxSensitivity: "internal", revision: 8 })) }));
    const { container } = renderApp(record);
    const select = await screen.findByRole("combobox", { name: "Highest label served" });
    expect(select).toHaveValue("restricted");
    expect(screen.getByText("No ceiling: it serves servers of every label.")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();
    await u.selectOptions(select, "internal");
    expect(screen.getByText("Tools may disappear for everyone who uses this gateway")).toBeInTheDocument();
    expect(screen.getByText(/serves servers labelled internal or lower/)).toBeInTheDocument();
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toMatchObject({ maxSensitivity: "internal" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).not.toHaveProperty("rateLimitPerMinute"));
    await screen.findByText("Gateway settings saved");
  });

  it("an unchanged ceiling is not sent, and an editor only reads it", async () => {
    const u = userEvent.setup();
    const calls = mockApi(gwRoutes("owner", () => gateway({ maxSensitivity: "confidential" }), { [`PATCH ${base}/${gatewayId}`]: () => gateway({ maxSensitivity: "confidential", revision: 8 }) }));
    const { unmount } = renderApp(record);
    expect(await screen.findByRole("combobox", { name: "Highest label served" })).toHaveValue("confidential");
    await u.type(screen.getByRole("textbox", { name: "Name" }), "!");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.some((c) => c.method === "PATCH")).toBe(true));
    expect(calls.find((c) => c.method === "PATCH")?.body).not.toHaveProperty("maxSensitivity");
    unmount();
    mockApi(gwRoutes("editor", () => gateway({ maxSensitivity: "confidential" })));
    renderApp(record);
    expect(await screen.findByRole("combobox", { name: "Highest label served" })).toBeDisabled();
  });

  it("explains both new reasons for an unavailable capability", () => {
    expect(unavailableLabels.sensitivity_exceeds_gateway).toBe("Above this gateway's ceiling");
    expect(unavailableHelp.sensitivity_exceeds_gateway).toMatch(/Raise the ceiling/);
    expect(unavailableLabels.sunset).toBe("Server retired");
    expect(unavailableHelp.sunset).toMatch(/no gateway serves it/);
  });
});

describe("Notification events", () => {
  it("names the three governance notices and who gets them (never webhooks)", () => {
    for (const e of ["server.review_due", "server.sunset_soon", "server.deprecated"] as const) {
      expect(allEvents).toContain(e);
      expect(eventLabels[e]).toBeTruthy();
      expect(eventDescriptions[e]).toBeTruthy();
      expect(eventRecipients[e]).toMatch(/portal and by email only/);
    }
  });
});

const settings = (extra: Partial<Schemas["GovernanceSettings"]> = {}): Schemas["GovernanceSettings"] => ({
  reviewIntervalDays: { public: 0, internal: 0, confidential: 180, restricted: 90 },
  returnOverdueToReview: false,
  revision: 3,
  updatedAt: "2026-10-20T10:00:00Z",
  ...extra,
});
const adminRoutes = (role: "platform_admin" | "platform_auditor", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes(role, null),
  "GET /v1/admin/settings/publishing": (): Schemas["PublishingSettings"] => ({ defaultPolicy: "approval_required", revision: 2, updatedAt: "2026-10-01T10:00:00Z" }),
  "GET /v1/admin/settings/governance": () => settings(),
  [`GET /v1/admin/teams`]: () => page([]),
  ...extra,
});

describe("Admin › Publishing › Server reviews", () => {
  it("shows the intervals and the overdue switch, and saves them with the settings' own revision", async () => {
    const u = userEvent.setup();
    const calls = mockApi(adminRoutes("platform_admin", { "PUT /v1/admin/settings/governance": () => settings({ revision: 4, returnOverdueToReview: true }) }));
    const { container } = renderApp("/admin/publishing");
    const days = await screen.findByRole("textbox", { name: "Restricted servers" });
    expect(days).toHaveValue("90");
    expect(screen.getByRole("textbox", { name: "Internal servers" })).toHaveValue("0");
    expect(screen.getByRole("switch", { name: "Send overdue servers back to review" })).not.toBeChecked();
    expect(await axe(container)).toHaveNoViolations();
    expect(screen.getByRole("button", { name: "Save review settings" })).toBeDisabled();
    await u.clear(days);
    await u.type(days, "30");
    await u.click(screen.getByRole("switch", { name: "Send overdue servers back to review" }));
    await u.click(screen.getByRole("button", { name: "Save review settings" }));
    await waitFor(() =>
      expect(calls.find((c) => c.method === "PUT" && c.url.endsWith("/governance"))?.body).toEqual({
        reviewIntervalDays: { public: 0, internal: 0, confidential: 180, restricted: 30 },
        returnOverdueToReview: true,
      }),
    );
    expect(calls.find((c) => c.method === "PUT" && c.url.endsWith("/governance"))?.headers.get("If-Match")).toBe('"3"');
    await screen.findByText("Review settings saved");
  });

  it("refuses a number that is not a day count before sending it", async () => {
    const u = userEvent.setup();
    const calls = mockApi(adminRoutes("platform_admin"));
    renderApp("/admin/publishing");
    const days = await screen.findByRole("textbox", { name: "Public servers" });
    await u.type(days, "x");
    expect(await screen.findByText("Use a whole number of days from 0 to 3650.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save review settings" })).toBeDisabled();
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
  });

  it("a change made elsewhere is told, and auditors only read", async () => {
    const u = userEvent.setup();
    mockApi(adminRoutes("platform_admin", { "PUT /v1/admin/settings/governance": () => Reply.error(412, "stale_revision", "stale") }));
    const { unmount } = renderApp("/admin/publishing");
    await u.click(await screen.findByRole("switch", { name: "Send overdue servers back to review" }));
    await u.click(screen.getByRole("button", { name: "Save review settings" }));
    expect(await screen.findByText("Changed elsewhere")).toBeInTheDocument();
    unmount();
    mockApi(adminRoutes("platform_auditor"));
    renderApp("/admin/publishing");
    expect(await screen.findByRole("textbox", { name: "Restricted servers" })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Save review settings" })).toBeNull();
    expect(screen.getByText("Platform admins change these settings.")).toBeInTheDocument();
  });
});
