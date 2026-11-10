/* A team's limit and retention overrides (Admin › Teams › a team › Limits & retention) and Team settings' read-only view. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { effectiveLimit, overrideChanges, overridesFormOf } from "../pages/admin/people/overrides-form";
import { page, team, teamSummary } from "./fixtures";
import { teamLimits, teamRetention } from "./fixtures-operations";
import { type Call, type Handler, Reply, mockApi, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const admin = `/v1/admin/teams/${team.slug}`;

const routes = (role: "platform_admin" | "platform_auditor" = "platform_admin", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
  ...shellRoutes(role, null),
  [`GET ${admin}`]: () => teamSummary(),
  [`GET ${admin}/members`]: () => page([]),
  [`GET ${admin}/publishing`]: () => ({ override: null, effective: "approval_required", defaultPolicy: "approval_required", revision: team.revision }),
  [`GET ${admin}/limits`]: () => teamLimits(),
  [`GET ${admin}/retention`]: () => teamRetention(),
  ...extra,
});

const sent = (calls: Call[], method: string, url: string) => calls.filter((c) => c.method === method && c.url === url);

describe("Admin › a team › Limits & retention", () => {
  it("sets the team's own limits up to the ceiling, then saves limits and retention with the team's revision in turn", async () => {
    const u = userEvent.setup();
    const calls = mockApi(
      routes("platform_admin", {
        [`PUT ${admin}/limits`]: (): Schemas["TeamLimits"] => teamLimits({ revision: 4 }),
        [`PUT ${admin}/retention`]: (): Schemas["TeamRetention"] => teamRetention({ revision: 5 }),
      }),
    );
    const { container } = renderApp(`/admin/teams/${team.slug}?tab=limits`);
    const limits = await screen.findByRole("table", { name: `Rate limits for ${team.name}` });
    // Only the keys teams can override.
    expect(within(limits).queryByText("Per person")).toBeNull();
    expect(within(limits).getByText("Ceiling: 5,000 per minute")).toBeInTheDocument();
    expect(within(limits).getByText("2,000 per minute")).toBeInTheDocument();
    expect(await axe(container)).toHaveNoViolations();

    await u.selectOptions(screen.getByRole("combobox", { name: "Per service account: team setting" }), "custom");
    await u.type(screen.getByRole("textbox", { name: "Per service account: team value (requests per minute)" }), "6000");
    expect(screen.getByText("At most the ceiling, 5,000 per minute.")).toBeInTheDocument();
    // An invalid value isn't previewed (not even capped at the ceiling): Applies says to fix it.
    const saRow = within(limits).getByRole("combobox", { name: "Per service account: team setting" }).closest("tr")!;
    expect(within(saRow).getByText("Fix the team value")).toBeInTheDocument();
    expect(within(saRow).queryByText("5,000 per minute")).toBeNull();
    await u.clear(screen.getByRole("textbox", { name: "Per service account: team value (requests per minute)" }));
    await u.type(screen.getByRole("textbox", { name: "Per service account: team value (requests per minute)" }), "0");
    expect(within(saRow).getByText("Fix the team value")).toBeInTheDocument();
    expect(within(saRow).queryByText("0 per minute")).toBeNull();
    await u.clear(screen.getByRole("textbox", { name: "Per service account: team value (requests per minute)" }));
    await u.type(screen.getByRole("textbox", { name: "Per service account: team value (requests per minute)" }), "2500");
    expect(within(limits).getByText("2,500 per minute")).toBeInTheDocument();
    await u.selectOptions(screen.getByRole("combobox", { name: "Per gateway: team setting" }), "inherit");
    // A longer period than the platform's: no confirmation needed.
    await u.selectOptions(screen.getByRole("combobox", { name: "Call records: team setting" }), "custom");
    await u.type(screen.getByRole("textbox", { name: "Call records: team days" }), "180");
    await u.click(screen.getByRole("button", { name: "Save settings" }));

    await waitFor(() => expect(sent(calls, "PUT", `${admin}/retention`)).toHaveLength(1));
    const [l] = sent(calls, "PUT", `${admin}/limits`);
    expect(l?.headers.get("If-Match")).toBe(`"${team.revision}"`);
    expect(l?.body).toEqual({ items: [{ key: "service_account_per_minute", value: 2500 }, { key: "gateway_per_minute", value: null }] });
    const [r] = sent(calls, "PUT", `${admin}/retention`);
    // The limits' save moved the team's revision on.
    expect(r?.headers.get("If-Match")).toBe('"4"');
    expect(r?.body).toEqual({ periods: [{ kind: "call_metadata", days: 180 }] });
    expect(await screen.findByText("Team limits and retention saved")).toBeInTheDocument();
  });

  it("asks before a shorter retention period, checks the bounds, and keeps edits through a conflict", async () => {
    const u = userEvent.setup();
    let current = teamRetention();
    let conflict = true;
    const calls = mockApi(
      routes("platform_admin", {
        [`GET ${admin}/retention`]: () => current,
        [`PUT ${admin}/retention`]: () => {
          if (!conflict) return teamRetention({ revision: 9 });
          conflict = false;
          current = teamRetention({ revision: 8, periods: teamRetention().periods.map((p) => (p.kind === "call_metadata" ? { ...p, override: 45, effective: 45 } : p)) });
          return Reply.error(412, "revision_conflict", "Changed");
        },
      }),
    );
    renderApp(`/admin/teams/${team.slug}?tab=limits`);
    const days = await screen.findByRole("textbox", { name: "Recorded call contents: team days" });
    await u.clear(days);
    await u.type(days, "120");
    expect(screen.getByText("Between 1 and 90 days.")).toBeInTheDocument();
    const row = days.closest("tr")!;
    expect(within(row).getByText("Fix the team value")).toBeInTheDocument();
    expect(within(row).queryByText("120 days")).toBeNull();
    await u.clear(days);
    await u.type(days, "7");
    await u.click(screen.getByRole("button", { name: "Save settings" }));
    const ask = await screen.findByRole("alertdialog", { name: `Delete ${team.name}'s records sooner?` });
    expect(ask).toHaveTextContent("Recorded call contents: 30 days → 7 days");
    await u.click(within(ask).getByRole("button", { name: "Save settings" }));
    expect(await screen.findByText("Someone else changed these settings while you were editing")).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Recorded call contents: team days" })).toHaveValue("7");
    await u.click(screen.getByRole("button", { name: "Overwrite with mine" }));
    await u.click(within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(sent(calls, "PUT", `${admin}/retention`)).toHaveLength(2));
    expect(sent(calls, "PUT", `${admin}/retention`)[1]?.headers.get("If-Match")).toBe('"8"');
    expect(sent(calls, "PUT", `${admin}/retention`)[1]?.body).toEqual({ periods: [{ kind: "captured_payloads", days: 7 }] });
    expect(sent(calls, "PUT", `${admin}/limits`)).toHaveLength(0);
  });

  it("is read-only for auditors", async () => {
    mockApi(routes("platform_auditor"));
    renderApp(`/admin/teams/${team.slug}?tab=limits`);
    const limits = await screen.findByRole("table", { name: `Rate limits for ${team.name}` });
    expect(within(limits).getByText("Inherits")).toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: /team setting/ })).toBeNull();
    expect(screen.getByText("You can view these settings. Only platform admins can change them.")).toBeInTheDocument();
  });

  it("works out what applies as typed, and only the changes", () => {
    const items = teamLimits().items;
    const sa = items.find((l) => l.key === "service_account_per_minute")!;
    expect(effectiveLimit(sa, { mode: "custom", value: "9000" })).toBe(5000);
    expect(effectiveLimit(sa, { mode: "inherit", value: "" })).toBe(1200);
    const form = overridesFormOf(items, teamRetention().periods);
    expect(overrideChanges(items, teamRetention().periods, form)).toEqual({ limits: [], periods: [] });
  });
});

describe("Team settings › Limits & retention", () => {
  it("shows the team's effective limits and periods to members, read-only", async () => {
    mockApi({
      ...shellRoutes("none", "member"),
      [`GET /v1/teams/${team.slug}/limits`]: () => teamLimits(),
      [`GET /v1/teams/${team.slug}/retention`]: () => teamRetention(),
    });
    const { container } = renderApp(`/teams/${team.slug}/settings?tab=limits`);
    const limits = await screen.findByRole("table", { name: "Rate limits that apply" });
    expect(within(limits).getByText("Per person").closest("tr")).toHaveTextContent("600 per minute");
    expect(within(limits).getByText("Per gateway").closest("tr")).toHaveTextContent("Set for your team");
    const retention = await screen.findByRole("table", { name: "Retention that applies" });
    expect(within(retention).getByText("Recorded call contents").closest("tr")).toHaveTextContent("30 days");
    expect(screen.queryByRole("textbox")).toBeNull();
    await waitFor(() => expect(document.title).toBe(`Limits & retention · Team settings · Open MCP Portal`));
    expect(await axe(container)).toHaveNoViolations();
  });
});
