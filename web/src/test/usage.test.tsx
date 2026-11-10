/* Usage dashboards (Team › Usage, Admin › Usage): range and grouping rules, totals, charts, the breakdown and empty states. */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { axe } from "vitest-axe";
import type { Schemas } from "../api/client";
import { CallsChart, outcomeChartTone } from "../components/usage/charts";
import { bucketFor, groupByProblem, nextHour, resolveRange } from "../components/usage/range";
import { gatewayId, team, teamSummary } from "./fixtures";
import { metrics, usageReport } from "./fixtures-operations";
import { type Call, type Handler, mockApi, renderBare, shellRoutes } from "./harness";
import { renderApp } from "./render-app";

const DAY = 86_400_000;
const teamUsage = `/v1/teams/${team.slug}/usage`;

const gatewayRows = (): Schemas["UsageReport"] =>
  usageReport({
    groupBy: "gateway",
    rows: [
      { key: gatewayId, label: "Support tools", ref: { id: gatewayId, slug: "support-tools", name: "Support tools", exists: true }, metrics: metrics({ calls: 100, errors: 5, p50LatencyMs: 75, p95LatencyMs: 850 }) },
      { key: "gone", label: "Old gateway", ref: { id: "gone", slug: "old", name: "Old gateway", exists: false }, metrics: metrics({ calls: 20, errors: 1 }) },
    ],
  });

/** Answers by grouping, as the server would. */
const answer = (_b: unknown, call: Call) => (call.search.get("groupBy") === "gateway" || call.search.get("groupBy") === "team" ? gatewayRows() : usageReport({ groupBy: (call.search.get("groupBy") ?? "day") as Schemas["UsageGroupBy"] }));

const requests = (calls: Call[], url = teamUsage) => calls.filter((c) => c.url === url);

describe("usage range rules", () => {
  const now = new Date("2026-10-16T07:42:10Z");
  it("ends presets at the next hour and spans whole UTC days for custom dates", () => {
    expect(nextHour(now).toISOString()).toBe("2026-10-16T08:00:00.000Z");
    const week = resolveRange("7d", null, null, now);
    expect(week.to?.toISOString()).toBe("2026-10-16T08:00:00.000Z");
    expect(week.from?.toISOString()).toBe("2026-10-09T08:00:00.000Z");
    const custom = resolveRange("custom", "2026-10-01", "2026-10-03", now);
    expect(custom.from?.toISOString()).toBe("2026-10-01T00:00:00.000Z");
    expect(custom.to?.toISOString()).toBe("2026-10-04T00:00:00.000Z");
  });

  it("refuses more than 90 days, an end before the start, and hourly totals over 7 days", () => {
    expect(resolveRange("custom", "2026-01-01", "2026-10-01").error).toBe("Choose at most 90 days.");
    expect(resolveRange("custom", "2026-07-04", "2026-10-01").error).toBeUndefined();
    expect(resolveRange("custom", "2026-10-05", "2026-10-01").error).toMatch(/start on or before the end/);
    expect(resolveRange("custom", "", "2026-10-01").error).toMatch(/Choose a start/);
    const month = resolveRange("30d", null, null, now) as { from: Date; to: Date };
    expect(groupByProblem("hour", month)).toMatch(/at most 7 days/);
    expect(groupByProblem("day", month)).toBeUndefined();
    expect(groupByProblem("hour", resolveRange("7d", null, null, now) as { from: Date; to: Date })).toBeUndefined();
    expect(bucketFor(resolveRange("24h", null, null, now) as { from: Date; to: Date })).toBe("hour");
    expect(bucketFor(month)).toBe("day");
  });
});

describe("calls chart colours", () => {
  it("tells a missing connection from a rate limit (and both from tool errors)", async () => {
    const both = metrics({ calls: 6, errors: 6, outcomes: { tool_error: 2, needs_authorization: 2, rate_limited: 2 } });
    renderBare(<CallsChart bucket="day" report={usageReport({ totals: both, rows: [{ key: "2026-10-16T00:00:00Z", label: "2026-10-16", start: "2026-10-16T00:00:00Z", metrics: both }] })} />);
    await screen.findByText("Needed a connection", { selector: "li" });
    const tone = (label: string) => screen.getByText(label, { selector: "li" }).querySelector("[data-tone]")?.getAttribute("data-tone");
    const tones = [tone("Needed a connection"), tone("Rate limited"), tone("Tool error")];
    expect(tones).toEqual([outcomeChartTone.needs_authorization, outcomeChartTone.rate_limited, outcomeChartTone.tool_error]);
    expect(new Set(tones).size).toBe(3);
  });
});

describe("Team › Usage", () => {
  const routes = (role: Schemas["TeamRole"] = "editor", extra: Record<string, Handler> = {}): Record<string, Handler> => ({
    ...shellRoutes("none", role),
    [`GET ${teamUsage}`]: answer,
    ...extra,
  });

  it("shows the last 7 days' totals, calls by outcome, latency and the breakdown by gateway", async () => {
    const calls = mockApi(routes());
    const { container } = renderApp(`/teams/${team.slug}/usage`);
    expect(await screen.findByRole("heading", { level: 1, name: "Usage" })).toBeInTheDocument();
    const totals = await screen.findByRole("group", { name: "Totals for the range" });
    expect(within(totals).getByText("120")).toBeInTheDocument();
    expect(within(totals).getByText("5%")).toBeInTheDocument();
    expect(within(totals).getByText("80 ms")).toBeInTheDocument();
    expect(within(totals).getByText("900 ms")).toBeInTheDocument();
    expect(within(totals).getByText("3.0 MiB")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Calls per day: 120 in total, 6 not OK/ })).toBeInTheDocument();
    const table = await screen.findByRole("table", { name: "Usage by gateway" });
    expect(within(table).getByText("Support tools").closest("tr")).toHaveTextContent("850 ms");
    expect(within(table).getByText("Old gateway").closest("tr")).toHaveTextContent("Deleted");
    await waitFor(() => expect(document.title).toBe(`Usage · ${team.name} · Open MCP Portal`));
    expect(await axe(container)).toHaveNoViolations();

    // One report for the chart (by day) and one for the table (by gateway), over the same hour-aligned week.
    const sent = requests(calls);
    expect(sent.map((c) => c.search.get("groupBy")).sort()).toEqual(["day", "gateway"]);
    const from = Date.parse(sent[0]!.search.get("from")!);
    const to = Date.parse(sent[0]!.search.get("to")!);
    expect(to - from).toBe(7 * DAY);
    expect(to % 3_600_000).toBe(0);
  });

  it("offers hourly totals only for up to 7 days, and refuses a custom range over 90 days", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes());
    const { router } = renderApp(`/teams/${team.slug}/usage`);
    await screen.findByRole("table", { name: "Usage by gateway" });
    await u.selectOptions(screen.getByRole("combobox", { name: "Group by" }), "hour");
    await waitFor(() => expect(requests(calls).some((c) => c.search.get("groupBy") === "hour")).toBe(true));
    expect(await screen.findByRole("table", { name: "Usage by hour" })).toBeInTheDocument();

    await u.selectOptions(screen.getByRole("combobox", { name: "Group by" }), "day");
    await u.selectOptions(screen.getByRole("combobox", { name: "Range" }), "30d");
    await waitFor(() => expect(within(screen.getByRole("combobox", { name: "Group by" })).getByRole("option", { name: "Hour" })).toBeDisabled());

    // An address asking for hourly totals over 30 days explains instead of asking the server.
    const before = requests(calls).length;
    await router.navigate({ to: "/teams/$team/usage", params: { team: team.slug }, search: { range: "30d", groupBy: "hour" } as never });
    expect(await screen.findByText(/Hourly totals cover at most 7 days/)).toBeInTheDocument();
    expect(requests(calls).slice(before).some((c) => c.search.get("groupBy") === "hour")).toBe(false);

    await router.navigate({ to: "/teams/$team/usage", params: { team: team.slug }, search: { range: "custom", from: "2026-01-01", to: "2026-10-01" } as never });
    expect(await screen.findByText("Choose at most 90 days.")).toBeInTheDocument();
    const n = requests(calls).length;
    await new Promise((r) => setTimeout(r, 50));
    expect(requests(calls)).toHaveLength(n);
    const fromGroup = screen.getByRole("group", { name: "From (UTC)" });
    expect(within(fromGroup).getByRole("combobox", { name: "From month" })).toHaveValue("01");
    expect(within(fromGroup).getByRole("combobox", { name: "From day" })).toHaveValue("01");
    expect(within(fromGroup).getByRole("combobox", { name: "From year" })).toHaveValue("2026");
    expect(screen.getByRole("group", { name: "To (UTC)" })).toHaveAccessibleDescription("Choose at most 90 days.");
  });

  it("names each part of the custom dates and asks for whole UTC days", async () => {
    const u = userEvent.setup();
    const calls = mockApi(routes());
    const { router, container } = renderApp(`/teams/${team.slug}/usage`);
    await screen.findByRole("table", { name: "Usage by gateway" });
    await router.navigate({ to: "/teams/$team/usage", params: { team: team.slug }, search: { range: "custom", from: "2026-01-30", to: "2026-03-31" } as never });
    const to = await screen.findByRole("group", { name: "To (UTC)" });
    for (const part of ["month", "day", "year"]) {
      expect(screen.getByRole("combobox", { name: `From ${part}` })).toBeInTheDocument();
      expect(within(to).getByRole("combobox", { name: `To ${part}` })).toBeInTheDocument();
    }
    expect(screen.getByRole("group", { name: "From (UTC)" })).toHaveAccessibleDescription("At most 90 days");
    expect(await axe(container)).toHaveNoViolations();

    // 30 January → February keeps the day within the month.
    await u.selectOptions(screen.getByRole("combobox", { name: "From month" }), "02");
    expect(screen.getByRole("combobox", { name: "From day" })).toHaveValue("28");
    await waitFor(() => expect(requests(calls).some((c) => c.search.get("from") === "2026-02-28T00:00:00.000Z" && c.search.get("to") === "2026-04-01T00:00:00.000Z")).toBe(true));
  });

  it("refuses a date that doesn't exist", () => {
    expect(resolveRange("custom", "2026-02-31", "2026-03-05").error).toMatch(/Choose a start/);
  });

  it("shows how far the totals reach in UTC, whatever the browser's time zone", async () => {
    const tz = process.env.TZ;
    process.env.TZ = "America/Los_Angeles"; // rolledUpTo 07:55Z is 00:55 there
    try {
      mockApi(routes());
      renderApp(`/teams/${team.slug}/usage`);
      const note = (await screen.findByText(/Includes calls up to/)).closest("p")!;
      const time = note.querySelector("time")!;
      expect(time).toHaveAttribute("datetime", "2026-10-16T07:55:00.000Z");
      expect(time.textContent).toMatch(/7:55/);
      expect(time.textContent).not.toMatch(/12:55/);
      expect(note).toHaveTextContent(/7:55\s?AM UTC\. Totals are updated every 5 minutes; all times here are UTC\./);
    } finally {
      if (tz === undefined) delete process.env.TZ;
      else process.env.TZ = tz;
    }
  });

  it("says when there were no calls", async () => {
    mockApi(routes("owner", { [`GET ${teamUsage}`]: () => usageReport({ totals: metrics(), rows: [], rolledUpTo: null }) }));
    renderApp(`/teams/${team.slug}/usage`);
    expect(await screen.findByText("No calls in this range.")).toBeInTheDocument();
    expect(screen.getByText(/none have been computed yet/)).toBeInTheDocument();
  });

  it("isn't for plain members", async () => {
    const calls = mockApi(routes("member"));
    renderApp(`/teams/${team.slug}/usage`);
    expect(await screen.findByText("Only the team's owners, admins and editors see its usage.")).toBeInTheDocument();
    expect(requests(calls)).toHaveLength(0);
  });
});

describe("Admin › Usage", () => {
  it("groups by team and narrows to one team", async () => {
    const u = userEvent.setup();
    const calls = mockApi({
      ...shellRoutes("platform_auditor", null),
      "GET /v1/admin/usage": answer,
      "GET /v1/admin/teams": () => ({ items: [teamSummary()], nextCursor: null }),
    });
    const { container } = renderApp("/admin/usage");
    await screen.findByRole("table", { name: "Usage by gateway" });
    expect(within(screen.getByRole("table", { name: "Usage by gateway" })).getByRole("link", { name: "Support tools" })).toHaveAttribute("href", `/admin/gateways/${gatewayId}`);
    expect(within(screen.getByRole("combobox", { name: "Group by" })).getByRole("option", { name: "Team" })).toBeInTheDocument();
    await u.selectOptions(await screen.findByRole("combobox", { name: "Team" }), team.slug);
    await waitFor(() => expect(requests(calls, "/v1/admin/usage").some((c) => c.search.get("team") === team.slug)).toBe(true));
    expect(await axe(container)).toHaveNoViolations();
  });
});
