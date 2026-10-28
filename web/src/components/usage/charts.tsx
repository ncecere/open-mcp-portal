/*
 * The usage dashboards' charts: calls per bucket stacked by outcome, and the
 * p50/p95 latency per bucket. Both have a text summary for assistive
 * technology and a "Show data" table.
 */
import { BarChart } from "@/components/ui/bar-chart/bar-chart";
import type { ChartTone } from "@/components/ui/chart/chart";
import { Card } from "@/components/ui/card/card";
import { LineChart } from "@/components/ui/line-chart/line-chart";
import { type CallOutcome, callOutcomes, outcomeLabels } from "../gateways/labels";
import { bucketLabel, ms, num, type UsageReport } from "./range";
import u from "./usage.module.css";

/**
 * Each outcome's colour in the stacked chart. Badges share a few tones, but stacked bars need the outcomes people
 * tell apart to differ: refusals for a missing connection (info) and for a rate limit (accent) are never both amber.
 * Nine outcomes, seven tones: the remaining errors share warning or danger by severity.
 */
export const outcomeChartTone: Record<CallOutcome, ChartTone> = {
  ok: "success",
  tool_error: "warning",
  denied: "neutral",
  upstream_error: "danger",
  timeout: "danger",
  too_large: "warning",
  bad_request: "warning",
  needs_authorization: "info",
  needs_approval: "warning",
  rate_limited: "accent",
};

const word = (bucket: "hour" | "day") => (bucket === "day" ? "day" : "hour");

/** Calls per day (or hour), stacked by outcome; only outcomes that happened get a series. */
export function CallsChart({ report, bucket }: { report: UsageReport; bucket: "hour" | "day" }) {
  const present = callOutcomes.filter((o) => (report.totals.outcomes[o] ?? 0) > 0);
  const data = report.rows.map((r) => ({
    label: bucketLabel(r.start ?? r.key, bucket),
    values: Object.fromEntries(present.map((o) => [o, r.metrics.outcomes[o] ?? 0])) as Record<CallOutcome, number>,
  }));
  const busiest = report.rows.reduce((a, b) => (b.metrics.calls > (a?.metrics.calls ?? -1) ? b : a), report.rows[0]);
  const summary =
    report.totals.calls === 0 || !busiest
      ? `Calls per ${word(bucket)}: none in this range.`
      : `Calls per ${word(bucket)}: ${num(report.totals.calls)} in total, ${num(report.totals.errors)} not OK; the busiest ${word(bucket)} was ${bucketLabel(busiest.start ?? busiest.key, bucket)} with ${num(busiest.metrics.calls)}.`;
  return (
    <Card title={`Calls per ${word(bucket)}`} description={`By outcome, in UTC ${word(bucket)}s.`}>
      <div className={u.chart}>
        <BarChart
          layout="stack"
          data={data}
          series={present.map((o) => ({ key: o, label: outcomeLabels[o], tone: outcomeChartTone[o] }))}
          summary={summary}
          dataTable={{ caption: `Calls per ${word(bucket)} by outcome` }}
        />
      </div>
    </Card>
  );
}

/** p50 and p95 latency per bucket (empty buckets are gaps). */
export function LatencyChart({ report, bucket }: { report: UsageReport; bucket: "hour" | "day" }) {
  const data = report.rows.map((r) => ({
    label: bucketLabel(r.start ?? r.key, bucket),
    values: { p50: r.metrics.p50LatencyMs ?? Number.NaN, p95: r.metrics.p95LatencyMs ?? Number.NaN },
  }));
  const summary = `Latency per ${word(bucket)}: ${ms(report.totals.p50LatencyMs)} at the median and ${ms(report.totals.p95LatencyMs)} at the 95th percentile over the whole range.`;
  return (
    <Card title="Latency" description="How long calls took: half were faster than p50, 95 in 100 faster than p95 (accurate to a bucket).">
      <div className={u.chart}>
        <LineChart
          data={data}
          series={[
            { key: "p50", label: "p50", tone: "info" },
            { key: "p95", label: "p95", tone: "warning" },
          ]}
          formatValue={(v) => ms(v)}
          summary={summary}
          dataTable={{ caption: `Latency per ${word(bucket)}` }}
        />
      </div>
    </Card>
  );
}
