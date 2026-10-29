/*
 * A server's Health tab: its current health and the recent checks, newest
 * first: scheduled ones, and manual ones (Test, Refresh, a save that read the
 * server). In a padded card, so the table's toolbar and pager line up with it.
 */
import { useQuery } from "@tanstack/react-query";
import { Activity } from "lucide-react";
import type { Schemas } from "../../api/client";
import { ListPage } from "../templates/list-page";
import { Badge, StatusBadge } from "@/components/ui/badge/badge";
import { Card } from "@/components/ui/card/card";
import { type DataTableColumn } from "@/components/ui/data-table/data-table";
import { Time } from "@/components/ui/time/time";
import s from "../../pages/shared.module.css";
import { HealthBadge } from "./badges";
import { failureDetail, failureText, type McpServer, signInRequiredLabel } from "./labels";
import { type ServerScope, healthChecksQuery } from "./scope";
import m from "./servers.module.css";

type Check = Schemas["McpHealthCheck"];

/** "Healthy", "Failing", or "Reachable — requires sign-in" (an oauth server's scheduled check, which uses nobody's token). */
const checkText = (c: Check) => (c.ok ? (c.signInRequired ? signInRequiredLabel : "Healthy") : "Failing");

const triggerLabels: Record<Check["trigger"], string> = { manual: "Manual", scheduled: "Scheduled" };
// Position is historical, not a lookup into today's list: a removed/replaced
// replica must not masquerade as the new endpoint occupying the same position.
const endpointLabel = (c: Check) => c.endpointId ? `Additional endpoint ${c.endpointPosition ?? ""} · ${c.endpointId}` : "Primary";

const columns: DataTableColumn<Check>[] = [
  {
    id: "checkedAt",
    header: "When",
    accessor: (c) => new Date(c.checkedAt),
    rowHeader: true,
    hideable: false,
    cell: (c) => (
      <span className={s.nowrap}>
        <Time value={c.checkedAt} />
      </span>
    ),
  },
  { id: "endpoint", header: "Endpoint", accessor: endpointLabel, cell: endpointLabel },
  { id: "result", header: "Result", accessor: (c) => checkText(c), cell: (c) => <StatusBadge tone={c.ok ? "success" : "danger"}>{checkText(c)}</StatusBadge> },
  { id: "latency", header: "Latency", accessor: (c) => c.latencyMs, numeric: true, cell: (c) => `${c.latencyMs.toLocaleString()} ms` },
  { id: "trigger", header: "Trigger", accessor: (c) => triggerLabels[c.trigger], cell: (c) => <Badge size="sm">{triggerLabels[c.trigger]}</Badge>, defaultHiddenNarrow: true },
  {
    id: "error",
    header: "Error",
    accessor: (c) => (c.ok ? "" : `${failureText(c)} ${failureDetail(c) ?? ""}`),
    cell: (c) => {
      if (c.ok) return <span className={s.muted}>—</span>;
      const detail = failureDetail(c);
      return (
        <span className={m.message}>
          {failureText(c)}
          {detail && <span className={s.secondary}>{detail}</span>}
        </span>
      );
    },
  },
];

export function HealthTab({ server, scope }: { server: McpServer; scope: ServerScope }) {
  const checks = useQuery(healthChecksQuery(scope, server.id));
  return (
    <Card title="Upstream health" description={<HealthBadge health={server.health} />}>
      <ListPage<Check>
        id="server-health"
        caption="Recent checks"
        columns={columns}
        data={checks.data ?? []}
        getRowId={(c) => `${c.checkedAt}:${c.endpointId ?? "primary"}`}
        rowLabel={(c) => `${endpointLabel(c)} ${c.checkedAt}`}
        loading={checks.isLoading}
        error={checks.error}
        onRetry={() => void checks.refetch()}
        empty={{ icon: <Activity />, title: "No checks yet.", description: "The scheduled check, Test and Refresh each add one here." }}
        tableProps={{ columnsMenuMin: 5 }}
      />
    </Card>
  );
}
