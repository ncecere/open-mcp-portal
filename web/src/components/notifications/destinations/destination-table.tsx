/*
 * The destinations as a table: name (format, host), events, health, an on/off switch and a row menu. Managers get
 * the switch and the menu (Send test, Delivery log, Change, Rotate secret, Delete); readers see the state and the log.
 */
import { History, KeyRound, Pencil, Send, Trash2 } from "lucide-react";
import { ActionMenu, type ActionItem } from "../../templates/action-menu";
import { RelativeTime } from "../../templates/relative-time";
import { Badge, StatusBadge } from "@/components/ui/badge/badge";
import { CellText } from "@/components/ui/data-table/data-table";
import { Switch } from "@/components/ui/switch/switch";
import { Table, Td, Tr } from "@/components/ui/table/table";
import s from "../../../pages/shared.module.css";
import { eventLabel } from "../events";
import type { Destination } from "./api";
import { errorClassText, formatLabels, stoppedByFailures } from "./labels";

export type RowHandlers = {
  onToggle: (d: Destination, enabled: boolean) => void;
  onTest: (d: Destination) => void;
  onLog: (d: Destination) => void;
  onEdit: (d: Destination) => void;
  onRotate: (d: Destination) => void;
  onDelete: (d: Destination) => void;
  /** The destination whose switch is saving. */
  toggling?: string;
};

function Health({ d }: { d: Destination }) {
  if (stoppedByFailures(d)) return <StatusBadge tone="danger">Stopped: repeated failures</StatusBadge>;
  if (!d.enabled) return <StatusBadge tone="neutral">Off</StatusBadge>;
  const h = d.health;
  if (h.state === "failing") {
    return (
      <>
        <StatusBadge tone="danger">Failing</StatusBadge>
        <span className={s.secondary}>
          {h.consecutiveFailures} in a row{h.lastErrorClass ? `: ${errorClassText(h.lastErrorClass)}` : ""}
        </span>
      </>
    );
  }
  if (h.state === "ok") {
    return (
      <>
        <StatusBadge tone="success">Healthy</StatusBadge>
        {h.lastSuccessAt && (
          <span className={s.secondary}>
            Last delivered <RelativeTime value={h.lastSuccessAt} />
          </span>
        )}
      </>
    );
  }
  return <StatusBadge tone="neutral">Nothing sent yet</StatusBadge>;
}

function actions(d: Destination, h: RowHandlers, canManage: boolean): ActionItem[] {
  const log = { label: "Delivery log", icon: <History aria-hidden />, onSelect: () => h.onLog(d) };
  if (!canManage) return [log];
  return [
    { label: "Send test…", icon: <Send aria-hidden />, onSelect: () => h.onTest(d) },
    log,
    { label: "Change…", icon: <Pencil aria-hidden />, onSelect: () => h.onEdit(d) },
    { label: "Rotate secret…", icon: <KeyRound aria-hidden />, hidden: d.format !== "json", onSelect: () => h.onRotate(d) },
    { label: "Delete…", icon: <Trash2 aria-hidden />, danger: true, onSelect: () => h.onDelete(d) },
  ];
}

export function DestinationTable({ items, canManage, handlers, empty }: { items: Destination[]; canManage: boolean; handlers: RowHandlers; empty: string }) {
  return (
    <Table
      caption="Webhook destinations"
      columns={["Destination", "Events", "Health", "On", { label: "", stickyEnd: true }]}
      stack
      empty={items.length === 0 ? <p className={s.muted}>{empty}</p> : undefined}
    >
      {items.map((d) => (
        <Tr key={d.id}>
          <Td>
            <CellText wrap="anywhere" primary={d.name} secondary={`${d.urlDisplay}`} />
            <span className={s.badges}>
              <Badge tone="neutral">{formatLabels[d.format]}</Badge>
              {d.teamEvents && <Badge tone="info">Every team&apos;s events</Badge>}
              {d.previousSecretExpiresAt && new Date(d.previousSecretExpiresAt) > new Date() && <Badge tone="warning">Two secrets signing</Badge>}
            </span>
          </Td>
          <Td>
            <span title={d.events.map(eventLabel).join(", ")}>{d.events.length === 1 ? eventLabel(d.events[0]!) : `${d.events.length} events`}</span>
          </Td>
          <Td>
            <Health d={d} />
          </Td>
          <Td nowrap>
            {canManage ? (
              <Switch
                label={<span className="sr-only">{`${d.name} enabled`}</span>}
                checked={d.enabled}
                disabled={handlers.toggling === d.id}
                onCheckedChange={(on) => handlers.onToggle(d, on)}
              />
            ) : (
              <span>{d.enabled ? "Enabled" : "Disabled"}</span>
            )}
          </Td>
          <Td stickyEnd>
            <ActionMenu label={`Actions for ${d.name}`} actions={actions(d, handlers, canManage)} />
          </Td>
        </Tr>
      ))}
    </Table>
  );
}
