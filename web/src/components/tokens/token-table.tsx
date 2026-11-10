/*
 * The tokens as a table: name (and the start of the token), kind, what it may do, who made it, when it expires (in
 * words, the exact date as its title), when it was last used, and its status. A platform token whose creator is no
 * longer a platform admin is Blocked. Revoked and expired tokens stay listed for 30 days. Never a secret.
 */
import { Trash2 } from "lucide-react";
import { formatDate, toDate } from "../../lib/bitop-format";
import { expiryText } from "../../lib/expiry";
import { ActionMenu } from "../templates/action-menu";
import { RelativeTime } from "../templates/relative-time";
import { Badge, StatusBadge } from "@/components/ui/badge/badge";
import { CellText } from "@/components/ui/data-table/data-table";
import { Table, Td, Tr } from "@/components/ui/table/table";
import s from "../../pages/shared.module.css";
import type { AutomationToken } from "./api";
import { blockedText, displayStatus, kindLabels, kindTone, shownScopes, statusLabels, statusTone } from "./labels";

function Expiry({ t }: { t: AutomationToken }) {
  const date = toDate(t.expiresAt);
  if (t.status === "revoked" || !date) return <span className={s.muted}>—</span>;
  return (
    <time className={s.nowrap} dateTime={date.toISOString()} title={formatDate(date, { style: "long" })}>
      {expiryText(t.expiresAt)}
    </time>
  );
}

type Props = { items: AutomationToken[]; onRevoke?: (t: AutomationToken) => void; empty: string; caption: string };

export function TokenTable({ items, onRevoke, empty, caption }: Props) {
  return (
    <Table
      caption={caption}
      columns={["Name", "Kind", "Can", "Created", "Expires", "Last used", "Status", ...(onRevoke ? [{ label: "", stickyEnd: true }] : [])]}
      stack
      empty={items.length === 0 ? <p className={s.muted}>{empty}</p> : undefined}
    >
      {items.map((t) => {
        const status = displayStatus(t);
        return (
          <Tr key={t.id}>
            <Td>
              <CellText wrap="anywhere" primary={t.name} secondary={<span className={s.mono}>{t.prefix}…</span>} />
            </Td>
            <Td>
              <Badge tone={kindTone[t.kind]}>{kindLabels[t.kind]}</Badge>
            </Td>
            <Td>
              <span className={s.badges}>
                {shownScopes(t).map((sc) => (
                  <Badge key={sc} tone="neutral" title={sc.endsWith(":write") ? "Includes read" : undefined}>
                    {sc}
                  </Badge>
                ))}
              </span>
            </Td>
            <Td>
              <CellText primary={<RelativeTime value={t.createdAt} />} secondary={t.createdByName ?? undefined} />
            </Td>
            <Td>
              <Expiry t={t} />
            </Td>
            <Td nowrap>{t.lastUsedAt ? <RelativeTime value={t.lastUsedAt} /> : <span className={s.muted}>Never</span>}</Td>
            <Td>
              <StatusBadge tone={statusTone[status]}>{statusLabels[status]}</StatusBadge>
              {status === "blocked" && <span className={s.secondary}>{blockedText}</span>}
            </Td>
            {onRevoke && (
              <Td stickyEnd>
                <ActionMenu label={`Actions for ${t.name}`} actions={[{ label: "Revoke…", icon: <Trash2 aria-hidden />, danger: true, hidden: t.status !== "active", onSelect: () => onRevoke(t) }]} />
              </Td>
            )}
          </Tr>
        );
      })}
    </Table>
  );
}
