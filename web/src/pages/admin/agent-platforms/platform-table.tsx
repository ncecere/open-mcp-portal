/*
 * The trusted agent platforms as a table: name and issuer, the audience a token must name, whether it is on, how
 * many service accounts relay for it, and its last key fetch (when, whether it worked, and the key IDs it
 * published). Platform admins get a row menu; auditors only read.
 */
import { Pencil, Power, RefreshCw, Trash2, Users } from "lucide-react";
import { plural } from "@/lib/format";
import { ActionMenu } from "@/components/templates/action-menu";
import { RelativeTime } from "@/components/templates/list-page";
import { Badge, StatusBadge } from "@/components/ui/badge/badge";
import { CellText } from "@/components/ui/data-table/data-table";
import { Table, Td, Tr } from "@/components/ui/table/table";
import { switchLabel } from "@/lib/terms";
import s from "../../shared.module.css";
import { type AgentPlatform, fetchErrorLabel } from "./api";

type Props = {
  platforms: AgentPlatform[];
  canEdit: boolean;
  onEdit: (p: AgentPlatform) => void;
  onTest: (p: AgentPlatform) => void;
  onRelays: (p: AgentPlatform) => void;
  onToggle: (p: AgentPlatform) => void;
  onDelete: (p: AgentPlatform) => void;
};

function LastFetch({ p }: { p: AgentPlatform }) {
  if (!p.lastFetch) return <span className={s.muted}>Not fetched yet</span>;
  return (
    <CellText
      primary={
        <span>
          <StatusBadge tone={p.lastFetch.ok ? "success" : "danger"}>{p.lastFetch.ok ? "Keys fetched" : "Fetch failed"}</StatusBadge> <RelativeTime value={p.lastFetch.at} />
        </span>
      }
      secondary={
        p.lastFetch.ok ? (
          p.keyIds.length > 0 ? (
            <span className={s.mono}>{`Key IDs: ${p.keyIds.join(", ")}`}</span>
          ) : undefined
        ) : (
          fetchErrorLabel(p.lastFetch.error)
        )
      }
    />
  );
}

export function PlatformTable({ platforms, canEdit, onEdit, onTest, onRelays, onToggle, onDelete }: Props) {
  return (
    <Table
      caption="Trusted agent platforms"
      columns={["Platform", "Audience", "Status", "Relay accounts", "Keys", ...(canEdit ? [{ label: "", stickyEnd: true }] : [])]}
      stack
      empty={
        platforms.length === 0 ? (
          <p className={s.muted}>{canEdit ? "None: the portal accepts no agent identity tokens. Trust a platform to let its agents act for people." : "None: the portal accepts no agent identity tokens."}</p>
        ) : undefined
      }
    >
      {platforms.map((p) => (
        <Tr key={p.id}>
          <Td>
            <CellText wrap="anywhere" primary={p.name} secondary={<span className={s.mono}>{p.issuer}</span>} />
          </Td>
          <Td>
            <span className={s.mono}>{p.audience}</span>
          </Td>
          <Td>
            <StatusBadge tone={p.enabled ? "success" : "neutral"}>{switchLabel(p.enabled)}</StatusBadge>
          </Td>
          <Td>
            {p.relayCount === 0 ? (
              <Badge tone="warning" title="Nothing can present this platform's tokens until a platform admin marks a service account as its relay.">
                None yet
              </Badge>
            ) : (
              plural(p.relayCount, "account")
            )}
          </Td>
          <Td>
            <LastFetch p={p} />
          </Td>
          {canEdit && (
            <Td stickyEnd>
              <ActionMenu
                label={`Actions for ${p.name}`}
                actions={[
                  { label: "Test the keys", icon: <RefreshCw aria-hidden />, onSelect: () => onTest(p) },
                  { label: "Relay accounts…", icon: <Users aria-hidden />, onSelect: () => onRelays(p) },
                  { label: "Edit…", icon: <Pencil aria-hidden />, onSelect: () => onEdit(p) },
                  { label: p.enabled ? "Turn off" : "Turn on", icon: <Power aria-hidden />, onSelect: () => onToggle(p) },
                  { label: "Stop trusting…", icon: <Trash2 aria-hidden />, danger: true, onSelect: () => onDelete(p) },
                ]}
              />
            </Td>
          )}
        </Tr>
      ))}
    </Table>
  );
}
