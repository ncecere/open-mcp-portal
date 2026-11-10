/* One entry of the platform audit log in a RecordPage: who, what, when, the target and what changed, field by field in plain words. */
import { useQuery } from "@tanstack/react-query";
import { api, unwrap, type Schemas } from "@/api/client";
import { actionLabel } from "@/components/audit/labels";
import { actedHow, actorName } from "@/components/audit/actors";
import { AuditTeam, auditSections } from "@/components/audit/record";
import { AuditTarget } from "@/components/audit/target";
import { RecordPage } from "@/components/templates/record-page";
import { Time } from "@/components/ui/time/time";
import s from "../../shared.module.css";

type Entry = Schemas["AuditEntry"];

/** `id` is the open entry (?record=); `listed` is it from the loaded list, if there. Otherwise it's fetched by id. */
type Props = { id: string | undefined; listed: Entry | undefined; onClose: () => void };

export function AuditEntryPage({ id, listed, onClose }: Props) {
  const open = Boolean(id);
  const fetched = useQuery({
    queryKey: ["admin", "audit", "entry", id],
    queryFn: async () => unwrap(await api.GET("/v1/admin/audit/{entryId}", { params: { path: { entryId: Number(id) } } })),
    enabled: open && !listed && /^\d+$/.test(id ?? ""),
    retry: false,
  });
  const entry = listed ?? fetched.data;
  const missing = open && !entry && (fetched.isError || !/^\d+$/.test(id ?? ""));
  return (
    <RecordPage
      open={open}
      onClose={onClose}
      title={entry ? actionLabel(entry.action, entry) : "Audit entry"}
      description="One entry of the platform audit log."
      loading={!entry && !missing}
      error={missing ? new Error("This audit entry doesn't exist, or the link is wrong.") : undefined}
      facts={
        entry
          ? [
              { label: "When", value: <Time value={entry.occurredAt} format="datetime" /> },
              { label: "Who", value: entry.actor.email && entry.actor.displayName ? `${actorName(entry.actor, entry)} (${entry.actor.email})` : actorName(entry.actor, entry) },
              ...(actedHow(entry) ? [{ label: "How", value: actedHow(entry) }] : []),
              ...(entry.clientIp ? [{ label: "Address", value: <code className={s.mono}>{entry.clientIp}</code> }] : []),
              ...(entry.teamId ? [{ label: "Team", value: <AuditTeam entry={entry} /> }] : []),
              { label: "Action", value: <code className={s.mono}>{entry.action}</code> },
              { label: "Target", value: <AuditTarget entry={entry} scope={{ kind: "platform" }} /> },
              { label: "Request ID", value: <code className={s.mono}>{entry.requestId || "—"}</code> },
            ]
          : []
      }
      sections={entry ? auditSections(entry) : []}
    />
  );
}
