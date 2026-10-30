/*
 * The Transfers card of a team's Servers page (decision 88): servers other
 * teams offer this team, which its owner accepts (admins can decline), and
 * servers this team offered, which its owners and admins can withdraw.
 * Nothing is shown to editors and members, or while nothing is waiting.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiError, ifMatch, unwrap } from "../../api/client";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { Time } from "@/components/ui/time/time";
import { toast } from "@/components/ui/toast/toast";
import s from "../../pages/shared.module.css";
import { CancelTransferDialog, type Transfer, transferTexts, transfersKey } from "./transfer-dialogs";
import m from "./servers.module.css";

type Props = { team: string; owner: boolean; manager: boolean };

export function TransfersCard({ team, owner, manager }: Props) {
  const qc = useQueryClient();
  const [closing, setClosing] = useState<{ transfer: Transfer; receiving: boolean } | null>(null);
  const list = useQuery({
    queryKey: [...transfersKey, team],
    enabled: manager,
    queryFn: async () => unwrap(await api.GET("/v1/teams/{team}/mcp-server-transfers", { params: { path: { team }, query: { pendingOnly: true } } })),
  });
  const accept = useMutation({
    mutationFn: async (t: Transfer) =>
      unwrap(await api.POST("/v1/teams/{team}/mcp-server-transfers/{transferId}/accept", { params: { path: { team, transferId: t.id }, header: ifMatch(t.revision) } })),
    onSuccess: (t) => {
      void qc.invalidateQueries({ queryKey: ["team", team] });
      void qc.invalidateQueries({ queryKey: transfersKey });
      toast.success(`${t.serverName} is now this team's`, "It may need a platform review before it is in the catalog again.");
    },
  });
  const pending = list.data ?? [];
  if (!manager || (pending.length === 0 && !list.error)) return null;
  return (
    <Card title="Server transfers" description="Servers offered to this team or by it. Nothing moves until an owner of the receiving team accepts.">
      <div className={m.stack}>
        {list.error && <ErrorAlert error={list.error} title="Couldn't load the transfers" onRetry={() => void list.refetch()} />}
        {accept.error && (
          <ErrorAlert error={accept.error} title="Couldn't accept it" describe={(e) => (e instanceof ApiError && transferTexts[e.code] ? { message: transferTexts[e.code]!, tone: "warning" as const } : undefined)} />
        )}
        <ul className={m.capList} aria-label="Pending server transfers">
          {pending.map((t) => {
            const incoming = t.toTeamSlug === team;
            return (
              <li key={t.id} className={m.inline}>
                <span>
                  <strong>{t.serverName}</strong> {incoming ? `from ${t.fromTeamName}` : `offered to ${t.toTeamName}`}
                  <span className={s.muted}>
                    {" "}
                    · asked <Time value={t.requestedAt} format="date" />
                    {t.requestedByName ? ` by ${t.requestedByName}` : ""}
                    {t.note ? ` · “${t.note}”` : ""}
                  </span>
                </span>
                {incoming && owner && (
                  <Button size="sm" loading={accept.isPending && accept.variables?.id === t.id} onClick={() => accept.mutate(t)}>
                    Accept {t.serverName}
                  </Button>
                )}
                <Button size="sm" variant="secondary" onClick={() => setClosing({ transfer: t, receiving: incoming })}>
                  {incoming ? "Decline" : "Withdraw"}
                </Button>
              </li>
            );
          })}
        </ul>
        {!owner && pending.some((t) => t.toTeamSlug === team) && <p className={s.note}>Only an owner of this team accepts a transfer.</p>}
      </div>
      {closing && (
        <CancelTransferDialog
          team={team}
          serverName={closing.transfer.serverName}
          transfer={closing.transfer}
          receiving={closing.receiving}
          onClose={() => setClosing(null)}
        />
      )}
    </Card>
  );
}
