/*
 * Moving a server to another team (decision 88): the owning team's owners and
 * admins offer it, the receiving team's owner accepts (their own Transfers card
 * on the Servers page), and either side can withdraw or decline. Nothing moves
 * until it is accepted. The server keeps its capabilities, gateway selections,
 * people's grants and sealed values; under approval_required a published server
 * goes back to review, and the accepting owner becomes its owner.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiError, ifMatch, type Schemas, unwrap } from "../../api/client";
import { ConfirmMutationDialog } from "../confirm-dialog";
import { FormDialog } from "../form-dialog";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Field } from "@/components/ui/field/field";
import { Input, Textarea } from "@/components/ui/input/input";
import { toast } from "@/components/ui/toast/toast";
import type { McpServer } from "./labels";
import { invalidateServer } from "./scope";
import m from "./servers.module.css";

export type Transfer = Schemas["ServerTransfer"];

export const transferTexts: Record<string, string> = {
  invalid_team: "Choose another team that exists and isn't archived.",
  transfer_pending: "This server already has a transfer waiting for an answer.",
  provider_not_allowed: "The server requires an auth provider that isn't open to that team. A platform admin adds the team to the provider's access list first.",
  changed_since_request: "The server changed after the transfer was asked for. Ask the owning team to withdraw it and ask again.",
  transfer_closed: "This transfer was already answered or withdrawn.",
  owner_required: "Only an owner of the receiving team accepts a transfer.",
};

const describe = (e: unknown) => (e instanceof ApiError && transferTexts[e.code] ? { message: transferTexts[e.code]!, tone: "warning" as const } : undefined);

export function RequestTransferDialog({ server, onClose }: { server: McpServer; onClose: () => void }) {
  const qc = useQueryClient();
  const [toTeam, setTeam] = useState("");
  const [note, setNote] = useState("");
  const send = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/v1/teams/{team}/mcp-servers/{serverId}/transfer", { params: { path: { team: server.teamSlug, serverId: server.id } }, body: { toTeam: toTeam.trim(), ...(note.trim() ? { note: note.trim() } : {}) } })),
    onSuccess: (t) => {
      invalidateServer(qc, server);
      void qc.invalidateQueries({ queryKey: transfersKey });
      toast.success("Transfer offered", `An owner of ${t.toTeamName} can accept it.`);
      onClose();
    },
  });
  return (
    <FormDialog
      title={`Offer ${server.name} to another team`}
      description="The receiving team's owner accepts first; until then nothing changes. It keeps its capabilities, gateway selections, people's grants and stored credentials. A published server goes back to review where the receiving team needs approval, and you stop managing it."
      onClose={onClose}
      onSubmit={() => toTeam.trim() && send.mutate()}
      submitLabel="Offer server"
      submitDisabled={!toTeam.trim()}
      busy={send.isPending}
    >
      <div className={m.stack}>
        <Field label="Receiving team" description="The team's slug, as it appears in its address.">
          <Input value={toTeam} maxLength={100} autoComplete="off" onChange={(e) => setTeam(e.target.value)} />
        </Field>
        <Field label="Note" labelHint="Optional" description="Shown to the receiving team's owners.">
          <Textarea value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} />
        </Field>
        {send.error && <ErrorAlert error={send.error} title="Couldn't offer the server" describe={describe} />}
      </div>
    </FormDialog>
  );
}

/** Withdraw (the owning team) or decline (the receiving team) a transfer; `team` is the team whose page it is. */
export function CancelTransferDialog({ team, serverName, transfer, onClose, receiving = false }: { team: string; serverName: string; transfer: { id: string; revision: number }; onClose: () => void; receiving?: boolean }) {
  const qc = useQueryClient();
  const [target] = useState<{ ok: true } | null>({ ok: true });
  const cancel = useMutation({
    mutationFn: async () =>
      unwrap(await api.DELETE("/v1/teams/{team}/mcp-server-transfers/{transferId}", { params: { path: { team, transferId: transfer.id }, header: ifMatch(transfer.revision) } })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["team", team] });
      void qc.invalidateQueries({ queryKey: transfersKey });
      toast.success(receiving ? "Transfer declined" : "Transfer withdrawn");
      onClose();
    },
  });
  return (
    <ConfirmMutationDialog
      target={target}
      onClose={onClose}
      mutation={cancel}
      onConfirm={() => cancel.mutate()}
      title={receiving ? `Decline ${serverName}?` : `Withdraw the offer of ${serverName}?`}
      description={receiving ? "The server stays with its team. They can offer it again." : "The server stays with your team."}
      confirmLabel={receiving ? "Decline transfer" : "Withdraw offer"}
      tone="primary"
    />
  );
}

export const transfersKey = ["transfers"];
