/*
 * Keys for servers (decision 72): the servers where each caller enters their
 * own key, with the person's entry for each: not entered, active (its last four
 * characters), or refused by the server (enter it again), whether agents may
 * use it, and when it was last used. On Account › My connections a person
 * enters, replaces, lets their agents use it (or stops that) and removes theirs;
 * in Admin › Users platform admins remove anyone's and auditors read. A key is
 * never shown again, anywhere.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Trash2 } from "lucide-react";
import { useState } from "react";
import { api, unwrap } from "../../api/client";
import { FormDialog } from "../form-dialog";
import { ConfirmMutationDialog } from "../confirm-dialog";
import { keyLabel, hintText, placementText, type ServerSecret } from "../servers/person-secret";
import { ListPage, RelativeTime, timeColumn } from "../templates/list-page";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { StatusBadge } from "@/components/ui/badge/badge";
import { CellText, type DataTableColumn } from "@/components/ui/data-table/data-table";
import { toast } from "@/components/ui/toast/toast";
import s from "../../pages/shared.module.css";
import { describeKeyError, KeyFields, myServerSecretsKey, useKeyForm } from "./key-form";

/** Whose keys: the signed-in person's, or a person's on their admin page. */
export type SecretsOwner = { self: true } | { self: false; userId: string; name: string };

export const serverSecretsKey = (o: SecretsOwner) => (o.self ? myServerSecretsKey : ["admin", "user", o.userId, "server-secrets"]);

export function useServerSecrets(o: SecretsOwner) {
  return useQuery({
    queryKey: serverSecretsKey(o),
    queryFn: async () =>
      o.self ? unwrap(await api.GET("/v1/me/server-secrets")) : unwrap(await api.GET("/v1/admin/users/{userId}/server-secrets", { params: { path: { userId: o.userId } } })),
  });
}

function statusOf(e: ServerSecret): { text: string; tone: "success" | "danger" | "neutral" } {
  if (!e.hasSecret) return { text: "Not entered", tone: "neutral" };
  return e.status === "rejected" ? { text: "Refused: enter it again", tone: "danger" } : { text: "Active", tone: "success" };
}

function columns(self: boolean): DataTableColumn<ServerSecret>[] {
  return [
    {
      id: "server",
      header: "Server",
      accessor: (e) => e.server.name,
      rowHeader: true,
      hideable: false,
      sortable: true,
      cell: (e) => <CellText wrap="anywhere" primary={`${e.server.name}`} secondary={`Team: ${e.server.teamName} · ${e.origin}`} />,
    },
    { id: "sent", header: "Sent as", accessor: (e) => placementText(e.config), defaultHiddenNarrow: true, cell: (e) => <CellText wrap="anywhere" primary={placementText(e.config)} secondary={keyLabel(e.config)} /> },
    { id: "key", header: self ? "Your key" : "Their key", accessor: (e) => hintText(e), cell: (e) => <CellText primary={hintText(e)} /> },
    {
      id: "status",
      header: "Status",
      accessor: (e) => statusOf(e).text,
      sortable: true,
      cell: (e) => <StatusBadge tone={statusOf(e).tone}>{statusOf(e).text}</StatusBadge>,
    },
    {
      ...timeColumn<ServerSecret>("lastUsedAt", "Last used", (e) => e.lastUsedAt),
      defaultHiddenNarrow: true,
      cell: (e) => (e.lastUsedAt ? <span className={s.nowrap}><RelativeTime value={e.lastUsedAt} /></span> : <span className={s.muted}>{e.hasSecret ? "Not used yet" : "—"}</span>),
    },
  ];
}

type Props = { owner: SecretsOwner; canRevoke: boolean };

export function ServerSecrets({ owner, canRevoke }: Props) {
  const qc = useQueryClient();
  const list = useServerSecrets(owner);
  const [entering, setEntering] = useState<string | null>(null);
  const [removing, setRemoving] = useState<ServerSecret | null>(null);
  const entry = list.data?.find((e) => e.server.id === entering);
  const refresh = () => void qc.invalidateQueries({ queryKey: serverSecretsKey(owner) });
  const remove = useMutation({
    mutationFn: async (e: ServerSecret) =>
      owner.self
        ? unwrap(await api.DELETE("/v1/me/server-secrets/{serverId}", { params: { path: { serverId: e.server.id } } }))
        : unwrap(await api.DELETE("/v1/admin/users/{userId}/server-secrets/{serverId}", { params: { path: { userId: owner.userId, serverId: e.server.id } } })),
    onSuccess: (_, e) => {
      setRemoving(null);
      toast.success(`The key for ${e.server.name} was removed`, owner.self ? "Calls to it ask you for a key again." : undefined);
    },
    onSettled: refresh,
  });
  const who = owner.self ? "you" : owner.name;
  return (
    <>
      <ListPage<ServerSecret>
        id={owner.self ? "my-server-secrets" : "admin-user-server-secrets"}
        caption={owner.self ? "Your keys for servers" : `Keys ${owner.name} entered for servers`}
        columns={columns(owner.self)}
        data={list.data ?? []}
        getRowId={(e) => e.server.id}
        rowLabel={(e) => e.server.name}
        loading={list.isLoading}
        error={list.error}
        onRetry={() => void list.refetch()}
        rowActions={(e) => [
          { label: e.hasSecret ? "Replace key…" : "Enter key…", icon: <KeyRound aria-hidden />, hidden: !owner.self || !e.reachable, onSelect: () => setEntering(e.server.id) },
          { label: "Remove key…", icon: <Trash2 aria-hidden />, danger: true, hidden: !canRevoke || !e.hasSecret, onSelect: () => setRemoving(e) },
        ]}
        empty={{
          icon: <KeyRound />,
          title: "No servers want your own key.",
          description: owner.self
            ? "Some servers want each person's own API key. The first time you use one, your AI client shows a link to paste yours here, once. It is stored encrypted, sent only to that server, and never shown again."
            : `Keys ${who} entered for servers that ask each person for their own are listed here, without the keys.`,
        }}
        tableProps={{ columnsMenuMin: 5 }}
      />
      {entry && <KeyDialog entry={entry} onClose={() => setEntering(null)} />}
      <ConfirmMutationDialog
        target={removing}
        onClose={() => setRemoving(null)}
        mutation={remove}
        onConfirm={(e) => remove.mutate(e)}
        title={`Remove ${owner.self ? "your" : `${owner.name}'s`} key for ${removing?.server.name ?? "this server"}?`}
        description={`It is deleted now. Calls to ${removing?.server.name ?? "the server"} ask ${owner.self ? "you" : "them"} for a key again.${owner.self ? "" : " Use this for a leaver or a key that leaked."}`}
        confirmLabel="Remove key"
      />
    </>
  );
}

/** Enter or replace a key from the list. */
function KeyDialog({ entry, onClose }: { entry: ServerSecret; onClose: () => void }) {
  const form = useKeyForm(entry, onClose);
  const described = describeKeyError(form.save.error);
  return (
    <FormDialog
      title={entry.hasSecret ? `Replace your key for ${entry.server.name}` : `Enter your key for ${entry.server.name}`}
      description="Only you can enter it. It is stored encrypted and never shown again."
      onClose={onClose}
      onSubmit={form.submit}
      submitLabel="Save key"
      busy={form.save.isPending}
    >
      <KeyFields entry={entry} form={form} />
      <ErrorAlert error={form.save.error} title={described?.title ?? "Couldn't save the key"} describe={describeKeyError} />
    </FormDialog>
  );
}
