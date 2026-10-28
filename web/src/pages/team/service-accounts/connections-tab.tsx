import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type Schemas, unwrap } from "../../../api/client";
import { serviceAccountsKey } from "../../../api/queries";
import { ConfirmMutationDialog } from "../../../components/confirm-dialog";
import { redirectTo, safeAuthorizeUrl } from "../../../components/providers/labels";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Badge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import s from "../../../components/servers/servers.module.css";
import { CreateConnection } from "./create-connection";
import { ConnectionEditor } from "./connection-editor";
import type { ServiceAccount, ServiceAccountAbilities } from "./labels";

export const sharedConnectionsKey = (team: string) => ["team", team, "service-connections"];
export type SharedConnection = Schemas["ServiceConnection"];
export function ConnectionsTab({ account, abilities }: { account: ServiceAccount; abilities: ServiceAccountAbilities }) {
  return <TeamConnectionsTab team={account.teamSlug} canManage={abilities.canManage} account={account} />;
}
export function TeamConnectionsTab({ team, canManage, account }: { team: string; canManage: boolean; account?: ServiceAccount }) {
  const qc = useQueryClient();
  const [editing, setEditing] = useState<SharedConnection | null>(null);
  const [revoking, setRevoking] = useState<SharedConnection | null>(null);
  const list = useQuery({
    queryKey: sharedConnectionsKey(team),
    queryFn: async () => unwrap(await api.GET("/v1/teams/{team}/service-connections", { params: { path: { team } } })),
  });
  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: sharedConnectionsKey(team) });
    void qc.invalidateQueries({ queryKey: serviceAccountsKey(team) });
  };
  const revoke = useMutation({
    mutationFn: async (c: SharedConnection) => unwrap(await api.DELETE("/v1/teams/{team}/service-connections/{connectionId}", { params: { path: { team, connectionId: c.id } } })),
    onSuccess: () => { setRevoking(null); invalidate(); },
  });
  const reconnect = useMutation({
    mutationFn: async (c: SharedConnection) => {
      const out = unwrap(await api.POST("/v1/teams/{team}/service-connections/{connectionId}/reconnect", { params: { path: { team, connectionId: c.id }, header: { "If-Match": `"${c.revision}"` } } }));
      const target = safeAuthorizeUrl(out.authorizeUrl);
      if (!target) throw new Error("The provider returned an unsafe authorization address");
      return target;
    },
    onSuccess: (target) => redirectTo.go(target),
    onSettled: invalidate,
  });
  return <div className={s.stack}>
    <Alert tone="info" title="Shared upstream accounts">
      Only explicitly assigned service accounts and allowed servers can use these connections. Calls act as the shared upstream account, which may be an administrator's own account. The connecting person must remain an active owner or admin of this team. Relayed people still use their own connections.
    </Alert>
    {!canManage && <Alert tone="info">Only this team's owners and admins can connect accounts or change access.</Alert>}
    <ErrorAlert error={list.error} title="Couldn't load shared connections" onRetry={() => void list.refetch()} />
    <ErrorAlert error={reconnect.error} title="Couldn't reconnect" />
    {list.isLoading && <p role="status">Loading shared connections…</p>}
    {list.data?.length === 0 && <p>No shared connections yet. A team owner or admin can connect one below.</p>}
    {list.data?.map((c) => <Card key={c.id} title={c.name} description={`${c.providerName} · Shared account: ${c.accountLabel || (c.status === "active" ? "Account label unavailable" : "Not connected yet")}`}>
      <div className={s.stack}>
        <p><Badge tone={c.status === "active" ? "success" : "warning"}>{c.status.replaceAll("_", " ")}</Badge> {account ? (c.accounts.includes(account.id) ? `Assigned to ${account.name}` : `Not assigned to ${account.name}`) : "Team-owned shared connection"}</p>
        <p>Granted scopes: {c.scopes.join(", ") || "None"}</p>
        <p>{c.accounts.length} allowed service accounts · {c.servers.length} allowed servers</p>
        <ul>{c.servers.map((g) => <li key={g.serverId}>{g.origin} · {g.scopes.join(", ") || "No scopes"}</li>)}</ul>
        {canManage && <div className={s.actions}>
          <Button size="sm" variant="secondary" onClick={() => setEditing(c)}>Manage access to {c.name}</Button>
          <Button size="sm" variant="secondary" loading={reconnect.isPending} onClick={() => reconnect.mutate(c)}>Reconnect {c.name}</Button>
          <Button size="sm" variant="secondary" onClick={() => setRevoking(c)}>Revoke {c.name}</Button>
        </div>}
      </div>
    </Card>)}
    {canManage && <CreateConnection team={team} />}
    {editing && <ConnectionEditor key={editing.id} team={team} connection={editing} onClose={() => setEditing((current) => current === editing ? null : current)} />}
    <ConfirmMutationDialog target={revoking} mutation={revoke} onClose={() => setRevoking(null)} title={`Revoke ${revoking?.name ?? "connection"}?`} description="This erases its tokens, assignments, destination grants and pending consent. No service account can use it afterwards." confirmLabel="Revoke connection" onConfirm={(c) => revoke.mutate(c)} />
  </div>;
}
