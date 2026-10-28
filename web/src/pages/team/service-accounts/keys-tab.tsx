/*
 * A service account's Keys: every key with its status, where it works, last
 * use and expiry (revoked and expired ones stay listed for 30 days). At most
 * two are active, so a key can be rotated without downtime: create the new
 * one, deploy it, revoke the old one. Create shows the secret once
 * (create-key-dialog.tsx); Revoke asks first and takes effect on the next
 * request. Owners, admins and platform staff see the keys; members are told
 * who can. A turned-off account is explained once, above the tabs (record.tsx);
 * here Create key is off, with the reason as its title.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Lock, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { api, unwrap } from "../../../api/client";
import { serviceAccountsKey } from "../../../api/queries";
import { ScopeBadges, scopeInheritance } from "../../../components/tool-scope";
import { ConfirmMutationDialog } from "../../../components/confirm-dialog";
import { ListPage, RelativeTime, timeColumn } from "../../../components/templates/list-page";
import { formatDate, toDate } from "../../../lib/bitop-format";
import { expiryText } from "../../../lib/expiry";
import { Alert } from "@/components/ui/alert/alert";
import { StatusBadge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { CellText, type DataTableColumn } from "@/components/ui/data-table/data-table";
import { EmptyState } from "@/components/ui/empty-state/empty-state";
import { toast } from "@/components/ui/toast/toast";
import s from "../../shared.module.css";
import { CreateKeyDialog } from "./create-key-dialog";
import {
  keyScopeText,
  keysQuery,
  keyStatusLabels,
  keyStatusTone,
  maxActiveKeys,
  rotationSteps,
  type ServiceAccount,
  type ServiceAccountAbilities,
  type ServiceAccountKey,
} from "./labels";

type Props = { account: ServiceAccount; abilities: ServiceAccountAbilities };

function Expiry({ k }: { k: ServiceAccountKey }) {
  const date = toDate(k.expiresAt);
  if (k.status === "revoked" || !date) return <span className={s.muted}>—</span>;
  return (
    <time className={s.nowrap} dateTime={date.toISOString()} title={formatDate(date, { style: "long" })}>
      {expiryText(k.expiresAt)}
    </time>
  );
}

const columns: DataTableColumn<ServiceAccountKey>[] = [
  { id: "name", header: "Name", accessor: "name", rowHeader: true, hideable: false, sortable: true, cell: (k) => <CellText primary={k.name} secondary={<span className={s.mono}>{k.prefix}…</span>} /> },
  { id: "status", header: "Status", accessor: (k) => keyStatusLabels[k.status], sortable: true, cell: (k) => <StatusBadge tone={keyStatusTone[k.status]}>{keyStatusLabels[k.status]}</StatusBadge> },
  { id: "toolScope", header: "Tool scope", cell: (k) => <ScopeBadges scope={k.toolScope} /> },
  { id: "gateways", header: "Gateways", accessor: (k) => keyScopeText(k), cell: (k) => <span className={k.gateways.length === 0 ? s.muted : undefined}>{keyScopeText(k)}</span> },
  { ...timeColumn<ServiceAccountKey>("lastUsedAt", "Last used", (k) => k.lastUsedAt), cell: (k) => (k.lastUsedAt ? <span className={s.nowrap}><RelativeTime value={k.lastUsedAt} /></span> : <span className={s.muted}>Never</span>) },
  { id: "expiresAt", header: "Expires", accessor: (k) => new Date(k.expiresAt), sortable: true, cell: (k) => <Expiry k={k} /> },
  { ...timeColumn<ServiceAccountKey>("createdAt", "Created", (k) => k.createdAt), cell: (k) => <CellText primary={<RelativeTime value={k.createdAt} />} secondary={k.createdByName ?? undefined} />, defaultHiddenNarrow: true },
];

/** Why Create key can't run now, or undefined. */
export function createKeyBlocked(account: ServiceAccount, active: number): string | undefined {
  if (account.retired) return "Permanently retired. Create a new ordinary service account and key.";
  if (!account.enabled) return "The account is turned off. Turn it on in Settings to create a key.";
  if (active >= maxActiveKeys) return `It already has ${maxActiveKeys} active keys, the most it can have. Revoke the old one once the new one is deployed.`;
  return undefined;
}

export function KeysTab({ account, abilities }: Props) {
  if (!abilities.canReadKeys) {
    return (
      <Card>
        <EmptyState icon={<Lock />} title="Only the team's owners and admins see this account's keys." description="Ask an owner or admin of the team if you need a key for it, or need one rotated." />
      </Card>
    );
  }
  return <KeyList account={account} canManage={abilities.canManage} />;
}

function KeyList({ account, canManage }: { account: ServiceAccount; canManage: boolean }) {
  const qc = useQueryClient();
  const keys = useQuery(keysQuery(account.teamSlug, account.id));
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<ServiceAccountKey | null>(null);
  const active = (keys.data ?? []).filter((k) => k.status === "active");
  // The list when it has loaded; the account's count before that.
  const activeCount = keys.data ? active.length : account.activeKeyCount;
  const blocked = createKeyBlocked(account, activeCount);
  const revoke = useMutation({
    mutationFn: async (k: ServiceAccountKey) =>
      unwrap(await api.DELETE("/v1/teams/{team}/service-accounts/{serviceAccountId}/keys/{keyId}", { params: { path: { team: account.teamSlug, serviceAccountId: account.id, keyId: k.id } } })),
    onSuccess: (_, k) => {
      setRevoking(null);
      toast.success(`${k.name} was revoked`);
    },
    onSettled: () => void qc.invalidateQueries({ queryKey: serviceAccountsKey(account.teamSlug) }),
  });
  const create = canManage && (
    <Button size="sm" disabled={Boolean(blocked)} title={blocked} onClick={() => setCreating(true)}>
      <Plus aria-hidden /> Create key
    </Button>
  );
  const onlyActive = revoking?.status === "active" && active.length === 1;
  return (
    <>
      <Alert tone="info" title="Account tool ceiling">
        <ScopeBadges scope={account.toolScope} />
        {scopeInheritance} Keys may store Everything under a restricted account; they inherit its live ceiling.
      </Alert>
      {activeCount >= maxActiveKeys ? (
        <Alert tone="warning" title={`${maxActiveKeys} active keys: the most it can have`}>
          {canManage ? `Once the newer key is deployed everywhere, revoke the older one; then you can create another. ${rotationSteps}` : rotationSteps}
        </Alert>
      ) : (
        <Alert tone="info">{`A service account can have at most ${maxActiveKeys} active keys. ${rotationSteps} Keys always expire, after at most 365 days.`}</Alert>
      )}
      <ListPage<ServiceAccountKey>
        id="service-account-keys"
        caption={`Keys of ${account.name}`}
        columns={columns}
        data={keys.data ?? []}
        getRowId={(k) => k.id}
        rowLabel={(k) => k.name}
        loading={keys.isLoading}
        error={keys.error}
        onRetry={() => void keys.refetch()}
        rowActions={canManage ? (k) => [{ label: "Revoke…", icon: <Trash2 aria-hidden />, danger: true, hidden: k.status !== "active", onSelect: () => setRevoking(k) }] : undefined}
        // Create key sits in the toolbar, which shows with an empty list too.
        empty={{ icon: <KeyRound />, title: "No keys yet.", description: "Create a key and store it in the CI system, script or agent that uses this account." }}
        tableProps={{ toolbar: create || undefined, columnsMenuMin: 6 }}
      />
      {creating && <CreateKeyDialog account={account} activeCount={activeCount} onClose={() => setCreating(false)} />}
      <ConfirmMutationDialog
        target={revoking}
        onClose={() => setRevoking(null)}
        mutation={revoke}
        onConfirm={(k) => revoke.mutate(k)}
        title={`Revoke ${revoking?.name ?? "key"}?`}
        description={
          onlyActive
            ? `It's the only active key of ${account.name}: whatever uses it stops working on its next request. This can't be undone.`
            : "Whatever uses it stops working on its next request. Make sure the newer key is deployed first. This can't be undone."
        }
        confirmLabel="Revoke key"
      />
    </>
  );
}
