/*
 * API keys (/settings/api-keys), from the account menu next to Profile: the
 * person's own keys with their status, last use and expiry (revoked and
 * expired ones stay listed for 30 days). Create shows the secret once
 * (create-key-dialog.tsx); Revoke asks first and takes effect at once.
 * Expiry reads in days ("in 7 days", never "next week"), the exact date as
 * its tooltip; a revoked key has none (its status says so). Gateways says
 * where a key works: all the person's gateways, or the ones it is limited
 * to (a deleted one is marked; a key whose gateways are all gone works
 * nowhere, and the page warns).
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { KeyRound, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import { api, unwrap } from "../../api/client";
import { myApiKeysQuery } from "../../api/queries";
import { ScopeBadges } from "../../components/tool-scope";
import { ConfirmMutationDialog } from "../../components/confirm-dialog";
import type { ApiKey } from "../../components/gateways/labels";
import { ListPage, RelativeTime, timeColumn } from "../../components/templates/list-page";
import { formatDate, toDate } from "../../lib/bitop-format";
import { expiryText } from "../../lib/expiry";
import { useIntent } from "../../lib/intents";
import { terms } from "../../lib/terms";
import { Alert } from "@/components/ui/alert/alert";
import { StatusBadge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { CellText, type DataTableColumn } from "@/components/ui/data-table/data-table";
import type { Facet } from "@/components/ui/filter-bar/filter-bar";
import { TextLink } from "@/components/ui/text-link/text-link";
import { toast } from "@/components/ui/toast/toast";
import s from "../shared.module.css";
import { CreateKeyDialog } from "./create-key-dialog";

const statusLabels: Record<ApiKey["status"], string> = { active: "Active", expired: "Expired", revoked: "Revoked" };
const statusTone = { active: "success", expired: "neutral", revoked: "danger" } as const;

export { expiryText };

function Expiry({ value }: { value: string | null | undefined }) {
  const date = toDate(value);
  if (!date) return <span className={s.muted}>—</span>;
  return (
    <time className={s.nowrap} dateTime={date.toISOString()} title={formatDate(date, { style: "long" })}>
      {expiryText(value)}
    </time>
  );
}

const facets: Facet<ApiKey>[] = [
  {
    id: "status",
    label: "Status",
    type: "toggle",
    allLabel: "All",
    accessor: (k) => k.status,
    options: (["active", "expired", "revoked"] as const).map((v) => ({ value: v, label: statusLabels[v] })),
  },
];

/** A limited key whose gateways are all deleted: it works nowhere. */
export const worksNowhere = (k: ApiKey) => k.gateways.length > 0 && k.gateways.every((g) => !g.exists);

/** "All my gateways", or the gateways a key is limited to. */
export function keyScopeText(k: ApiKey): string {
  if (k.gateways.length === 0) return "All my gateways";
  return k.gateways.map((g) => (g.exists ? g.name : `${g.name} (deleted)`)).join(", ");
}

function KeyScope({ k }: { k: ApiKey }) {
  if (k.gateways.length === 0) return <span className={s.muted}>All my gateways</span>;
  return (
    <span>
      {keyScopeText(k)}
      {worksNowhere(k) && (
        <>
          {" "}
          <StatusBadge tone="warning">Works nowhere</StatusBadge>
        </>
      )}
    </span>
  );
}

const columns: DataTableColumn<ApiKey>[] = [
  { id: "name", header: "Name", accessor: "name", rowHeader: true, hideable: false, sortable: true, cell: (k) => <CellText primary={k.name} secondary={<span className={s.mono}>{k.prefix}…</span>} /> },
  { id: "status", header: "Status", accessor: (k) => statusLabels[k.status], sortable: true, cell: (k) => <StatusBadge tone={statusTone[k.status]}>{statusLabels[k.status]}</StatusBadge> },
  { id: "toolScope", header: "Tool scope", cell: (k) => <ScopeBadges scope={k.toolScope} /> },
  { id: "gateways", header: "Gateways", accessor: (k) => keyScopeText(k), cell: (k) => <KeyScope k={k} /> },
  { ...timeColumn<ApiKey>("lastUsedAt", "Last used", (k) => k.lastUsedAt), cell: (k) => (k.lastUsedAt ? <span className={s.nowrap}><RelativeTime value={k.lastUsedAt} /></span> : <span className={s.muted}>Never</span>) },
  {
    id: "expiresAt",
    header: "Expires",
    accessor: (k) => (k.expiresAt ? new Date(k.expiresAt) : null),
    sortable: true,
    cell: (k) => (k.status === "revoked" ? <span className={s.muted}>—</span> : <Expiry value={k.expiresAt} />),
  },
  { ...timeColumn<ApiKey>("createdAt", "Created", (k) => k.createdAt), defaultHiddenNarrow: true },
];

export function ApiKeysPage() {
  const qc = useQueryClient();
  const keys = useQuery(myApiKeysQuery());
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<ApiKey | null>(null);
  const stranded = (keys.data ?? []).filter((k) => k.status === "active" && worksNowhere(k));
  useIntent("create-api-key", () => setCreating(true));
  const revoke = useMutation({
    mutationFn: async (k: ApiKey) => unwrap(await api.DELETE("/v1/me/api-keys/{keyId}", { params: { path: { keyId: k.id } } })),
    onSuccess: (_, k) => {
      setRevoking(null);
      toast.success(`${k.name} was revoked`);
    },
    onSettled: () => void qc.invalidateQueries({ queryKey: myApiKeysQuery().queryKey }),
  });
  const create = (
    <Button onClick={() => setCreating(true)}>
      <Plus aria-hidden /> Create API key
    </Button>
  );
  return (
    <>
      <ListPage<ApiKey>
        id="my-api-keys"
        title={terms.apiKeys}
        description="Personal keys for MCP clients, agents and scripts. A key acts as you: its tool scope can only restrict your access, never add to it. Prompts and resources are unaffected."
        primaryAction={create}
        notices={
          <>
            {stranded.length > 0 && (
              <Alert tone="warning" title={stranded.length === 1 ? `${stranded[0]!.name} works nowhere` : `${stranded.length} keys work nowhere`}>
                Every gateway {stranded.length === 1 ? "this key is" : "these keys are"} limited to was deleted. Revoke {stranded.length === 1 ? "it" : "them"} and create a new key.
              </Alert>
            )}
            <Alert tone="info">
              Connect a client from <TextLink render={<Link to="/gateways" />}>{terms.myGateways}</TextLink>: each gateway shows the snippets to copy. Claude Code, VS Code
              and Cursor can sign in through your browser instead (<TextLink render={<Link to="/settings/connected-apps" />}>{terms.connectedApps}</TextLink>); keys
              are for clients that can&apos;t, and for your own scripts. For CI and shared automation, use a team&apos;s service account. Keep keys secret, and
              revoke a key you no longer use.
            </Alert>
            <Alert tone="info">Automation (CI) tokens are made by team admins under Team settings.</Alert>
          </>
        }
        caption={terms.apiKeys}
        columns={columns}
        data={keys.data ?? []}
        getRowId={(k) => k.id}
        rowLabel={(k) => k.name}
        facets={facets}
        loading={keys.isLoading}
        error={keys.error}
        onRetry={() => void keys.refetch()}
        rowActions={(k) => [{ label: "Revoke…", icon: <Trash2 aria-hidden />, danger: true, hidden: k.status !== "active", onSelect: () => setRevoking(k) }]}
        empty={{ icon: <KeyRound />, title: "No API keys yet.", description: "Create a key to connect an MCP client such as Claude Code, VS Code or Cursor to a gateway.", action: create }}
        tableProps={{ columnsMenuMin: 6 }}
      />
      {creating && <CreateKeyDialog onClose={() => setCreating(false)} />}
      <ConfirmMutationDialog
        target={revoking}
        onClose={() => setRevoking(null)}
        mutation={revoke}
        onConfirm={(k) => revoke.mutate(k)}
        title={`Revoke ${revoking?.name ?? "key"}?`}
        description="Clients and scripts using this key stop working on their next request. This can't be undone."
        confirmLabel="Revoke key"
      />
    </>
  );
}
