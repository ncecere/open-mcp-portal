/*
 * A platform gateway's Access tab (Admin): who may use it, as grants to
 * teams, people and SSO groups. Platform admins add and remove them (each
 * removal confirmed); auditors read.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Users } from "lucide-react";
import { useState } from "react";
import { api, unwrap } from "../../api/client";
import { adminGatewaysKey } from "../../api/queries";
import { ScopeBadges } from "../tool-scope";
import { ConfirmMutationDialog } from "../confirm-dialog";
import { ListPage, timeColumn } from "../templates/list-page";
import { Alert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { CellText, type DataTableColumn } from "@/components/ui/data-table/data-table";
import { toast } from "@/components/ui/toast/toast";
import s from "../../pages/shared.module.css";
import { AddGrantDialog, subjectName } from "./add-grant-dialog";
import type { Gateway, GatewayGrant } from "./labels";
import { type GatewayAbilities, grantsQuery } from "./scope";

const kindLabels: Record<GatewayGrant["subjectKind"], string> = { team: "Team", user: "Person", group: "SSO group" };

const detail = (g: GatewayGrant) => (g.subjectKind === "team" ? g.team?.slug : g.subjectKind === "user" ? g.user?.email : undefined);

const columns: DataTableColumn<GatewayGrant>[] = [
  {
    id: "subject",
    header: "Who",
    accessor: subjectName,
    rowHeader: true,
    sortable: true,
    cell: (g) => <CellText primary={g.subjectKind === "group" ? <span className={s.mono}>{subjectName(g)}</span> : subjectName(g)} secondary={detail(g)} />,
  },
  { id: "toolScope", header: "Tool scope", cell: (g) => <ScopeBadges scope={g.toolScope} /> },
  { id: "kind", header: "Kind", accessor: (g) => kindLabels[g.subjectKind], sortable: true },
  { ...timeColumn<GatewayGrant>("createdAt", "Added", (g) => g.createdAt) },
  { id: "expires", header: "Expires", cell: (g) => g.expiresAt ? `${Date.parse(g.expiresAt) <= Date.now() ? "Expired · " : ""}${new Date(g.expiresAt).toLocaleString()}` : "Permanent" },
  { id: "by", header: "Added by", accessor: (g) => g.addedByName ?? "", defaultHiddenNarrow: true, cell: (g) => g.addedByName ?? <span className={s.muted}>—</span> },
];

export const grantsHelp =
  "A team grant covers everyone on the team now, and people who join later. A group grant uses the groups claim your identity provider sends at sign-in, so it follows each person's groups as of their last sign-in. Removing a grant takes effect on the next call.";

export function GatewayAccessTab({ gateway, abilities }: { gateway: Gateway; abilities: GatewayAbilities }) {
  const qc = useQueryClient();
  const grants = useQuery(grantsQuery(gateway.id));
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<GatewayGrant | null>(null);
  const remove = useMutation({
    mutationFn: async (g: GatewayGrant) => unwrap(await api.DELETE("/v1/admin/gateways/{gatewayId}/grants/{grantId}", { params: { path: { gatewayId: gateway.id, grantId: g.id } } })),
    onSuccess: (_, g) => {
      setRemoving(null);
      toast.success("Access removed", `${subjectName(g)} can't use ${gateway.name} from their next call.`);
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: grantsQuery(gateway.id).queryKey });
      void qc.invalidateQueries({ queryKey: adminGatewaysKey });
    },
  });
  const add = abilities.canManageGrants && (
    <Button size="sm" onClick={() => setAdding(true)}>
      <Plus aria-hidden /> Add grant
    </Button>
  );
  return (
    <>
      <Alert tone="info">{grantsHelp} Matching grants are alternatives (class or exact name); independent credential ceilings all apply. Prompts and resources are unaffected.</Alert>
      <Card title="Grants" description="Who may use this gateway. Each person sees only the capabilities it offers." actions={add || undefined}>
        <ListPage<GatewayGrant>
          id="gateway-grants"
          caption="Grants"
          columns={columns}
          data={grants.data ?? []}
          getRowId={(g) => g.id}
          rowLabel={subjectName}
          loading={grants.isLoading}
          error={grants.error}
          onRetry={() => void grants.refetch()}
          rowActions={abilities.canManageGrants ? (g) => [{ label: "Remove…", icon: <Trash2 aria-hidden />, danger: true, onSelect: () => setRemoving(g) }] : undefined}
          empty={{
            icon: <Users />,
            title: "Nobody can use this gateway yet.",
            description: abilities.canManageGrants ? "Grant it to a team, a person or an SSO group." : "Platform admins grant it to teams, people or SSO groups.",
            action: add || undefined,
          }}
          tableProps={{ columnsMenuMin: 5 }}
        />
      </Card>
      {adding && <AddGrantDialog gateway={gateway} onClose={() => setAdding(false)} />}
      <ConfirmMutationDialog
        target={removing}
        onClose={() => setRemoving(null)}
        mutation={remove}
        onConfirm={(g) => remove.mutate(g)}
        title={`Remove access for ${removing ? subjectName(removing) : ""}?`}
        description={
          removing?.subjectKind === "team"
            ? "Its members lose access on their next call, unless another grant covers them."
            : removing?.subjectKind === "group"
              ? "The group's members lose access on their next call, unless another grant covers them."
              : "They lose access on their next call, unless another grant covers them."
        }
        confirmLabel="Remove access"
      />
    </>
  );
}
