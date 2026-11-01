/*
 * Group → team role mappings: members of a directory group get a role (admin, editor or member; never owner) in a
 * team. The directory manages only memberships it created; memberships someone added by hand are never changed.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { useId, useState } from "react";
import { api, unwrap } from "../../../api/client";
import { ConfirmMutationDialog } from "../../../components/confirm-dialog";
import { V02ErrorAlert } from "../../../components/errors";
import { ActionMenu } from "../../../components/templates/action-menu";
import { friendly } from "../../../lib/error-wording";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Badge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { Dialog, DialogClose } from "@/components/ui/dialog/dialog";
import { Field, Form } from "@/components/ui/field/field";
import { NativeSelect } from "@/components/ui/input/input";
import { Loading } from "@/components/ui/spinner/spinner";
import { Table, Td, Tr } from "@/components/ui/table/table";
import { toast } from "@/components/ui/toast/toast";
import s from "../../shared.module.css";
import { type Mapping, createMapping, deleteMapping, groupsQuery, mappingsQuery, provisioningKey } from "./api";

const roles = ["member", "editor", "admin"] as const;

export function MappingsCard({ canEdit }: { canEdit: boolean }) {
  const qc = useQueryClient();
  const list = useQuery(mappingsQuery);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<Mapping | null>(null);
  const remove = useMutation({
    mutationFn: deleteMapping,
    onSuccess: () => (setRemoving(null), toast.success("Mapping removed")),
    onSettled: () => void qc.invalidateQueries({ queryKey: provisioningKey }),
  });
  const items = list.data ?? [];
  return (
    <Card
      title="Group mappings"
      description="Members of a directory group get a team role. Gateway grants to SSO groups are separate: they use the groups from single sign-on."
      actions={
        canEdit ? (
          <Button size="sm" onClick={() => setAdding(true)}>
            <Plus aria-hidden /> Map a group
          </Button>
        ) : undefined
      }
    >
      {list.isLoading ? (
        <Loading label="Loading mappings…" />
      ) : list.error ? (
        <ErrorAlert error={list.error} title="Couldn't load the mappings" onRetry={() => void list.refetch()} />
      ) : (
        <Table caption="Group mappings" columns={["Group", "Team", "Role", "Members", ...(canEdit ? [{ label: "", stickyEnd: true }] : [])]} stack
          empty={items.length === 0 ? <p className={s.muted}>No mappings: directory groups don&apos;t grant team roles yet.</p> : undefined}>
          {items.map((m) => (
            <Tr key={m.id}>
              <Td>{m.groupName}</Td>
              <Td>{m.teamName}</Td>
              <Td>
                <Badge tone="neutral">{m.role}</Badge>
              </Td>
              <Td>{m.memberCount}</Td>
              {canEdit && (
                <Td stickyEnd>
                  <ActionMenu label={`Actions for ${m.groupName} in ${m.teamName}`} actions={[{ label: "Remove…", icon: <Trash2 aria-hidden />, danger: true, onSelect: () => setRemoving(m) }]} />
                </Td>
              )}
            </Tr>
          ))}
        </Table>
      )}
      {adding && <AddDialog onClose={() => setAdding(false)} />}
      <ConfirmMutationDialog
        target={removing}
        onClose={() => setRemoving(null)}
        mutation={{ ...remove, error: friendly(remove.error) }}
        onConfirm={(m) => remove.mutate(m)}
        title={`Remove the mapping of ${removing?.groupName ?? "this group"}?`}
        description="Members lose the team membership only this mapping gave them. Memberships added by hand stay."
        confirmLabel="Remove mapping"
      />
    </Card>
  );
}

function AddDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const formId = useId();
  const groups = useQuery(groupsQuery);
  const teams = useQuery({ queryKey: ["admin", "teams", "for-mapping"], queryFn: async () => unwrap(await api.GET("/v1/admin/teams", { params: { query: { limit: 200, status: "active" } } })) });
  const [group, setGroup] = useState("");
  const [team, setTeam] = useState("");
  const [role, setRole] = useState<(typeof roles)[number]>("member");
  const add = useMutation({
    mutationFn: () => createMapping({ groupId: group, teamId: team, role }),
    onSuccess: () => {
      toast.success("Group mapped");
      onClose();
    },
    onSettled: () => void qc.invalidateQueries({ queryKey: provisioningKey }),
  });
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title="Map a directory group"
      description="Applied to the group's linked members at once, and kept in step as the directory changes the group."
      footer={
        <>
          <DialogClose>Cancel</DialogClose>
          <Button type="submit" form={formId} loading={add.isPending} disabled={!group || !team}>
            Map group
          </Button>
        </>
      }
    >
      {groups.isLoading || teams.isLoading ? (
        <Loading label="Loading groups and teams…" />
      ) : (
        <Form id={formId} onSubmit={(e) => (e.preventDefault(), add.mutate())}>
          <Field label="Directory group">
            <NativeSelect value={group} onChange={(e) => setGroup(e.target.value)}>
              <option value="">Choose a group</option>
              {(groups.data ?? []).map((g) => (
                <option key={g.id} value={g.id}>
                  {g.displayName} ({g.memberCount})
                </option>
              ))}
            </NativeSelect>
          </Field>
          <Field label="Team">
            <NativeSelect value={team} onChange={(e) => setTeam(e.target.value)}>
              <option value="">Choose a team</option>
              {(teams.data?.items ?? []).map(({ team: t }) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </NativeSelect>
          </Field>
          <Field label="Role" description="Never owner: team owners aren't directory managed.">
            <NativeSelect value={role} onChange={(e) => setRole(e.target.value as (typeof roles)[number])}>
              {roles.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </NativeSelect>
          </Field>
          <V02ErrorAlert error={add.error} title="Couldn't map the group" />
        </Form>
      )}
    </Dialog>
  );
}
