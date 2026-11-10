import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { api, unwrap, type Schemas } from "../api/client";
import { membersKey } from "../api/queries";
import { emailProblem } from "../lib/validation";
import s from "../pages/shared.module.css";
import { ConfirmMutationDialog } from "./confirm-dialog";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { RelativeTime } from "@/components/templates/relative-time";
import { Badge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { Dialog, DialogClose } from "@/components/ui/dialog/dialog";
import { Field, Form } from "@/components/ui/field/field";
import { Input, NativeSelect } from "@/components/ui/input/input";
import { Table, TableActions, Td, Tr } from "@/components/ui/table/table";
import { toast } from "@/components/ui/toast/toast";
import { canManage, roleLabels, teamRoles, type TeamRole } from "./roles";

export { membersKey };

/** Why a member can't leave: the last owner has to hand the team over first. */
export function leaveBlockedReason(list: { role: string }[] | undefined, myRole?: string) {
  if (myRole !== "owner" || !list) return undefined;
  return list.filter((m) => m.role === "owner").length <= 1 ? "You're the only owner. Make someone else an owner before you leave." : undefined;
}

export const invitesKey = (team: string) => ["team", team, "invites"];

export { MemberList } from "./member-list";

export function AddMemberDialog({ team, myRole, open, onOpenChange }: { team: string; myRole?: TeamRole; open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const formId = useId();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<TeamRole>("member");
  const [result, setResult] = useState<Schemas["MemberAddResult"] | null>(null);

  const add = useMutation({
    mutationFn: async () => unwrap(await api.POST("/v1/teams/{team}/members", { params: { path: { team } }, body: { email, role } })),
    onSuccess: (r) => {
      setResult(r);
      qc.invalidateQueries({ queryKey: ["team", team] });
    },
  });
  const close = (o: boolean) => {
    onOpenChange(o);
    if (!o) {
      setEmail("");
      setRole("member");
      setResult(null);
      add.reset();
    }
  };
  return (
    <Dialog
      open={open}
      onOpenChange={close}
      title="Add member"
      description="People who have never signed in get an invite. They join the team when they first sign in."
      footer={
        result ? (
          <Button onClick={() => close(false)}>Done</Button>
        ) : (
          <>
            <DialogClose>Cancel</DialogClose>
            <Button type="submit" form={formId} loading={add.isPending}>
              Add member
            </Button>
          </>
        )
      }
    >
      {result ? (
        <Alert tone="success" title={result.status === "added" ? "Member added" : "Invite created"}>
          {result.status === "added"
            ? `${result.member?.user.displayName} was added as ${roleLabels[result.member?.role ?? "member"].toLowerCase()}.`
            : `An invite was created for ${result.invite?.email}. They will join when they sign in.`}
        </Alert>
      ) : (
        <Form
          id={formId}
          onSubmit={(e) => {
            e.preventDefault();
            add.mutate();
          }}
        >
          <Field label="Email address" description="Use the email address they sign in with." validate={(v) => emailProblem(String(v ?? "")) ?? null}>
            <Input type="email" autoComplete="off" value={email} onChange={(e) => setEmail(e.target.value)} />
          </Field>
          <Field label="Role">
            <NativeSelect value={role} onChange={(e) => setRole(e.target.value as TeamRole)}>
              {teamRoles
                .filter((r) => canManage(myRole, "", r))
                .map((r) => (
                  <option key={r} value={r}>
                    {roleLabels[r]}
                  </option>
                ))}
            </NativeSelect>
          </Field>
          <ErrorAlert error={add.error} />
        </Form>
      )}
    </Dialog>
  );
}

type Invite = Schemas["Invite"];

export function InviteList({ team, myRole }: { team: string; myRole?: TeamRole }) {
  const qc = useQueryClient();
  const [revoking, setRevoking] = useState<Invite | null>(null);
  const invites = useQuery({
    queryKey: invitesKey(team),
    queryFn: async () => unwrap(await api.GET("/v1/teams/{team}/invites", { params: { path: { team } } })),
  });
  const revoke = useMutation({
    mutationFn: async (inv: Invite) =>
      unwrap(await api.DELETE("/v1/teams/{team}/invites/{inviteId}", { params: { path: { team, inviteId: inv.id } } })),
    onSuccess: () => {
      setRevoking(null);
      toast.success("Invite revoked");
    },
    onSettled: () => qc.invalidateQueries({ queryKey: invitesKey(team) }),
  });
  if (invites.isLoading) return null;
  if (invites.error) return <ErrorAlert error={invites.error} title="Couldn't load open invites" />;
  const list = invites.data ?? [];
  // Nothing to show: the section collapses.
  if (list.length === 0) return null;
  // No actions column for someone who can't revoke any of them (an auditor).
  const actions = list.some((inv) => canManage(myRole, inv.role));
  return (
    <Card title="Open invites" description="People who were added but haven't signed in yet." flush>
      <Table caption="Open invites" columns={actions ? ["Email", "Role", "Expires", ""] : ["Email", "Role", "Expires"]}>
        {list.map((inv) => (
          <Tr key={inv.id}>
            <Td className={s.primary}>{inv.email}</Td>
            <Td>
              <Badge>{roleLabels[inv.role]}</Badge>
            </Td>
            <Td muted nowrap>
              <RelativeTime value={inv.expiresAt} />
            </Td>
            {actions && (
              <Td>
                <TableActions>
                  {canManage(myRole, inv.role) && (
                    <Button size="sm" variant="ghost" aria-label={`Revoke the invite for ${inv.email}`} onClick={() => setRevoking(inv)}>
                      Revoke
                    </Button>
                  )}
                </TableActions>
              </Td>
            )}
          </Tr>
        ))}
      </Table>
      <ConfirmMutationDialog
        target={revoking}
        onClose={() => setRevoking(null)}
        mutation={revoke}
        onConfirm={(inv) => revoke.mutate(inv)}
        title={`Revoke the invite for ${revoking?.email ?? "this person"}?`}
        description="The invite stops working now. You can invite them again later."
        confirmLabel="Revoke invite"
      />
    </Card>
  );
}
