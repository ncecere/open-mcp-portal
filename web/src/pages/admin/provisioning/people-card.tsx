/*
 * Provisioned people: each SCIM account with who it is linked to, or the existing person an admin can adopt (same
 * sign-in subject); and the people under directory control, with their manual and directory standing. Adopting
 * also re-enrolls someone deleted from the directory, once their clean-up is done. Unlinking returns someone to
 * manual control.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { friendly } from "../../../lib/error-wording";
import { ConfirmMutationDialog } from "../../../components/confirm-dialog";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Badge, StatusBadge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { CellText } from "@/components/ui/data-table/data-table";
import { Stack } from "@/components/ui/layout/layout";
import { Loading } from "@/components/ui/spinner/spinner";
import { Table, Td, Tr } from "@/components/ui/table/table";
import { toast } from "@/components/ui/toast/toast";
import s from "../../shared.module.css";
import { type ManagedPerson, type ProvisionedUser, adopt, provisioningKey, reasonText, standingLabels, unlink, usersQuery } from "./api";

const standingTone = { none: "neutral", active: "success", inactive: "warning", deleted: "danger" } as const;

function LinkCell({ u, canEdit, onAdopt }: { u: ProvisionedUser; canEdit: boolean; onAdopt: (u: ProvisionedUser) => void }) {
  if (u.linked) return <CellText primary={u.linked.email} secondary={standingLabels[u.linked.directoryStanding]} />;
  if (!u.candidate) return <span className={s.muted}>Enrolls on first sign-in</span>;
  if (!u.candidate.adoptable) {
    return <CellText primary={u.candidate.email} secondary={u.candidate.reason ? reasonText[u.candidate.reason] : undefined} />;
  }
  return (
    <span className={s.badges}>
      <span>{u.candidate.email}</span>
      {canEdit && (
        <Button size="sm" variant="secondary" onClick={() => onAdopt(u)}>
          Adopt
        </Button>
      )}
    </span>
  );
}

export function PeopleCard({ canEdit }: { canEdit: boolean }) {
  const qc = useQueryClient();
  const list = useQuery(usersQuery);
  const [adopting, setAdopting] = useState<ProvisionedUser | null>(null);
  const [unlinking, setUnlinking] = useState<ManagedPerson | null>(null);
  const done = { onSettled: () => void qc.invalidateQueries({ queryKey: provisioningKey }) };
  const adoptM = useMutation({ mutationFn: adopt, ...done, onSuccess: () => (setAdopting(null), toast.success("Now directory managed")) });
  const unlinkM = useMutation({ mutationFn: unlink, ...done, onSuccess: () => (setUnlinking(null), toast.success("Returned to manual control")) });
  if (list.isLoading) return <Loading label="Loading provisioned people…" />;
  if (list.error) return <ErrorAlert error={list.error} title="Couldn't load provisioned people" onRetry={() => void list.refetch()} />;
  const data = list.data!;
  return (
    <>
      <Card title="Provisioned accounts" description="Accounts the identity provider pushed. An account links to someone when its externalId is their sign-in subject.">
        <Stack gap={4}>
          {data.truncated && <Alert tone="info">Only the first 500 accounts are listed. The identity provider has the full list.</Alert>}
          <Table caption="Provisioned accounts" columns={["Account", "externalId", "Directory", "Portal person"]} stack
            empty={data.resources.length === 0 ? <p className={s.muted}>The identity provider hasn&apos;t pushed anyone yet.</p> : undefined}>
            {data.resources.map((u) => (
              <Tr key={u.id}>
                <Td>
                  <CellText primary={u.userName} secondary={u.displayName || undefined} />
                </Td>
                <Td>{u.externalId ? <span className={s.mono}>{u.externalId}</span> : <span className={s.muted}>None</span>}</Td>
                <Td>
                  <StatusBadge tone={u.active ? "success" : "warning"}>{u.active ? "Active" : "Deactivated"}</StatusBadge>
                </Td>
                <Td>
                  <LinkCell u={u} canEdit={canEdit} onAdopt={setAdopting} />
                </Td>
              </Tr>
            ))}
          </Table>
        </Stack>
      </Card>
      <Card title="Directory-managed people" description="Manual and directory standing are separate: lifting one never lifts the other.">
        <Table caption="Directory-managed people" columns={["Person", "Status", "Directory", "Manual", ...(canEdit ? [{ label: "", stickyEnd: true }] : [])]} stack
          empty={data.people.length === 0 ? <p className={s.muted}>Nobody is directory managed yet.</p> : undefined}>
          {data.people.map((p) => (
            <Tr key={p.id}>
              <Td>
                <CellText primary={p.email} secondary={p.displayName || undefined} />
              </Td>
              <Td>
                <StatusBadge tone={p.status === "active" ? "success" : "warning"}>{p.status === "active" ? "Active" : "Suspended"}</StatusBadge>
              </Td>
              <Td>
                <Badge tone={standingTone[p.directoryStanding]}>{standingLabels[p.directoryStanding]}</Badge>
                {p.cleanupPending && <span className={s.secondary}>Clean-up in progress</span>}
              </Td>
              <Td>{p.manualStatus === "active" ? "Active" : "Suspended"}</Td>
              {canEdit && (
                <Td stickyEnd>
                  {!p.cleanupPending && (
                    <Button size="sm" variant="secondary" onClick={() => setUnlinking(p)}>
                      Unlink
                    </Button>
                  )}
                </Td>
              )}
            </Tr>
          ))}
        </Table>
      </Card>
      <ConfirmMutationDialog
        target={adopting}
        onClose={() => setAdopting(null)}
        mutation={{ ...adoptM, error: friendly(adoptM.error) }}
        onConfirm={(u) => adoptM.mutate(u)}
        title={`Put ${adopting?.candidate?.email ?? "this person"} under directory control?`}
        description="From now on the identity provider can deactivate and delete them, and its group mappings apply. Memberships someone added by hand stay as they are."
        confirmLabel="Adopt"
      />
      <ConfirmMutationDialog
        target={unlinking}
        onClose={() => setUnlinking(null)}
        mutation={{ ...unlinkM, error: friendly(unlinkM.error) }}
        onConfirm={(p) => unlinkM.mutate(p)}
        title={`Return ${unlinking?.email ?? "this person"} to manual control?`}
        description="Only their manual status applies afterwards, and memberships the directory created become manual. The identity provider can no longer deactivate them."
        confirmLabel="Unlink"
      />
    </>
  );
}
