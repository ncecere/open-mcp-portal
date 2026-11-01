/*
 * Provisioning tokens (ompscim_…): the identity provider's bearer credential for /scim/v2 only. Created and revoked
 * here by platform admins; the secret is shown once. They belong to the directory, not to the admin who made them.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { useId, useState } from "react";
import { friendly } from "../../../lib/error-wording";
import { ConfirmMutationDialog } from "../../../components/confirm-dialog";
import { V02ErrorAlert } from "../../../components/errors";
import { ActionMenu } from "../../../components/templates/action-menu";
import { RelativeTime } from "../../../components/templates/list-page";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { StatusBadge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { CopyField } from "@/components/ui/copy-field/copy-field";
import { CellText } from "@/components/ui/data-table/data-table";
import { Dialog, DialogClose } from "@/components/ui/dialog/dialog";
import { Field, Form } from "@/components/ui/field/field";
import { Input } from "@/components/ui/input/input";
import { Stack } from "@/components/ui/layout/layout";
import { NumberInput } from "@/components/ui/number-input/number-input";
import { Loading } from "@/components/ui/spinner/spinner";
import { Table, Td, Tr } from "@/components/ui/table/table";
import { toast } from "@/components/ui/toast/toast";
import s from "../../shared.module.css";
import { type ProvisioningToken, createToken, provisioningKey, revokeToken, tokensQuery } from "./api";

const maxActive = 5;
const tone = { active: "success", expired: "neutral", revoked: "neutral" } as const;
const label = { active: "Active", expired: "Expired", revoked: "Revoked" } as const;

export function TokensCard({ canEdit }: { canEdit: boolean }) {
  const qc = useQueryClient();
  const list = useQuery(tokensQuery);
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<ProvisioningToken | null>(null);
  const items = list.data ?? [];
  const full = items.filter((t) => t.status === "active").length >= maxActive;
  const revoke = useMutation({
    mutationFn: revokeToken,
    onSuccess: (_, t) => {
      setRevoking(null);
      toast.success(`${t.name} was revoked`);
    },
    onSettled: () => void qc.invalidateQueries({ queryKey: provisioningKey }),
  });
  return (
    <Card
      title="Provisioning tokens"
      description="The identity provider sends one as a bearer token to the SCIM base URL. It works there only, never on the API or an MCP gateway."
      actions={
        canEdit ? (
          <Button size="sm" disabled={full} title={full ? `${maxActive} tokens are active, the most there can be.` : undefined} onClick={() => setCreating(true)}>
            <Plus aria-hidden /> Create token
          </Button>
        ) : undefined
      }
    >
      {list.isLoading ? (
        <Loading label="Loading tokens…" />
      ) : list.error ? (
        <ErrorAlert error={list.error} title="Couldn't load the tokens" onRetry={() => void list.refetch()} />
      ) : (
        <Table caption="Provisioning tokens" columns={["Name", "Created", "Expires", "Last used", "Status", ...(canEdit ? [{ label: "", stickyEnd: true }] : [])]} stack
          empty={items.length === 0 ? <p className={s.muted}>No tokens yet.</p> : undefined}>
          {items.map((t) => (
            <Tr key={t.id}>
              <Td>
                <CellText primary={t.name} secondary={<span className={s.mono}>{t.prefix}…</span>} />
              </Td>
              <Td>
                <CellText primary={<RelativeTime value={t.createdAt} />} secondary={t.createdByName ?? undefined} />
              </Td>
              <Td nowrap>{t.status === "revoked" ? <span className={s.muted}>—</span> : <RelativeTime value={t.expiresAt} />}</Td>
              <Td nowrap>{t.lastUsedAt ? <RelativeTime value={t.lastUsedAt} /> : <span className={s.muted}>Never</span>}</Td>
              <Td>
                <StatusBadge tone={tone[t.status]}>{label[t.status]}</StatusBadge>
              </Td>
              {canEdit && (
                <Td stickyEnd>
                  <ActionMenu label={`Actions for ${t.name}`} actions={[{ label: "Revoke…", icon: <Trash2 aria-hidden />, danger: true, hidden: t.status !== "active", onSelect: () => setRevoking(t) }]} />
                </Td>
              )}
            </Tr>
          ))}
        </Table>
      )}
      {creating && <CreateDialog onClose={() => setCreating(false)} />}
      <ConfirmMutationDialog
        target={revoking}
        onClose={() => setRevoking(null)}
        mutation={{ ...revoke, error: friendly(revoke.error) }}
        onConfirm={(t) => revoke.mutate(t)}
        title={`Revoke ${revoking?.name ?? "token"}?`}
        description="The identity provider's next push is refused. Create a new token and update the provider if provisioning should continue."
        confirmLabel="Revoke token"
      />
    </Card>
  );
}

function CreateDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const formId = useId();
  const [name, setName] = useState("");
  const [days, setDays] = useState("90");
  const [submitted, setSubmitted] = useState(false);
  const create = useMutation({
    mutationFn: () => createToken({ name: name.trim(), expiresInDays: Number(days) }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: provisioningKey }),
  });
  if (create.data) {
    return (
      <Dialog open onOpenChange={(o) => !o && onClose()} title="Token created" size="lg" footer={<Button onClick={onClose}>Done</Button>}>
        <Stack gap={5}>
          <Alert tone="warning" title="Copy this token now.">
            It won&apos;t be shown again. Store it in the identity provider&apos;s provisioning settings.
          </Alert>
          <CopyField label="Token" name="provisioning token" value={create.data.secret} description={`Starts with ${create.data.prefix}. Sent as “Authorization: Bearer …” to the SCIM base URL only.`} />
        </Stack>
      </Dialog>
    );
  }
  const n = Number(days);
  const daysError = submitted && !(Number.isInteger(n) && n >= 1 && n <= 365) ? "Enter a whole number of days from 1 to 365." : undefined;
  const nameError = submitted && !name.trim() ? "Enter a name." : undefined;
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title="Create a provisioning token"
      description="For the identity provider that pushes people and groups. It keeps working if you leave; revoke it here when it's no longer used."
      size="lg"
      footer={
        <>
          <DialogClose>Cancel</DialogClose>
          <Button type="submit" form={formId} loading={create.isPending}>
            Create token
          </Button>
        </>
      }
    >
      <Form
        id={formId}
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          setSubmitted(true);
          if (name.trim() && Number.isInteger(n) && n >= 1 && n <= 365) create.mutate();
        }}
      >
        <Field label="Name" description="Which identity provider uses it." error={nameError}>
          <Input maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Expires after (days)" description="From 1 to 365 days. Make a new one before it does." error={daysError}>
          <NumberInput value={days} onValueChange={setDays} maximumFractionDigits={0} unit="days" />
        </Field>
        <V02ErrorAlert error={create.error} title="Couldn't create the token" />
      </Form>
    </Dialog>
  );
}
