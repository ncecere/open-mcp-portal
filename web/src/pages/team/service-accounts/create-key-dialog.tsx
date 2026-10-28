/*
 * Create a service account key: a name (where it's deployed), how many days
 * it lasts (keys always expire; 90 by default, at most 365) and, optionally,
 * the gateways it's limited to: any the account can use now, its team's or
 * platform gateways granted to the team. The secret is shown once, right
 * after, with a warning and a copy button; when another key was active
 * before this one, the next rotation step too. It's gone when the dialog
 * closes. No toast: the dialog's own title says it was created.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { api, ApiError, type Schemas, unwrap } from "../../../api/client";
import { serviceAccountsKey } from "../../../api/queries";
import { ScopeBadges, ScopeEditor, scopeProblem, type ToolScope } from "../../../components/tool-scope";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Combobox } from "@/components/ui/combobox/combobox";
import { CopyField } from "@/components/ui/copy-field/copy-field";
import { Dialog, DialogClose } from "@/components/ui/dialog/dialog";
import { Field, Form } from "@/components/ui/field/field";
import { Input } from "@/components/ui/input/input";
import { Stack } from "@/components/ui/layout/layout";
import { NumberInput } from "@/components/ui/number-input/number-input";
import { accountGatewaysQuery, maxActiveKeys, type ServiceAccount } from "./labels";

/** The most gateways a key can be limited to (the API's maxItems). */
const maxKeyGateways = 50;

const daysProblem = (text: string) => {
  const n = Number(text);
  return text && Number.isInteger(n) && n >= 1 && n <= 365 ? undefined : "Enter a whole number of days from 1 to 365.";
};

/** A refusal in the account's words (409 too_many_keys or disabled, 422 gateway_not_usable). */
function refusal(err: unknown): string | undefined {
  if (!(err instanceof ApiError)) return undefined;
  if (err.code === "too_many_keys") return `It already has ${maxActiveKeys} active keys. Revoke the older one first.`;
  if (err.code === "disabled") return "The account is turned off. Turn it on in Settings first.";
  if (err.code === "gateway_not_usable") return "A chosen gateway isn't one this account can use now. Remove it and try again.";
  return undefined;
}

type Props = {
  account: ServiceAccount;
  /** Its active keys now, before this one: one or more means this key is a rotation. */
  activeCount: number;
  onClose: () => void;
};

export function CreateKeyDialog({ account, activeCount, onClose }: Props) {
  const qc = useQueryClient();
  const formId = useId();
  const team = account.teamSlug;
  const [name, setName] = useState("");
  const [days, setDays] = useState("90");
  const [gatewayIds, setGatewayIds] = useState<string[]>([]);
  const [toolScope, setToolScope] = useState<ToolScope>(null);
  const [submitted, setSubmitted] = useState(false);
  const gateways = useQuery(accountGatewaysQuery(team, account.id));
  const create = useMutation({
    // activeBefore: the active keys when Create was pressed (the list counts the new key once it reloads).
    mutationFn: async (_: { activeBefore: number }) =>
      unwrap(
        await api.POST("/v1/teams/{team}/service-accounts/{serviceAccountId}/keys", {
          params: { path: { team, serviceAccountId: account.id } },
          body: { name: name.trim(), expiresInDays: Number(days), toolScope, ...(gatewayIds.length > 0 ? { gatewayIds } : {}) },
        }),
      ),
    onSuccess: () => void qc.invalidateQueries({ queryKey: serviceAccountsKey(team) }),
  });

  // One Dialog in both states, so it stays open (and keeps focus) when the secret appears.
  if (create.data) {
    return (
      <Dialog open onOpenChange={(o) => !o && onClose()} title="Key created" size="lg" footer={<Button onClick={onClose}>Done</Button>}>
        <SecretView created={create.data} rotating={(create.variables?.activeBefore ?? 0) >= 1} />
      </Dialog>
    );
  }
  const nameError = submitted && !name.trim() ? "Enter a name." : undefined;
  const daysError = submitted ? daysProblem(days) : undefined;
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={`Create a key for ${account.name}`}
      description="The key acts as the service account, not as you. The secret is shown once, right after it's created."
      footer={
        <>
          <DialogClose>Cancel</DialogClose>
          <Button type="submit" form={formId} loading={create.isPending}>
            Create key
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
          if (name.trim() && !daysProblem(days) && !scopeProblem(toolScope)) create.mutate({ activeBefore: activeCount });
        }}
      >
        <Field label="Name" description="Where it's deployed, for example “GitHub Actions release workflow”." error={nameError}>
          <Input maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Expires after (days)" description="Keys always expire: from 1 to 365 days. Rotate it before it does." error={daysError}>
          <NumberInput value={days} onValueChange={setDays} maximumFractionDigits={0} unit="days" />
        </Field>
        <Field
          label="Limit to gateways (optional)"
          description={gatewayIds.length > 0 ? "The key works only on these gateways." : "Leave empty to use the key on every gateway the account can use. A limit never gives it more access."}
        >
          <Combobox
            multiple
            items={(gateways.data ?? []).map((g) => ({ value: g.id, label: g.name, hint: g.ownerKind === "platform" ? `${g.slug} · platform` : g.slug }))}
            value={gatewayIds}
            onValueChange={(v) => setGatewayIds(v.slice(0, maxKeyGateways))}
            placeholder="All its gateways"
            listLabel="Gateways it can use"
            chipsLabel="Chosen gateways"
            emptyText="No gateway matches."
          />
        </Field>
        <p>Account ceiling (applies together with this key, even when the key selects Everything):</p>
        <ScopeBadges scope={account.toolScope} />
        <ScopeEditor value={toolScope} onChange={setToolScope} disabled={create.isPending} />
        <ErrorAlert error={create.error} title="Couldn't create the key" describe={(err) => {
            const message = refusal(err);
            return message ? { message } : undefined;
          }}
        />
      </Form>
    </Dialog>
  );
}

/** The secret once, and what to do next. */
function SecretView({ created, rotating }: { created: Schemas["ServiceAccountKeyCreated"]; rotating: boolean }) {
  return (
    <Stack gap={5}>
      <Alert tone="warning" title="Copy this key now.">
        It won&apos;t be shown again. Store it in the secret store of the system that uses it (your CI&apos;s secrets, a vault). If you lose it, revoke it and
        create a new one.
      </Alert>
      <CopyField
        label="Secret"
        name="service account key secret"
        value={created.secret}
        description={`Send it as “Authorization: Bearer …” to a gateway's URL. Starts with ${created.key.prefix}.`}
      />
      {rotating && (
        <Alert tone="info" title="Next: finish the rotation">
          Deploy this key where the older one is used, then revoke the older key on the Keys tab.
        </Alert>
      )}
    </Stack>
  );
}
