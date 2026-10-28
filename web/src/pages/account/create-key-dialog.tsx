/*
 * Create API key: a name, how many days it lasts (keys always expire;
 * 90 by default) and, optionally, the gateways it is limited to (picked
 * from My gateways; none means every gateway the person can use). The
 * secret is shown once, right after, with a warning and
 * a copy button; it's gone when the dialog closes. The person can put it
 * into a gateway's connection snippets there and then, if they choose to.
 * No toast: the dialog's own "API key created" says so, and a toast would
 * sit over its Done button on a phone.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { api, type Schemas, unwrap } from "../../api/client";
import { myApiKeysQuery, myGatewaysQuery } from "../../api/queries";
import { ScopeEditor, scopeProblem, type ToolScope } from "../../components/tool-scope";
import { ConnectSection } from "../../components/gateways/connect";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Checkbox } from "@/components/ui/checkbox/checkbox";
import { Combobox } from "@/components/ui/combobox/combobox";
import { CopyField } from "@/components/ui/copy-field/copy-field";
import { Dialog, DialogClose } from "@/components/ui/dialog/dialog";
import { Field, Form } from "@/components/ui/field/field";
import { Input, NativeSelect } from "@/components/ui/input/input";
import { Stack } from "@/components/ui/layout/layout";
import { NumberInput } from "@/components/ui/number-input/number-input";

/** The most gateways a key can be limited to (the API's maxItems). */
const maxKeyGateways = 50;

const daysProblem = (text: string) => {
  const n = Number(text);
  return text && Number.isInteger(n) && n >= 1 && n <= 365 ? undefined : "Enter a whole number of days from 1 to 365.";
};

export function CreateKeyDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const formId = useId();
  const [name, setName] = useState("");
  const [days, setDays] = useState("90");
  const [gatewayIds, setGatewayIds] = useState<string[]>([]);
  const [toolScope, setToolScope] = useState<ToolScope>(null);
  const [submitted, setSubmitted] = useState(false);
  const gateways = useQuery(myGatewaysQuery());
  const create = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/me/api-keys", {
          body: { name: name.trim(), expiresInDays: Number(days), toolScope, ...(gatewayIds.length > 0 ? { gatewayIds } : {}) },
        }),
      ),
    onSuccess: () => void qc.invalidateQueries({ queryKey: myApiKeysQuery().queryKey }),
  });

  // One Dialog in both states, so it stays open (and keeps focus) when the secret appears.
  if (create.data) {
    return (
      <Dialog open onOpenChange={(o) => !o && onClose()} title="API key created" size="lg" footer={<Button onClick={onClose}>Done</Button>}>
        <SecretView created={create.data} />
      </Dialog>
    );
  }
  const nameError = submitted && !name.trim() ? "Enter a name." : undefined;
  const daysError = submitted ? daysProblem(days) : undefined;
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title="Create API key"
      description="A personal key for MCP clients and scripts. It acts as you, and the secret is shown once, right after it's created."
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
          if (name.trim() && !daysProblem(days) && !scopeProblem(toolScope)) create.mutate();
        }}
      >
        <Field label="Name" description="Where you'll use it, for example “Claude Code on my laptop”." error={nameError}>
          <Input maxLength={100} value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Expires after (days)" description="Keys always expire: from 1 to 365 days. Create a new one when it does." error={daysError}>
          <NumberInput value={days} onValueChange={setDays} maximumFractionDigits={0} unit="days" />
        </Field>
        <Field
          label="Limit to gateways (optional)"
          description={
            gatewayIds.length > 0
              ? "The key works only on these gateways, and only while you can use them."
              : "Leave empty to use the key on every gateway you can use. A limit never gives you more access."
          }
        >
          <Combobox
            multiple
            items={(gateways.data ?? []).map((g) => ({ value: g.id, label: g.name, hint: g.slug }))}
            value={gatewayIds}
            onValueChange={(v) => setGatewayIds(v.slice(0, maxKeyGateways))}
            placeholder={gateways.data?.length === 0 ? "You can't use any gateway yet" : "All my gateways"}
            listLabel="My gateways"
            chipsLabel="Chosen gateways"
            emptyText="No gateway matches."
          />
        </Field>
        <ScopeEditor value={toolScope} onChange={setToolScope} disabled={create.isPending} />
        <ErrorAlert error={create.error} title="Couldn't create the key" />
      </Form>
    </Dialog>
  );
}

/** The secret once, and the choice to put it into a gateway's snippets. */
function SecretView({ created }: { created: Schemas["ApiKeyCreated"] }) {
  const gateways = useQuery(myGatewaysQuery());
  // A limited key only works on its gateways: offer only those.
  const scope = new Set(created.key.gateways.filter((g) => g.exists).map((g) => g.id));
  const list = (gateways.data ?? []).filter((g) => created.key.gateways.length === 0 || scope.has(g.id));
  const [gatewayId, setGatewayId] = useState("");
  const [fill, setFill] = useState(false);
  const chosen = list.find((g) => g.id === gatewayId) ?? list[0];
  return (
    <Stack gap={5}>
      <Alert tone="warning" title="Copy this key now.">
        It won&apos;t be shown again. Store it somewhere safe, such as a password manager. If you lose it, revoke it and create a new one.
      </Alert>
      <CopyField label="Secret" name="API key secret" value={created.secret} description={`Send it as “Authorization: Bearer …” to a gateway's URL. Starts with ${created.key.prefix}.`} />
      {chosen && (
        <Stack gap={4}>
          <Field label="Connect a gateway">
            <NativeSelect value={chosen.id} onChange={(e) => setGatewayId(e.target.value)}>
              {list.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </NativeSelect>
          </Field>
          <Checkbox label="Put this key into the snippets" description="Only on this screen. Anyone who sees the snippets can use the key." checked={fill} onCheckedChange={setFill} />
          <ConnectSection key={chosen.id} slug={chosen.slug} url={chosen.url} secret={fill ? created.secret : undefined} preferKey bare />
        </Stack>
      )}
    </Stack>
  );
}
