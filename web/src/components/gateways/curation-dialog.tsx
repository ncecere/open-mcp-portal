import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError, type Schemas } from "../../api/client";
import { FormDialog } from "../form-dialog";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Checkbox } from "@/components/ui/checkbox/checkbox";
import { Field } from "@/components/ui/field/field";
import { Dialog } from "@/components/ui/dialog/dialog";
import { Input, Textarea } from "@/components/ui/input/input";
import { ArgumentFields, choicesOf, object, policyOf, previewOf, type Policy } from "./curation-fields";
import type { Gateway, GatewayCapability } from "./labels";
import { gatewayCapabilitiesQuery, gatewayQuery, invalidateGateway, setCapabilities, type GatewayScope } from "./scope";
import g from "./gateways.module.css";

export function ToolDefinitionDialog({ capability, onClose }: { capability: GatewayCapability; onClose: () => void }) {
  return <Dialog open title={`Tool definitions: ${capability.exposedName}`} description="Server text and gateway edits are untrusted. This view changes nothing." onOpenChange={(open) => { if (!open) onClose(); }} size="lg">
    <div className={g.stack}>
      {capability.curation && <Alert tone="info">Edited for this gateway. The original catalog definition is unchanged.</Alert>}
      <details open><summary>Model-facing definition</summary><pre className={g.definition}>{JSON.stringify(capability.effectiveDefinition, null, 2)}</pre></details>
      <details open><summary>Original server definition</summary><pre className={g.definition}>{JSON.stringify(capability.originalDefinition, null, 2)}</pre></details>
    </div>
  </Dialog>;
}

type Props = { gateway: Gateway; scope: GatewayScope; current: Schemas["GatewayCapabilities"]; capability: GatewayCapability; onClose: () => void };

export function CurationDialog({ gateway, scope, current, capability, onClose }: Props) {
  const qc = useQueryClient();
  // Freeze both review guards: background refetches must not rebase a policy edit.
  const [seen] = useState(() => ({ current, cap: capability }));
  const cap = seen.cap;
  const original = object(cap.originalDefinition);
  const schema = object(original.inputSchema);
  const properties = object(schema.properties);
  const fallbackName = `${cap.serverSlug}__${cap.name}`;
  const [name, setName] = useState(cap.curation?.nameOverride ?? "");
  const [description, setDescription] = useState(cap.curation?.descriptionOverride ?? String(original.description ?? cap.description));
  const [overrideDescription, setOverrideDescription] = useState(cap.curation?.descriptionOverride != null);
  const [choices, setChoices] = useState(() => choicesOf(cap.curation, properties));
  const [stale, setStale] = useState(false);
  const [validation, setValidation] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: (curation: Policy | null) => setCapabilities(scope, gateway, seen.current.items.map((c) => ({ capabilityId: c.capabilityId, ...(c.minRole ? { minRole: c.minRole } : {}), ...(c.capabilityId === cap.capabilityId ? { curation, expectedFingerprint: cap.fingerprint } : {}) })), seen.current.revision),
    onSuccess: (saved) => {
      qc.setQueryData(gatewayCapabilitiesQuery(scope, gateway.id).queryKey, saved);
      void qc.invalidateQueries({ queryKey: gatewayQuery(scope, gateway.id).queryKey });
      invalidateGateway(qc, gateway);
      onClose();
    },
    onError: (err) => {
      if (err instanceof ApiError && (err.status === 412 || err.code === "changed_since_review")) {
        setStale(true);
        void qc.invalidateQueries({ queryKey: gatewayCapabilitiesQuery(scope, gateway.id).queryKey });
      }
    },
  });
  let policy: Policy | null = null;
  let previewError = "";
  try { policy = policyOf(name, description, choices, properties); if (!overrideDescription) policy.descriptionOverride = null; } catch (err) { previewError = (err as Error).message; }
  const disabled = save.isPending || stale || !cap.fingerprint;
  return <FormDialog title={`Curate ${cap.exposedName}`} description="Only this gateway changes. Rewritten tool text is untrusted and can hide risk; constraints are not a substitute for upstream authorization." size="lg" onClose={onClose}
    submitLabel={cap.stale ? "Review and resave policy" : "Save policy"} busy={save.isPending} submitDisabled={disabled || !policy}
    onSubmit={() => { if (disabled) return; if (!policy) { setValidation(previewError); return; } save.mutate(policy); }}>
    <div className={g.stack}>
      {cap.stale && <Alert tone="warning" title="Definition changed">This tool is unavailable until you review the current original definition and resave against its fresh fingerprint.</Alert>}
      {stale && <Alert tone="warning">The gateway or tool changed while this dialog was open. Close it and review the refreshed definition before saving again.</Alert>}
      <Field label="Exposed name" description={`Leave empty to use ${fallbackName}. Names must be unique within this gateway.`}>
        <Input value={name} maxLength={128} pattern="[A-Za-z0-9_.-]+" disabled={disabled} onChange={(e) => setName(e.target.value)} />
      </Field>
      <Checkbox label="Override description for this gateway" checked={overrideDescription} disabled={disabled} onCheckedChange={setOverrideDescription} />
      <Field label="Model-facing description" description="Overrides are at most 2000 characters. Turn off the override to inherit the original description.">
        <Textarea value={overrideDescription ? description : String(original.description ?? cap.description)} maxLength={2000} disabled={disabled || !overrideDescription} onChange={(e) => setDescription(e.target.value)} />
      </Field>
      <ArgumentFields schema={schema} choices={choices} onChange={setChoices} disabled={disabled} />
      {(validation || previewError) && <Alert tone="warning">{validation || previewError}</Alert>}
      <details><summary>Model definition preview (server validates on save)</summary><pre className={g.definition}>{policy ? JSON.stringify(previewOf(original, policy, fallbackName), null, 2) : previewError}</pre></details>
      <details><summary>Original server definition</summary><pre className={g.definition}>{JSON.stringify(original, null, 2)}</pre></details>
      <Button variant="secondary" disabled={disabled || !cap.curation} onClick={() => save.mutate(null)}>Clear policy and restore defaults</Button>
      <ErrorAlert error={save.error} title="Couldn't save tool policy" />
    </div>
  </FormDialog>;
}
