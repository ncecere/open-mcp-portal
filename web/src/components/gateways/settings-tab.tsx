/*
 * A gateway's Settings tab: name, description, the switch, its rate limit
 * and "Record call contents" in one form (If-Match on its revision; edits
 * survive a change made elsewhere, AD-01), the slug (never changes) and
 * Delete in the Danger zone. Saving with the switch turned off, or with
 * recording turned on, asks first. Only changed limit and recording values
 * are sent. Whoever can't edit reads it, told who can (in Admin, a team
 * gateway's record says so above).
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ApiError } from "../../api/client";
import { parseRate, rateProblem, rateText } from "../../lib/limits";
import { captureWhat, captureWho, keptFallback, useCaptureRetention } from "../capture";
import { useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { adminOnly } from "../../lib/terms";
import { ConfirmMutationDialog } from "../confirm-dialog";
import { useRevisionForm } from "../templates/revision-form";
import { DangerAction, DangerZone, SettingsPage, SettingsSection } from "../templates/settings-page";
import { Button } from "@/components/ui/button/button";
import { CopyField } from "@/components/ui/copy-field/copy-field";
import { Field } from "@/components/ui/field/field";
import { Input, Textarea } from "@/components/ui/input/input";
import { Switch } from "@/components/ui/switch/switch";
import { toast } from "@/components/ui/toast/toast";
import type { Gateway } from "./labels";
import { CeilingSection } from "./ceiling-section";
import type { Sensitivity } from "../servers/governance";
import { CaptureSection, type RateMode, RateLimitSection, useGatewayLimit } from "./operations-fields";
import { deleteGateway, type GatewayAbilities, type GatewayScope, invalidateGateway, listPath, storeGateway, updateGateway } from "./scope";

type Form = { name: string; description: string; enabled: boolean; capturePayloads: boolean; rateMode: RateMode; rate: string; maxSensitivity: Sensitivity };
const formOf = (x: Gateway): Form => ({
  name: x.name,
  description: x.description,
  enabled: x.enabled,
  capturePayloads: x.capturePayloads ?? false,
  maxSensitivity: x.maxSensitivity ?? "restricted",
  rateMode: x.rateLimitPerMinute === null || x.rateLimitPerMinute === undefined ? "inherit" : "custom",
  rate: x.rateLimitPerMinute === null || x.rateLimitPerMinute === undefined ? "" : String(x.rateLimitPerMinute),
});
const labels = { name: "Name", description: "Description", enabled: "Enabled", capturePayloads: "Record call contents", maxSensitivity: "Sensitivity ceiling", rateMode: "Rate limit", rate: "Requests per minute" };
const choices = { rateMode: { inherit: "Inherit", custom: "Its own limit" }, maxSensitivity: { public: "Public", internal: "Internal", confidential: "Confidential", restricted: "Restricted (no ceiling)" } };

/** The rate limit as the update sends it: null inherits. */
const rateOf = (f: Form) => (f.rateMode === "inherit" ? null : parseRate(f.rate));

/** The refused limit (422 invalid_limit above_ceiling), for the field. */
const limitRefusal = (err: unknown) => (err instanceof ApiError && err.code === "invalid_limit" ? "Above the platform's ceiling for gateways." : undefined);

type Confirm = "off" | "capture";

type Props = { gateway: Gateway; scope: GatewayScope; abilities: GatewayAbilities };

function readOnlyNote(gateway: Gateway, scope: GatewayScope) {
  if (scope.kind === "team") return "Members can view the gateway's settings. Owners and admins can change them.";
  // Admin's record of a team gateway already explains who changes it, above the tabs.
  if (gateway.ownerKind === "team") return null;
  return adminOnly;
}

export function GatewaySettingsTab({ gateway, scope, abilities }: Props) {
  const qc = useQueryClient();
  const saved = formOf(gateway);
  const [form, setForm, revision] = useRevisionForm(saved, gateway.revision, { labels, choices });
  const [submitted, setSubmitted] = useState(false);
  const { ceiling } = useGatewayLimit(gateway);
  const kept = useCaptureRetention(gateway.teamSlug, gateway.ownerKind === "platform");
  // Saving would switch it off or start recording: confirmed first.
  const [confirming, setConfirming] = useState<Confirm | null>(null);
  const save = useMutation({
    mutationFn: async () => {
      const rate = rateOf(form);
      return updateGateway(scope, gateway, {
        name: form.name.trim(),
        description: form.description,
        enabled: form.enabled,
        ...(form.capturePayloads !== saved.capturePayloads ? { capturePayloads: form.capturePayloads } : {}),
        ...(form.maxSensitivity !== saved.maxSensitivity ? { maxSensitivity: form.maxSensitivity } : {}),
        ...(rate !== (gateway.rateLimitPerMinute ?? null) ? { rateLimitPerMinute: rate } : {}),
      });
    },
    onSuccess: (updated) => {
      setSubmitted(false);
      setConfirming(null);
      storeGateway(qc, updated);
      toast.success("Gateway settings saved", savedNote(gateway, updated));
    },
  });
  const canEdit = abilities.canEdit;
  const nameError = submitted && !form.name.trim() ? "Enter a name." : undefined;
  const rateError = form.rateMode === "custom" ? (form.rate.trim() ? rateProblem(form.rate, ceiling) : submitted ? "Enter a number of requests per minute, or inherit." : undefined) : undefined;
  const invalid = !form.name.trim() || Boolean(form.rateMode === "custom" && (rateProblem(form.rate, ceiling) || !form.rate.trim()));
  const dirty = JSON.stringify({ ...form, name: form.name.trim() }) !== JSON.stringify(saved);
  return (
    <SettingsPage
      revision={revision}
      canEdit={canEdit}
      readOnlyNote={readOnlyNote(gateway, scope)}
      dirty={dirty}
      saving={save.isPending}
      error={limitRefusal(save.error) ? undefined : save.error}
      message={(submitted && invalid) || rateError ? "Not saved: fix the highlighted field" : undefined}
      onSave={() => {
        setSubmitted(true);
        if (invalid) return;
        if (!saved.capturePayloads && form.capturePayloads) setConfirming("capture");
        else if (gateway.enabled && !form.enabled) setConfirming("off");
        else save.mutate();
      }}
      onDiscard={() => {
        setForm(saved);
        setSubmitted(false);
      }}
    >
      <SettingsSection title="General" description="How the gateway is named in lists and in My gateways.">
        <Field label="Name" error={nameError}>
          <Input maxLength={100} disabled={!canEdit} value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} />
        </Field>
        <Field label="Description" labelHint="Optional">
          <Textarea maxLength={2000} disabled={!canEdit} value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} />
        </Field>
        <CopyField label="Slug" name="gateway slug" value={gateway.slug} description="Can't be changed: it's part of the endpoint URL clients use." />
        <Switch
          label="Enabled"
          description="Turned off, the endpoint answers “not found” to everyone. Its capabilities and access stay as they are."
          disabled={!canEdit}
          checked={form.enabled}
          onCheckedChange={(v) => setForm((f) => ({ ...f, enabled: v }))}
        />
      </SettingsSection>
      <RateLimitSection
        gateway={gateway}
        mode={form.rateMode}
        value={form.rate}
        error={limitRefusal(save.error) ?? rateError}
        disabled={!canEdit}
        onChange={(rateMode, rate) => {
          if (limitRefusal(save.error)) save.reset();
          setForm((f) => ({ ...f, rateMode, rate }));
        }}
      />
      <CeilingSection
        value={form.maxSensitivity}
        saved={saved.maxSensitivity}
        disabled={!canEdit}
        unavailable={gateway.unavailableCount}
        onChange={(maxSensitivity) => setForm((f) => ({ ...f, maxSensitivity }))}
      />
      <CaptureSection gateway={gateway} checked={form.capturePayloads} disabled={!canEdit} onChange={(v) => setForm((f) => ({ ...f, capturePayloads: v }))} />
      {canEdit && <DeleteGateway gateway={gateway} scope={scope} />}
      <ConfirmMutationDialog
        target={confirming === "capture" ? form : null}
        onClose={() => setConfirming(null)}
        mutation={save}
        onConfirm={() => save.mutate()}
        title={`Record what's sent through ${gateway.name}?`}
        description={`${captureWhat} ${gateway.ownerKind === "team" ? `Readable by ${gateway.teamName ?? "the team"}'s owners and admins and by platform admins and auditors; every view is audited.` : captureWho} ${kept ?? keptFallback} Everyone who uses the gateway is told it records.${
          gateway.enabled && !form.enabled ? " The gateway is also turned off." : ""
        }`}
        confirmLabel="Record call contents"
        tone="primary"
      />
      <ConfirmMutationDialog
        target={confirming === "off" ? form : null}
        onClose={() => setConfirming(null)}
        mutation={save}
        onConfirm={() => save.mutate()}
        title={`Disable ${gateway.name}?`}
        description={`Everyone using it loses access at once: its endpoint answers “not found” until it's enabled again. Its capabilities${
          gateway.ownerKind === "platform" ? " and grants" : ""
        } stay as they are.`}
        confirmLabel="Disable gateway"
      />
    </SettingsPage>
  );
}

/** The saved toast's detail: what the switch, the limit or recording now do. */
function savedNote(before: Gateway, after: Gateway) {
  if (after.enabled !== before.enabled) return after.enabled ? "The gateway is on." : "The gateway is off: its endpoint answers “not found”.";
  if (after.capturePayloads !== before.capturePayloads) return after.capturePayloads ? "It records call contents from the next call." : "It no longer records call contents. Recordings already made are kept for their retention period.";
  if (after.rateLimitPerMinute !== before.rateLimitPerMinute && after.effectiveRateLimitPerMinute !== undefined) return `Rate limit now: ${rateText(after.effectiveRateLimitPerMinute)}.`;
  return undefined;
}

function DeleteGateway({ gateway, scope }: { gateway: Gateway; scope: GatewayScope }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [confirming, setConfirming] = useState<Gateway | null>(null);
  const del = useMutation({
    mutationFn: async () => deleteGateway(scope, gateway),
    onSuccess: () => {
      setConfirming(null);
      toast.success(`${gateway.name} was deleted`);
      // Leave first: the record would load again and find nothing.
      void navigate({ ...listPath(scope), replace: true }).then(() => invalidateGateway(qc, gateway));
    },
  });
  return (
    <DangerZone>
      <DangerAction
        title="Delete this gateway"
        description={`Removes ${gateway.name} and its endpoint. Clients connected to it stop working at once. Its call records are kept. This can't be undone.`}
        action={
          <Button variant="danger" onClick={() => setConfirming(gateway)}>
            Delete gateway
          </Button>
        }
      />
      <ConfirmMutationDialog
        target={confirming}
        onClose={() => setConfirming(null)}
        mutation={del}
        onConfirm={() => del.mutate()}
        title={`Delete ${gateway.name}?`}
        description={`Everyone using ${gateway.url} loses access immediately. Its slug becomes free for another gateway.`}
        confirmLabel="Delete gateway"
      />
    </DangerZone>
  );
}
