/*
 * A service account's Settings: name, description, role and the switch in
 * one form (If-Match on its revision; edits survive a change made elsewhere,
 * AD-01). Saving with the switch turned off asks first (its keys stop at the
 * next request); Delete, in the Danger zone, asks too. The team's owners and
 * admins change them; members and platform staff read.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { api, ApiError, ifMatch, unwrap } from "../../../api/client";
import { serviceAccountsKey } from "../../../api/queries";
import { ScopeBadges, ScopeEditor, scopeFormValue, scopeProblem, type ToolScope } from "../../../components/tool-scope";
import { ConfirmMutationDialog } from "../../../components/confirm-dialog";
import { useRevisionForm } from "../../../components/templates/revision-form";
import { DangerAction, DangerZone, SettingsPage, SettingsSection } from "../../../components/templates/settings-page";
import { Button } from "@/components/ui/button/button";
import { Field } from "@/components/ui/field/field";
import { Input, Textarea } from "@/components/ui/input/input";
import { Switch } from "@/components/ui/switch/switch";
import { toast } from "@/components/ui/toast/toast";
import { readOnlyText } from "../access";
import { useTeam } from "../common";
import { nameProblem, roleLabel, type ServiceAccount, type ServiceAccountAbilities, type ServiceAccountRole, storeServiceAccount } from "./labels";
import { RoleChoice } from "./role-choice";

type Form = { name: string; description: string; role: ServiceAccountRole; enabled: boolean; toolScope: ToolScope };
const formOf = (a: ServiceAccount): Form => ({ name: a.name, description: a.description, role: a.role, enabled: a.enabled, toolScope: scopeFormValue(a.toolScope) });
const labels = { name: "Name", description: "Description", role: "Role", enabled: "Enabled", toolScope: "Tool scope" };
const choices = { role: { member: roleLabel("member"), editor: roleLabel("editor") } };

type Props = { account: ServiceAccount; abilities: ServiceAccountAbilities };

export function SettingsTab({ account, abilities }: Props) {
  const qc = useQueryClient();
  const { role, archived } = useTeam();
  const saved = formOf(account);
  const [form, setForm, revision] = useRevisionForm(saved, account.revision, { labels, choices });
  const [submitted, setSubmitted] = useState(false);
  // Saving would switch it off: confirmed first.
  const [confirmingOff, setConfirmingOff] = useState<Form | null>(null);
  const save = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PATCH("/v1/teams/{team}/service-accounts/{serviceAccountId}", {
          params: { path: { team: account.teamSlug, serviceAccountId: account.id }, header: ifMatch(account.revision) },
          body: { name: form.name, description: form.description, role: form.role, enabled: form.enabled, ...(JSON.stringify(form.toolScope) !== JSON.stringify(saved.toolScope) ? { toolScope: form.toolScope } : {}) },
        }),
      ),
    onSuccess: (updated) => {
      setSubmitted(false);
      setConfirmingOff(null);
      storeServiceAccount(qc, updated);
      toast.success("Service account saved", updated.enabled === account.enabled ? undefined : updated.enabled ? "Its keys work again." : "Its keys are refused from now on.");
    },
  });
  const canEdit = abilities.canManage;
  const taken = save.error instanceof ApiError && save.error.code === "name_taken";
  const nameError = (submitted ? nameProblem(form.name) : undefined) ?? (taken ? "Another service account in this team has this name. Choose another." : undefined);
  const dirty = JSON.stringify({ ...form, description: form.description.trim() }) !== JSON.stringify({ ...saved, description: saved.description.trim() });
  return (
    <SettingsPage
      revision={revision}
      canEdit={canEdit}
      // An archived team's notice already says nothing changes; platform staff get the default note.
      readOnlyNote={archived ? null : role ? readOnlyText(role, "the service account's settings", "Owners and admins") : undefined}
      dirty={dirty}
      saving={save.isPending}
      error={taken ? undefined : save.error}
      message={nameError ? "Not saved: fix the highlighted field" : undefined}
      onSave={() => {
        setSubmitted(true);
        if (nameProblem(form.name) || scopeProblem(form.toolScope)) return;
        if (account.enabled && !form.enabled) setConfirmingOff(form);
        else save.mutate();
      }}
      onDiscard={() => {
        setForm(saved);
        setSubmitted(false);
        save.reset();
      }}
    >
      <SettingsSection title="General" description="How the account is named in lists and in call records.">
        <Field label="Name" description="Lower-case letters, digits and dashes; unique in the team." error={nameError}>
          <Input
            spellCheck={false}
            autoComplete="off"
            maxLength={64}
            disabled={!canEdit}
            value={form.name}
            onChange={(e) => {
              if (taken) save.reset();
              setForm((f) => ({ ...f, name: e.target.value }));
            }}
          />
        </Field>
        <Field label="Description" labelHint="Optional">
          <Textarea maxLength={2000} disabled={!canEdit} value={form.description} onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))} />
        </Field>
        <RoleChoice value={form.role} disabled={!canEdit} onChange={(r) => setForm((f) => ({ ...f, role: r }))} />
        <Switch
          label="Enabled"
          description="Turned off, its keys are refused on their next request. Its keys and settings stay as they are."
          disabled={!canEdit}
          checked={form.enabled}
          onCheckedChange={(v) => setForm((f) => ({ ...f, enabled: v }))}
        />
      </SettingsSection>
      <SettingsSection title="Account tool ceiling" description="Applies immediately to every key together with its own ceiling. Everything on a key inherits this live limit.">
        {canEdit ? <ScopeEditor value={form.toolScope} onChange={(toolScope) => setForm((f) => ({ ...f, toolScope: scopeFormValue(toolScope) }))} disabled={save.isPending} /> : <ScopeBadges scope={account.toolScope} />}
      </SettingsSection>
      {canEdit && <DeleteAccount account={account} />}
      <ConfirmMutationDialog
        target={confirmingOff}
        onClose={() => setConfirmingOff(null)}
        mutation={save}
        onConfirm={() => save.mutate()}
        title={`Disable ${account.name}?`}
        description="Whatever uses its keys stops working on its next request, until it's turned on again. Its keys stay as they are."
        confirmLabel="Disable service account"
      />
    </SettingsPage>
  );
}

function DeleteAccount({ account }: { account: ServiceAccount }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [confirming, setConfirming] = useState<ServiceAccount | null>(null);
  const del = useMutation({
    mutationFn: async () => unwrap(await api.DELETE("/v1/teams/{team}/service-accounts/{serviceAccountId}", { params: { path: { team: account.teamSlug, serviceAccountId: account.id } } })),
    onSuccess: () => {
      setConfirming(null);
      toast.success(`${account.name} was deleted`);
      // Leave first: the record would load again and find nothing.
      void navigate({ to: "/teams/$team/service-accounts", params: { team: account.teamSlug }, replace: true }).then(() =>
        qc.invalidateQueries({ queryKey: serviceAccountsKey(account.teamSlug) }),
      );
    },
  });
  return (
    <DangerZone>
      <DangerAction
        title="Delete this service account"
        description={`Removes ${account.name} and revokes its keys at once. Its call records are kept. This can't be undone.`}
        action={
          <Button variant="danger" onClick={() => setConfirming(account)}>
            Delete service account
          </Button>
        }
      />
      <ConfirmMutationDialog
        target={confirming}
        onClose={() => setConfirming(null)}
        mutation={del}
        onConfirm={() => del.mutate()}
        title={`Delete ${account.name}?`}
        description="Every key it has stops working immediately. Its name becomes free for another service account."
        confirmLabel="Delete service account"
      />
    </DangerZone>
  );
}
