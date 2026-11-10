/*
 * A server's Settings tab: one form over the server (If-Match on its
 * revision; edits survive a change made elsewhere, AD-01), the replace-only
 * credential values, and Delete in the Danger zone (owners and admins). Members
 * and Admin read it: Admin never changes a team's server settings.
 *
 * A new URL is read again at once. User authorization (requirement-section.tsx)
 * names the provider and scopes whose user token the server receives. Under
 * approval_required, a published server goes back to review (pending) when
 * its URL changes or its requirement widens what a capability receives: the
 * form says so before the save, and the saved message after it. "Record
 * call contents" is for the team's owners and admins (editors read it; it's
 * only sent when changed) and asks first when turned on. Authentication
 * (auth-mode-fields.tsx, settings-auth.tsx) switches between None, a static
 * credential, each person's own key (person-secret.ts), the portal's own
 * OAuth client (machine-auth.ts) and each person's OAuth sign-in, with the
 * same review warnings.
 * TLS to the server (tls-section.tsx) is saved with the rest, in any mode: a
 * changed CA is a trust change and reviewed again. The form's state, save and
 * problems are in settings-form.ts (useServerSettingsForm).
 */
import { captureWhat, keptFallback, useCaptureRetention } from "../capture";
import { ConfirmMutationDialog } from "../confirm-dialog";
import { Switch } from "@/components/ui/switch/switch";
import { Alert } from "@/components/ui/alert/alert";
import { SettingsPage, SettingsSection } from "../templates/settings-page";
import { CopyField } from "@/components/ui/copy-field/copy-field";
import { Field } from "@/components/ui/field/field";
import { Input, Textarea } from "@/components/ui/input/input";
import { describeAuthError } from "./auth-errors";
import { AuthModeFields } from "./auth-mode-fields";
import type { McpServer } from "./labels";
import { reviewedAgain } from "./requirement";
import { RequirementFields } from "./requirement-section";
import type { ServerAbilities, ServerScope } from "./scope";
import { CredentialFields } from "./credential-fields";
import { EnabledSwitch, TimeoutField, UrlField, urlProblem } from "./server-fields";
import { DeleteServer } from "./delete-server";
import { EndpointFields } from "./endpoint-fields";
import { ServerProtectionFields } from "./protection-fields";
import { deletesText, keysDeleted } from "./person-secret";
import { useServerSettingsForm } from "./settings-form";
import { TlsSection } from "./tls-section";
import { tlsRefusal } from "./tls";
import { AuthChangeNotes } from "./settings-auth";
import { authModeOf, type UpstreamForm } from "./upstream-auth";

/** Why the User authorization section is closed in the modes that already send one credential per call. */
const noRequirementTitle: Partial<Record<UpstreamForm["mode"], string>> = {
  oauth: "Not with OAuth sign-in",
  person_secret: "Not with each person's own key",
  machine_oauth: "Not with the portal's own OAuth client",
};
const noRequirementText: Partial<Record<UpstreamForm["mode"], string>> = {
  oauth: "Each call already carries the person's own token for this server, so it can't carry another account too.",
  person_secret: "Each call already carries the person's own key for this server, so it can't carry another account too.",
  machine_oauth: "Each call already carries the portal's own token for this server, so it can't carry another account too.",
};

type Props = { server: McpServer; scope: ServerScope; abilities: ServerAbilities };

export function ServerSettingsTab({ server, scope, abilities }: Props) {
  const {
    revision,
    canEdit,
    dirty,
    save,
    submitted,
    invalid,
    form,
    set,
    fields,
    dev,
    errors,
    reqRefused,
    authError,
    urlChanged,
    leavesCatalog,
    endpointBlocked,
    problems,
    secretErrors,
    originMoved,
    parts,
    setParts,
    partErrors,
    noParts,
    change,
    detected,
    applyDetected,
    secret,
    setSecret,
    tlsForm,
    setTlsForm,
    tlsErrors,
    caChanged,
    noRequirement,
    reqErrors,
    resetsOverrides,
    requirementWidens,
    confirmingCapture,
    setConfirmingCapture,
    submit,
    discard,
    confirmCapture,
  } = useServerSettingsForm({ server, scope, abilities });
  const kept = useCaptureRetention(server.teamSlug, false);

  return (
    <SettingsPage
      revision={revision}
      canEdit={canEdit}
      readOnlyNote={
        scope.kind === "admin"
          ? "You can view these settings. The team's editors, admins and owners change them."
          : "Members can view the server's settings. Editors, admins and owners can change them."
      }
      dirty={dirty}
      saving={save.isPending}
      error={errors.url || reqRefused || Object.keys(tlsRefusal(save.error)).length > 0 ? undefined : (authError ?? save.error)}
      onSave={submit}
      onDiscard={discard}
      message={submitted && invalid ? "Not saved: fix the highlighted fields" : leavesCatalog ? "Saving takes the server out of the catalog until it's reviewed again" : undefined}
    >
      <SettingsSection title="General" description="How the server is named in the team's lists and, once published, in the catalog.">
        <Field label="Name" error={errors.name}>
          <Input maxLength={100} disabled={!canEdit} value={form.name} onChange={(e) => fields.set({ name: e.target.value })} />
        </Field>
        <Field label="Description" labelHint="Optional">
          <Textarea maxLength={2000} disabled={!canEdit} value={form.description} onChange={(e) => fields.set({ description: e.target.value })} />
        </Field>
        <CopyField label="Slug" name="server slug" value={server.slug} description="Can't be changed. Gateways name the server's tools slug__tool." />
      </SettingsSection>
      <SettingsSection title="Connection" description="A new URL is read again when you save. After changing only the credential, press Refresh on the Overview tab.">
        <UrlField {...fields} />
        {leavesCatalog && urlChanged && (
          <Alert tone="warning" title="The server will leave the catalog">
            Your team needs approval to publish, so a new URL is reviewed again: once you save, {server.name} is out of the company catalog until a platform admin approves it.
          </Alert>
        )}
        <TimeoutField {...fields} />
        <EnabledSwitch {...fields} />
      </SettingsSection>
      <EndpointFields value={form.endpoints} onChange={(endpoints) => set({ endpoints })} server={server} primaryUrl={form.url} mode={form.upstream.mode} blocked={endpointBlocked} disabled={!canEdit || !abilities.canManage} submitted={submitted} dev={dev} />
      <ServerProtectionFields value={form.protection} onChange={(protection) => set({ protection })} disabled={!canEdit || !abilities.canManage} submitted={submitted} error={save.error} />
      <SettingsSection title="Authentication" description="How the portal proves itself to the server: nothing, a static credential of headers, a token, Basic or a query key (stored encrypted), each person's own key, the portal's own OAuth client, or each person's own OAuth sign-in.">
        <AuthModeFields
          team={server.teamSlug}
          url={form.url}
          urlError={urlProblem(form.url, dev)}
          value={form.upstream}
          onChange={(upstream) => {
            if (describeAuthError(save.error)) save.reset();
            set({ upstream });
          }}
          detected={detected}
          onDetected={applyDetected}
          onUseUrl={(url) => set({ url })}
          server={server}
          secret={secret}
          setSecret={setSecret}
          errors={submitted ? problems : {}}
          secretErrors={submitted ? secretErrors : {}}
          deletesKeys={keysDeleted(server, form.upstream.secret, originMoved, form.upstream.mode) ? deletesText(server) : undefined}
          staticAlso={parts.length > 0}
          disabled={!canEdit}
          headerFields={<CredentialFields parts={parts} setParts={setParts} errors={submitted ? partErrors : {}} disabled={!canEdit} noParts={submitted && noParts} />}
          notes={canEdit && <AuthChangeNotes server={server} change={change} leavesCatalog={leavesCatalog} />}
        />
      </SettingsSection>
      <TlsSection
        server={server}
        form={tlsForm}
        setForm={(patch) => setTlsForm((f) => ({ ...f, ...patch }))}
        errors={tlsErrors}
        disabled={!canEdit}
        originMoved={originMoved}
        reviewsCa={canEdit && reviewedAgain(server) && caChanged}
      />
      <SettingsSection
        title="User authorization"
        description="Whether calls to this server carry each caller's own token for another service, such as GitHub. Each capability can override it on the Capabilities tab."
      >
        {noRequirement ? (
          <Alert tone="info" title={noRequirementTitle[form.upstream.mode]}>
            {noRequirementText[form.upstream.mode]}
            {server.requirement && authModeOf(server) !== form.upstream.mode ? ` Saving removes the requirement (${server.requirement.providerName}).` : ""}
          </Alert>
        ) : (
          <RequirementFields
            server={server}
            value={form.requirement}
            onChange={(requirement) => {
              if (reqRefused) save.reset();
              set({ requirement });
            }}
            errors={reqErrors}
            disabled={!canEdit}
            resetsOverrides={resetsOverrides}
          />
        )}
        {leavesCatalog && !noRequirement && requirementWidens && (
          <Alert tone="warning" title="The server will leave the catalog">
            Your team needs approval to publish, and this sends more to the server than before (a provider, another provider or a new scope), so it&apos;s reviewed
            again: once you save, {server.name} is out of the company catalog until a platform admin approves it. Removing or narrowing a requirement never needs a
            review.
          </Alert>
        )}
      </SettingsSection>
      <SettingsSection
        title="Record call contents"
        description="Off by default: call records hold only who called what, when and how it went. Gateways using this server, and their callers, see that it records."
      >
        <Switch
          label="Record call contents"
          description={[
            `${captureWhat} Applies to calls through any gateway.`,
            `Readable by ${server.teamName}'s owners and admins and by platform admins and auditors; every view is recorded in the audit log.`,
            kept,
            canEdit && !abilities.canManage ? "Only the team's owners and admins can change it." : undefined,
          ]
            .filter(Boolean)
            .join(" ")}
          disabled={!canEdit || !abilities.canManage}
          checked={form.capturePayloads}
          onCheckedChange={(v) => set({ capturePayloads: v })}
        />
      </SettingsSection>
      {scope.kind === "team" && abilities.canManage && <DeleteServer server={server} />}
      <ConfirmMutationDialog
        target={confirmingCapture}
        onClose={() => setConfirmingCapture(null)}
        mutation={save}
        onConfirm={confirmCapture}
        tone="primary"
        title={`Record what's sent to ${server.name}?`}
        description={`${captureWhat} This covers calls through every gateway that offers its capabilities, including other teams' gateways; their callers are told it records. Readable by ${server.teamName}'s owners and admins and by platform staff; every view is audited. ${kept ?? keptFallback}`}
        confirmLabel="Record call contents"
      />
    </SettingsPage>
  );
}
