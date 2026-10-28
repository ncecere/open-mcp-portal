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
 * changed CA is a trust change and reviewed again.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api, ApiError, ifMatch, unwrap } from "../../api/client";
import { authProvidersQuery } from "../../api/queries";
import { invalidScopeText, scopesProblem } from "../providers/labels";
import { useAuthConfig } from "../../session";
import { captureWhat, keptFallback, useCaptureRetention } from "../capture";
import { ConfirmMutationDialog } from "../confirm-dialog";
import { Switch } from "@/components/ui/switch/switch";
import { Alert } from "@/components/ui/alert/alert";
import { useRevisionForm } from "../templates/revision-form";
import { SettingsPage, SettingsSection } from "../templates/settings-page";
import { CopyField } from "@/components/ui/copy-field/copy-field";
import { Field } from "@/components/ui/field/field";
import { Input, Textarea } from "@/components/ui/input/input";
import { toast } from "@/components/ui/toast/toast";
import { describeAuthError } from "./auth-errors";
import { AuthModeFields } from "./auth-mode-fields";
import type { McpServer } from "./labels";
import { type RequirementForm, requirementBody, requirementFormOf, reviewedAgain, serverChangeWidens } from "./requirement";
import { RequirementFields } from "./requirement-section";
import { capabilitiesQuery, type ServerAbilities, type ServerScope, storeServer } from "./scope";
import { CredentialFields } from "./credential-fields";
import { credentialsBody, partProblems, type PartForm, partsOf } from "./credentials";
import { EnabledSwitch, type ServerForm, serverFieldErrors, serverProblems, TimeoutField, UrlField, urlProblem } from "./server-fields";
import { DeleteServer } from "./delete-server";
import { sameOrigin } from "./origin";
import { machineProblems } from "./machine-auth";
import { deletesText, keysDeleted, secretProblems } from "./person-secret";
import { TlsSection } from "./tls-section";
import { changesCa, emptyTlsForm, tlsBody, tlsDirty, tlsProblems, tlsRefusal, type TlsForm } from "./tls";
import { AuthChangeNotes, settingsAuthBody } from "./settings-auth";
import { applyDetection, authChange, authModeOf, countedUpstream, type DetectResult, oauthProblems, upstreamFormOf, type UpstreamForm } from "./upstream-auth";

type SettingsForm = ServerForm & { requirement: RequirementForm; capturePayloads: boolean; upstream: UpstreamForm };

const formOf = (x: McpServer): SettingsForm => ({
  name: x.name,
  description: x.description,
  url: x.url,
  timeoutSeconds: x.timeoutSeconds,
  enabled: x.enabled,
  requirement: requirementFormOf(x),
  capturePayloads: x.capturePayloads ?? false,
  upstream: upstreamFormOf(x),
});
const labels = {
  name: "Name",
  description: "Description",
  url: "URL",
  timeoutSeconds: "Timeout (seconds)",
  enabled: "Enabled",
  requirement: "User authorization",
  capturePayloads: "Record call contents",
  upstream: "Authentication",
};

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

/** The requirement's field errors: the form's own, or the server's refusal. */
function requirementErrors(r: RequirementForm, err: unknown, shown: boolean) {
  const out: { provider?: string; scopes?: string } = {};
  if (shown && r.on && !r.providerId) out.provider = "Choose a provider, or turn off Requires a connection.";
  const scopes = r.on ? scopesProblem(r.scopes) : undefined;
  if (shown && scopes) out.scopes = scopes;
  if (err instanceof ApiError && err.code === "provider_not_found") out.provider = "This provider was turned off or removed. Choose another.";
  if (err instanceof ApiError && err.code === "provider_not_allowed") out.provider = "This provider isn't open to this team. Choose another, or ask a platform admin to add the team or server to its access list.";
  if (err instanceof ApiError && err.code === "invalid_scope") out.scopes = invalidScopeText(err.details);
  return out;
}

type Props = { server: McpServer; scope: ServerScope; abilities: ServerAbilities };

/** The saved message: what a new URL did (read again; back to review), or a wider requirement (back to review). */
function savedMessage(before: McpServer, after: McpServer, urlChanged: boolean, caChanged = false) {
  if (before.publishState === "published" && after.publishState === "pending") {
    toast.success("Server settings saved", `${after.name} left the catalog until a platform admin reviews ${urlChanged ? "its new URL" : caChanged ? "its new CA" : "what it now receives"}.`);
  } else if (urlChanged && after.lastRefreshError) {
    toast.warning("Server settings saved", "Its capabilities couldn't be read from the new URL. See the Overview tab.");
  } else {
    toast.success("Server settings saved", urlChanged ? "Its capabilities were read again from the new URL." : undefined);
  }
}

export function ServerSettingsTab({ server, scope, abilities }: Props) {
  const qc = useQueryClient();
  const dev = Boolean(useAuthConfig().data?.devAuthEnabled);
  const saved = formOf(server);
  const [form, setForm, revision] = useRevisionForm(saved, server.revision, { labels });
  const ownKeys = form.upstream.mode === "person_secret";
  // OAuth sign-in, each person's own key and the portal's own OAuth client each replace a requirement (one credential per call).
  const noRequirement = form.upstream.mode === "oauth" || form.upstream.mode === "machine_oauth" || ownKeys;
  const providers = useQuery(authProvidersQuery());
  const caps = useQuery(capabilitiesQuery(scope, server.id));
  const [parts, setParts] = useState<PartForm[]>(() => partsOf(server));
  const [secret, setSecret] = useState("");
  const [detected, setDetected] = useState<DetectResult>();
  const [submitted, setSubmitted] = useState(false);
  const [confirmingCapture, setConfirmingCapture] = useState<true | null>(null);
  const [tlsForm, setTlsForm] = useState<TlsForm>(emptyTlsForm);
  const kept = useCaptureRetention(server.teamSlug, false);
  const save = useMutation({
    mutationFn: async (_: { before: McpServer; urlChanged: boolean }) => {
      const authBody = settingsAuthBody(server, form, parts, secret, detected);
      // OAuth replaces a requirement (one credential per call): switching removes it.
      const requirement = noRequirement ? (server.requirement ? null : undefined) : requirementBody(form.requirement, server);
      return unwrap(
        await api.PATCH("/v1/teams/{team}/mcp-servers/{serverId}", {
          params: { path: { team: server.teamSlug, serverId: server.id }, header: ifMatch(server.revision) },
          body: {
            name: form.name.trim(),
            description: form.description,
            url: form.url.trim(),
            timeoutSeconds: form.timeoutSeconds,
            enabled: form.enabled,
            ...authBody,
            ...(requirement === undefined ? {} : { requirement }),
            ...(tlsBody(tlsForm) ? { tls: tlsBody(tlsForm) } : {}),
            ...(form.capturePayloads !== saved.capturePayloads ? { capturePayloads: form.capturePayloads } : {}),
          },
        }),
      );
    },
    onSuccess: (updated, { before, urlChanged }) => {
      setConfirmingCapture(null);
      setParts(partsOf(updated));
      setSecret("");
      setTlsForm(emptyTlsForm);
      setSubmitted(false);
      storeServer(qc, updated);
      // Overrides may have gone back to inherit, and every capability's requirement may differ.
      void qc.invalidateQueries({ queryKey: capabilitiesQuery(scope, server.id).queryKey });
      savedMessage(before, updated, urlChanged, caChanged);
    },
  });
  const canEdit = abilities.canEdit && scope.kind === "team";
  // Turned off, the provider and scopes left in the fields don't count.
  const requirement = form.requirement.on ? form.requirement : saved.requirement.on ? { on: false, providerId: "", scopes: [] } : saved.requirement;
  // Only the chosen mode's fields count.
  const upstream = countedUpstream(form.upstream, saved.upstream);
  const dirty =
    JSON.stringify({ ...form, name: form.name.trim(), url: form.url.trim(), requirement, upstream }) !== JSON.stringify(saved) ||
    ((form.upstream.mode === "static_header" || form.upstream.mode === "person_secret") && credentialsBody(parts, server) !== undefined) ||
    Boolean(secret) ||
    tlsDirty(tlsForm);
  // Parts of the server's own credential: required in static mode, optional (and only shown while some are stored) next to each person's key.
  const staticMode = form.upstream.mode === "static_header" || (ownKeys && parts.length > 0);
  // Another origin never keeps a stored value (F-1): every part is entered again.
  const originMoved = !sameOrigin(server.url, form.url.trim());
  const partErrors = staticMode ? partProblems(parts, { originMoved }) : {};
  const noParts = form.upstream.mode === "static_header" && parts.length === 0;
  const problems = {
    ...serverProblems(form, { dev }),
    ...oauthProblems(form.upstream, { server, detected, secret }),
    ...machineProblems(form.upstream.mode, form.upstream.machine, { server, secret, url: form.url }),
  };
  const reqErrors = requirementErrors(form.requirement, save.error, submitted);
  const secretErrors = ownKeys ? secretProblems(form.upstream.secret) : {};
  const tlsErrors = { ...(submitted ? tlsProblems(tlsForm, server) : {}), ...tlsRefusal(save.error) };
  const invalid =
    Object.keys(tlsProblems(tlsForm, server)).length > 0 ||
    Object.keys(problems).length > 0 ||
    Object.keys(secretErrors).length > 0 ||
    Object.keys(partErrors).length > 0 ||
    noParts ||
    Object.keys(requirementErrors(form.requirement, null, true)).length > 0;
  const shown = submitted ? problems : {};
  const refused = serverFieldErrors(save.error).url;
  const errors = { ...shown, url: shown.url ?? refused };
  const reqRefused = save.error instanceof ApiError && (save.error.code === "provider_not_found" || save.error.code === "provider_not_allowed" || save.error.code === "invalid_scope");
  const set = (patch: Partial<SettingsForm>) => {
    // The refusal was for the URL that was sent: editing it clears it.
    if (patch.url !== undefined && refused) save.reset();
    setForm((f) => ({ ...f, ...patch }));
  };
  const fields = { form, set, errors, dev, disabled: !canEdit };
  const urlChanged = form.url.trim() !== server.url;
  const requirementWidens = requirementBody(form.requirement, server) !== undefined && serverChangeWidens(server, form.requirement, caps.data, providers.data);
  // A refused save about the sign-in, in words (the save bar shows the error).
  const authError = useMemo(() => {
    const d = describeAuthError(save.error);
    return d ? new Error(d.title ? `${d.title}. ${d.message}` : d.message) : undefined;
  }, [save.error]);
  const change = authChange(server, form.upstream, { urlChanged, detected });
  const caChanged = changesCa(tlsForm, server);
  const leavesCatalog = canEdit && reviewedAgain(server) && (urlChanged || (!noRequirement && requirementWidens) || Boolean(change.review) || caChanged);
  const providerChanges = Boolean(server.requirement) && (!form.requirement.on || form.requirement.providerId !== server.requirement?.providerId);
  const resetsOverrides = providerChanges ? (caps.data ?? []).filter((c) => !c.goneAt && c.requirementOverride.mode === "scopes").length : 0;

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
      onSave={() => {
        setSubmitted(true);
        if (invalid) return;
        if (!saved.capturePayloads && form.capturePayloads) setConfirmingCapture(true);
        else save.mutate({ before: server, urlChanged });
      }}
      onDiscard={() => {
        setForm(saved);
        setParts(partsOf(server));
        setSecret("");
        setTlsForm(emptyTlsForm);
        setDetected(undefined);
        setSubmitted(false);
      }}
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
          onDetected={(r) => {
            setDetected(r);
            setForm((f) => ({ ...f, upstream: applyDetection(f.upstream, r, server.oauth) }));
          }}
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
        onConfirm={() => save.mutate({ before: server, urlChanged })}
        tone="primary"
        title={`Record what's sent to ${server.name}?`}
        description={`${captureWhat} This covers calls through every gateway that offers its capabilities, including other teams' gateways; their callers are told it records. Readable by ${server.teamName}'s owners and admins and by platform staff; every view is audited. ${kept ?? keptFallback}`}
        confirmLabel="Record call contents"
      />
    </SettingsPage>
  );
}
