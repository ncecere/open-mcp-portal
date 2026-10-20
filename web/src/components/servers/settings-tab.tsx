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
 * header, each person's OAuth sign-in and the portal's own OAuth client
 * (machine-auth.ts), with the same review warnings.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
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
import { DangerAction, DangerZone, SettingsPage, SettingsSection } from "../templates/settings-page";
import { Button } from "@/components/ui/button/button";
import { CopyField } from "@/components/ui/copy-field/copy-field";
import { Field } from "@/components/ui/field/field";
import { Input, Textarea } from "@/components/ui/input/input";
import { toast } from "@/components/ui/toast/toast";
import { describeAuthError } from "./auth-errors";
import { PresentPersonSwitch, relaxesServerSwitch } from "./presence";
import { AuthModeFields } from "./auth-mode-fields";
import type { McpServer } from "./labels";
import { type RequirementForm, requirementBody, requirementFormOf, reviewedAgain, serverChangeWidens } from "./requirement";
import { RequirementFields } from "./requirement-section";
import { capabilitiesQuery, invalidateServer, type ServerAbilities, type ServerScope, storeServer } from "./scope";
import { CredentialFields } from "./credential-fields";
import { credentialsBody, partProblems, type PartForm, partsOf } from "./credentials";
import { EnabledSwitch, type ServerForm, serverFieldErrors, serverProblems, TimeoutField, UrlField, urlProblem } from "./server-fields";
import { sameOrigin } from "./origin";
import { machineProblems } from "./machine-auth";
import { AuthChangeNotes, settingsAuthBody } from "./settings-auth";
import { applyDetection, authChange, authModeOf, countedUpstream, type DetectResult, oauthProblems, upstreamFormOf, type UpstreamForm } from "./upstream-auth";

type SettingsForm = ServerForm & { requirement: RequirementForm; capturePayloads: boolean; upstream: UpstreamForm; requiresPresentPerson: boolean };

const formOf = (x: McpServer): SettingsForm => ({
  name: x.name,
  description: x.description,
  url: x.url,
  timeoutSeconds: x.timeoutSeconds,
  enabled: x.enabled,
  requirement: requirementFormOf(x),
  capturePayloads: x.capturePayloads ?? false,
  upstream: upstreamFormOf(x),
  requiresPresentPerson: x.requiresPresentPerson ?? false,
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
  requiresPresentPerson: "Require a present person",
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
function savedMessage(before: McpServer, after: McpServer, urlChanged: boolean) {
  if (before.publishState === "published" && after.publishState === "pending") {
    toast.success("Server settings saved", `${after.name} left the catalog until a platform admin reviews ${urlChanged ? "its new URL" : "what it now receives"}.`);
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
  // OAuth sign-in and the portal's own OAuth client each replace a requirement (one credential per call).
  const oneCredential = form.upstream.mode === "oauth" || form.upstream.mode === "machine_oauth";
  const providers = useQuery(authProvidersQuery());
  const caps = useQuery(capabilitiesQuery(scope, server.id));
  const [parts, setParts] = useState<PartForm[]>(() => partsOf(server));
  const [secret, setSecret] = useState("");
  const [detected, setDetected] = useState<DetectResult>();
  const [submitted, setSubmitted] = useState(false);
  const [confirmingCapture, setConfirmingCapture] = useState<true | null>(null);
  const kept = useCaptureRetention(server.teamSlug, false);
  const save = useMutation({
    mutationFn: async (_: { before: McpServer; urlChanged: boolean }) => {
      const authBody = settingsAuthBody(server, form, parts, secret, detected);
      // OAuth replaces a requirement (one credential per call): switching removes it.
      const requirement = oneCredential ? (server.requirement ? null : undefined) : requirementBody(form.requirement, server);
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
            ...(form.capturePayloads !== saved.capturePayloads ? { capturePayloads: form.capturePayloads } : {}),
            ...(form.requiresPresentPerson !== saved.requiresPresentPerson ? { requiresPresentPerson: form.requiresPresentPerson } : {}),
          },
        }),
      );
    },
    onSuccess: (updated, { before, urlChanged }) => {
      setConfirmingCapture(null);
      setParts(partsOf(updated));
      setSecret("");
      setSubmitted(false);
      storeServer(qc, updated);
      // Overrides may have gone back to inherit, and every capability's requirement may differ.
      void qc.invalidateQueries({ queryKey: capabilitiesQuery(scope, server.id).queryKey });
      savedMessage(before, updated, urlChanged);
    },
  });
  const canEdit = abilities.canEdit && scope.kind === "team";
  // Turned off, the provider and scopes left in the fields don't count.
  const requirement = form.requirement.on ? form.requirement : saved.requirement.on ? { on: false, providerId: "", scopes: [] } : saved.requirement;
  // Only the chosen mode's fields count.
  const upstream = countedUpstream(form.upstream, saved.upstream);
  const dirty =
    JSON.stringify({ ...form, name: form.name.trim(), url: form.url.trim(), requirement, upstream }) !== JSON.stringify(saved) ||
    (form.upstream.mode === "static_header" && credentialsBody(parts, server) !== undefined) ||
    Boolean(secret);
  const staticMode = form.upstream.mode === "static_header";
  // Another origin never keeps a stored value (F-1): every part is entered again.
  const originMoved = !sameOrigin(server.url, form.url.trim());
  const partErrors = staticMode ? partProblems(parts, { originMoved }) : {};
  const noParts = staticMode && parts.length === 0;
  const problems = {
    ...serverProblems(form, { dev }),
    ...oauthProblems(form.upstream, { server, detected, secret }),
    ...machineProblems(form.upstream.mode, form.upstream.machine, { server, secret, url: form.url }),
  };
  const reqErrors = requirementErrors(form.requirement, save.error, submitted);
  const invalid = Object.keys(problems).length > 0 || Object.keys(partErrors).length > 0 || noParts || Object.keys(requirementErrors(form.requirement, null, true)).length > 0;
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
  const relaxesPresence = relaxesServerSwitch(saved.requiresPresentPerson, form.requiresPresentPerson, caps.data);
  const leavesCatalog = canEdit && reviewedAgain(server) && (urlChanged || (!oneCredential && requirementWidens) || Boolean(change.review) || relaxesPresence);
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
      error={errors.url || reqRefused ? undefined : (authError ?? save.error)}
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
      <SettingsSection title="Authentication" description="How the portal proves itself to the server: nothing, a static credential of headers, a token, Basic or a query key (stored encrypted), or each person's own OAuth sign-in.">
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
          disabled={!canEdit}
          headerFields={<CredentialFields parts={parts} setParts={setParts} errors={submitted ? partErrors : {}} disabled={!canEdit} noParts={submitted && noParts} />}
          notes={canEdit && <AuthChangeNotes server={server} change={change} leavesCatalog={leavesCatalog} />}
        />
      </SettingsSection>
      <SettingsSection
        title="User authorization"
        description="Whether calls to this server carry each caller's own token for another service, such as GitHub. Each capability can override it on the Capabilities tab."
      >
        {oneCredential ? (
          <Alert tone="info" title={form.upstream.mode === "oauth" ? "Not with OAuth sign-in" : "Not with the portal's own OAuth client"}>
            {form.upstream.mode === "oauth"
              ? "Each call already carries the person's own token for this server, so it can't carry another account too."
              : "Each call already carries the portal's own token for this server, so it can't carry another account too."}
            {server.requirement && authModeOf(server) !== "oauth" ? ` Saving removes the requirement (${server.requirement.providerName}).` : ""}
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
        {leavesCatalog && !oneCredential && requirementWidens && (
          <Alert tone="warning" title="The server will leave the catalog">
            Your team needs approval to publish, and this sends more to the server than before (a provider, another provider or a new scope), so it&apos;s reviewed
            again: once you save, {server.name} is out of the company catalog until a platform admin approves it. Removing or narrowing a requirement never needs a
            review.
          </Alert>
        )}
      </SettingsSection>
      <SettingsSection title="Calls from agents" description="Agent platforms the portal trusts can call this server's tools for a person. The call is the person's, and the platform says whether they are present.">
        <PresentPersonSwitch
          checked={form.requiresPresentPerson}
          onChange={(requiresPresentPerson) => set({ requiresPresentPerson })}
          disabled={!canEdit}
          leaves={relaxesPresence}
          server={server}
        />
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

function DeleteServer({ server }: { server: McpServer }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [confirming, setConfirming] = useState<McpServer | null>(null);
  const del = useMutation({
    mutationFn: async () => unwrap(await api.DELETE("/v1/teams/{team}/mcp-servers/{serverId}", { params: { path: { team: server.teamSlug, serverId: server.id } } })),
    onSuccess: () => {
      setConfirming(null);
      toast.success(`${server.name} was deleted`);
      // Leave first: the record would load again and find nothing.
      void navigate({ to: "/teams/$team/servers", params: { team: server.teamSlug }, replace: true }).then(() => invalidateServer(qc, server));
    },
  });
  return (
    <DangerZone>
      <DangerAction
        title="Delete this server"
        description={`Removes ${server.name} and everything read from it${server.publishState === "published" ? ", and takes it off the catalog" : ""}. This can't be undone.`}
        action={
          <Button variant="danger" onClick={() => setConfirming(server)}>
            Delete server
          </Button>
        }
      />
      <ConfirmMutationDialog
        target={confirming}
        onClose={() => setConfirming(null)}
        mutation={del}
        onConfirm={() => del.mutate()}
        title={`Delete ${server.name}?`}
        description="Its capabilities, health checks and catalog entry are deleted. Its slug becomes free for another server."
        confirmLabel="Delete server"
      />
    </DangerZone>
  );
}
