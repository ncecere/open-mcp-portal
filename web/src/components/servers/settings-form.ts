/*
 * The state behind a server's Settings tab (settings-tab.tsx): the form over the server (If-Match on its revision),
 * the replace-only credential parts, client secret and TLS material next to it, the save, and everything derived
 * from them: what's dirty, each section's problems, and whether saving sends the server back to review.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api, ApiError, ifMatch, unwrap } from "../../api/client";
import { authProvidersQuery } from "../../api/queries";
import { useAuthConfig } from "../../session";
import { invalidScopeText, scopesProblem } from "../providers/labels";
import { useRevisionForm } from "../templates/revision-form";
import { toast } from "@/components/ui/toast/toast";
import { describeAuthError } from "./auth-errors";
import { credentialsBody, partProblems, type PartForm, partsOf } from "./credentials";
import { endpointFormsOf, endpointsBody, endpointProblems, endpointReviewChanged, type EndpointForm } from "./endpoints";
import type { McpServer } from "./labels";
import { machineProblems } from "./machine-auth";
import { sameOrigin } from "./origin";
import { secretProblems } from "./person-secret";
import { type ProtectionForm, protectionBody, protectionFormOf, protectionProblems } from "./protection-fields";
import { type RequirementForm, requirementBody, requirementFormOf, reviewedAgain, serverChangeWidens } from "./requirement";
import { capabilitiesQuery, type ServerAbilities, type ServerScope, storeServer } from "./scope";
import { type ServerForm, serverFieldErrors, serverProblems } from "./server-fields";
import { settingsAuthBody } from "./settings-auth";
import { changesCa, emptyTlsForm, tlsBody, tlsDirty, tlsProblems, tlsRefusal, type TlsForm } from "./tls";
import { applyDetection, authChange, countedUpstream, type DetectResult, oauthProblems, upstreamFormOf, type UpstreamForm } from "./upstream-auth";

export type SettingsForm = ServerForm & { requirement: RequirementForm; capturePayloads: boolean; upstream: UpstreamForm; protection: ProtectionForm; endpoints: EndpointForm[] };

const formOf = (x: McpServer): SettingsForm => ({
  name: x.name,
  description: x.description,
  url: x.url,
  timeoutSeconds: x.timeoutSeconds,
  enabled: x.enabled,
  requirement: requirementFormOf(x),
  capturePayloads: x.capturePayloads ?? false,
  upstream: upstreamFormOf(x),
  protection: protectionFormOf(x),
  endpoints: endpointFormsOf(x),
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
  protection: "Upstream protection",
  endpoints: "Additional endpoints",
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

/** The saved message: what a new URL did (read again; back to review), or a wider requirement (back to review). */
function savedMessage(before: McpServer, after: McpServer, urlChanged: boolean, caChanged = false, endpointsChanged = false) {
  if (before.publishState === "published" && after.publishState === "pending") {
    toast.success("Server settings saved", `${after.name} left the catalog until a platform admin reviews ${urlChanged ? "its new URL" : caChanged ? "its new CA" : endpointsChanged ? "its additional destinations" : "what it now receives"}.`);
  } else if (urlChanged && after.lastRefreshError) {
    toast.warning("Server settings saved", "Its capabilities couldn't be read from the new URL. See the Overview tab.");
  } else {
    toast.success("Server settings saved", urlChanged ? "Its capabilities were read again from the new URL." : undefined);
  }
}

type Options = { server: McpServer; scope: ServerScope; abilities: ServerAbilities };

export function useServerSettingsForm({ server, scope, abilities }: Options) {
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
  const save = useMutation({
    mutationFn: async (_: { before: McpServer; urlChanged: boolean }) => {
      const authBody = settingsAuthBody(server, form, parts, secret, detected);
      const endpointBody = endpointsBody(form.endpoints, server, form.upstream.mode);
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
            ...protectionBody(form.protection, saved.protection),
            ...authBody,
            ...(endpointBody === undefined ? {} : { endpoints: endpointBody }),            ...(requirement === undefined ? {} : { requirement }),
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
      setForm((f) => ({ ...f, endpoints: endpointFormsOf(updated) }));
      setSubmitted(false);
      storeServer(qc, updated);
      // Overrides may have gone back to inherit, and every capability's requirement may differ.
      void qc.invalidateQueries({ queryKey: capabilitiesQuery(scope, server.id).queryKey });
      savedMessage(before, updated, urlChanged, caChanged, endpointChanged);
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
  const endpointBlocked = !["none", "static_header"].includes(form.upstream.mode) || form.requirement.on || server.tls != null || tlsDirty(tlsForm);
  const endpointChanged = endpointReviewChanged(form.endpoints, server) || (form.endpoints.length > 0 && form.upstream.mode !== saved.upstream.mode);
  const invalid =
    Object.keys(endpointProblems(form.endpoints, { ...server, url: form.url }, form.upstream.mode, dev, endpointBlocked)).length > 0 ||
    Object.keys(protectionProblems(form.protection)).length > 0 ||
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
  const leavesCatalog = canEdit && reviewedAgain(server) && (urlChanged || (!noRequirement && requirementWidens) || Boolean(change.review) || caChanged || endpointChanged);
  const providerChanges = Boolean(server.requirement) && (!form.requirement.on || form.requirement.providerId !== server.requirement?.providerId);
  const resetsOverrides = providerChanges ? (caps.data ?? []).filter((c) => !c.goneAt && c.requirementOverride.mode === "scopes").length : 0;


  /** Save: shows the problems first, and asks before recording call contents for the first time. */
  const submit = () => {
    setSubmitted(true);
    if (invalid) return;
    if (!saved.capturePayloads && form.capturePayloads) setConfirmingCapture(true);
    else save.mutate({ before: server, urlChanged });
  };
  const confirmCapture = () => save.mutate({ before: server, urlChanged });
  const discard = () => {
    setForm(saved);
    setParts(partsOf(server));
    setSecret("");
    setTlsForm(emptyTlsForm);
    setDetected(undefined);
    setSubmitted(false);
  };
  /** What "Detect" found at the URL: kept, and applied to the sign-in fields. */
  const applyDetected = (r: DetectResult) => {
    setDetected(r);
    setForm((f) => ({ ...f, upstream: applyDetection(f.upstream, r, server.oauth) }));
  };

  return {
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
  };
}
