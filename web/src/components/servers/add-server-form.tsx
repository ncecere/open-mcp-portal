/*
 * Add MCP server (?form=new over the team's server list): name and slug
 * (suggested from the name, never changed afterwards), description, the
 * address, timeout and the switch, then how the portal authenticates:
 * Detect sign-in, and None, a static header, each person's own OAuth
 * sign-in or each person's own key (auth-mode-fields.tsx). The portal reads
 * the server's capabilities at once, except in OAuth mode (someone signs in
 * first: the record page opens on "Authorize to read its tools", setup.tsx)
 * and in own-key mode (an editor enters theirs under Account › My connections
 * first, person-secret-card.tsx).
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { api, type Schemas, unwrap } from "../../api/client";
import { teamServersKey } from "../../api/queries";
import { useAuthConfig } from "../../session";
import { FormPage, FormSection } from "../templates/form-page";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Field } from "@/components/ui/field/field";
import { Input, Textarea } from "@/components/ui/input/input";
import { toast } from "@/components/ui/toast/toast";
import { describeAuthError } from "./auth-errors";
import { AuthModeFields } from "./auth-mode-fields";
import { defaultIdentity, identityBasisText, useIdentityDefault } from "./identity-default";
import { serverSlug, slugPattern } from "./labels";
import { firstDiscoveryKey } from "./scope";
import { CredentialFields } from "./credential-fields";
import { credentialsBody, newPart, partProblems, type PartForm } from "./credentials";
import { secretInput, secretProblems } from "./person-secret";
import { EnabledSwitch, type ServerForm, serverFieldErrors, serverProblems, TimeoutField, UrlField, urlProblem } from "./server-fields";
import { machineInput, machineProblems } from "./machine-auth";
import { applyDetection, type DetectResult, oauthInput, oauthProblems, upstreamFormOf, type UpstreamForm } from "./upstream-auth";
import m from "./servers.module.css";

const empty: ServerForm = { name: "", description: "", url: "", timeoutSeconds: 30, enabled: true };

const slugProblem = (slug: string) =>
  !slug ? "Enter a slug." : slugPattern.test(slug) ? undefined : "Use 1 to 48 lowercase letters, digits and hyphens, starting and ending with a letter or digit.";

/**
 * The request body's authentication: the mode, its credential parts or OAuth settings, and the identity switch (left
 * out while the default for the address isn't known: the server then decides the same way).
 */
function authBody(parts: PartForm[], u: UpstreamForm, secret: string, sendIdentity: boolean | undefined, detected?: DetectResult) {
  const credentials = u.mode === "static_header" ? credentialsBody(parts) : undefined;
  const mode = u.mode === "static_header" && !credentials?.length ? "none" : u.mode;
  return {
    authMode: mode,
    ...(credentials?.length ? { credentials } : {}),
    ...(mode === "oauth" ? { oauth: oauthInput(u.oauth, secret, detected) } : {}),
    ...(mode === "person_secret" ? { personSecret: secretInput(u.secret) } : {}),
    ...(mode === "machine_oauth" ? { machineOAuth: machineInput(u.machine, secret) } : {}),
    ...(sendIdentity === undefined ? {} : { sendIdentity }),
  };
}

export function AddServerForm({ team, onClose }: { team: string; onClose: () => void }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const dev = Boolean(useAuthConfig().data?.devAuthEnabled);
  const formRef = useRef<HTMLFormElement>(null);
  const [form, setForm] = useState(empty);
  const [slug, setSlug] = useState("");
  const [slugEdited, setSlugEdited] = useState(false);
  const [parts, setParts] = useState<PartForm[]>(() => [newPart()]);
  const [upstream, setUpstream] = useState<UpstreamForm>(() => upstreamFormOf());
  // The identity switch follows the address until someone moves it (decision 64).
  const [identityTouched, setIdentityTouched] = useState(false);
  const basis = useIdentityDefault(team, form.url, upstream.mode, urlProblem(form.url, dev));
  const followed = defaultIdentity(basis);
  const sendIdentity = identityTouched ? upstream.sendIdentity : (followed ?? true);
  const [detected, setDetected] = useState<DetectResult>();
  const [secret, setSecret] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [created, setCreated] = useState<Schemas["McpServerCreated"] | null>(null);
  const create = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/teams/{team}/mcp-servers", {
          params: { path: { team } },
          body: {
            slug,
            name: form.name.trim(),
            description: form.description.trim() || undefined,
            url: form.url.trim(),
            ...authBody(parts, upstream, secret, identityTouched ? upstream.sendIdentity : followed, detected),
            timeoutSeconds: form.timeoutSeconds,
            enabled: form.enabled,
            // Recording call contents starts off: owners and admins turn it on in Settings, after a confirmation.
            capturePayloads: false,
          },
        }),
      ),
    onSuccess: (created) => {
      const s = created.server;
      qc.setQueryData(firstDiscoveryKey(s.id), created);
      void qc.invalidateQueries({ queryKey: teamServersKey(team) });
      if (created.setupRequired) toast.success(`${s.name} was added`, s.authMode === "person_secret" ? "Enter your key next, so the portal can read its tools." : "Authorize next, so the portal can read its tools.");
      else if (created.refreshError) toast.warning(`${s.name} was added`, "Its capabilities couldn't be read yet.");
      else toast.success(`${s.name} was added`);
      setCreated(created);
    },
  });
  // Saved: the form stops counting as unsaved (dirty={false} below) in this render, so its guard lets the
  // navigation through; the effect runs after the form's guard has taken that in (children's effects run first).
  // Navigating from onSuccess raced it: a quick reply arrived before the busy state rendered.
  useEffect(() => {
    // Replace the form's history entry: Back from the new server returns to the list.
    if (created) void navigate({ to: "/teams/$team/servers/$serverId", params: { team, serverId: created.server.id }, replace: true });
  }, [created, navigate, team]);
  // Only the chosen mode's fields count.
  const staticMode = upstream.mode === "static_header";
  const partErrors = staticMode ? partProblems(parts) : {};
  const noParts = staticMode && parts.length === 0;
  const secretErrors = upstream.mode === "person_secret" ? secretProblems(upstream.secret) : {};
  const allProblems = () => ({ ...serverProblems(form, { dev }), ...oauthProblems(upstream, { detected, secret }), ...machineProblems(upstream.mode, upstream.machine, { secret, url: form.url }) });
  const problems = submitted ? allProblems() : {};
  const fromServer = serverFieldErrors(create.error);
  // A refusal belongs to the value that was sent: editing that field clears it, so the form can be sent again.
  const set = (patch: Partial<ServerForm>) => {
    if (patch.url !== undefined && fromServer.url) create.reset();
    setForm((f) => ({ ...f, ...patch }));
  };
  const slugError = (submitted ? slugProblem(slug) : undefined) ?? fromServer.slug;
  const errors = { ...problems, url: problems.url ?? fromServer.url };
  const shownError = fromServer.slug || fromServer.url ? undefined : create.error;

  const submit = () => {
    setSubmitted(true);
    if (Object.keys(allProblems()).length > 0 || Object.keys(secretErrors).length > 0 || Object.keys(partErrors).length > 0 || noParts || slugProblem(slug)) {
      requestAnimationFrame(() => formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());
      return;
    }
    create.mutate();
  };
  const fields = { form, set, errors, dev };
  return (
    <FormPage
      label="Add MCP server"
      title="Add MCP server"
      description="A remote MCP server your team runs, reached over Streamable HTTP. It stays private to the team until it's published to the catalog."
      onClose={onClose}
      onSubmit={submit}
      submitLabel="Add server"
      busy={create.isPending}
      dirty={created ? false : undefined}
      formRef={formRef}
    >
      <FormSection title="Server">
        <Field label="Name" error={errors.name}>
          <Input
            maxLength={100}
            value={form.name}
            onChange={(e) => {
              set({ name: e.target.value });
              if (!slugEdited) setSlug(serverSlug(e.target.value));
            }}
          />
        </Field>
        <Field label="Slug" description="Can't be changed later. Gateways name its tools slug__tool, so keep it short." error={slugError}>
          <Input
            spellCheck={false}
            autoComplete="off"
            maxLength={48}
            value={slug}
            onChange={(e) => {
              setSlugEdited(true);
              if (fromServer.slug) create.reset();
              setSlug(e.target.value);
            }}
          />
        </Field>
        <Field label="Description" labelHint="Optional" description="What the server is for. Shown in the catalog once published." className={m.wide}>
          <Textarea maxLength={2000} value={form.description} onChange={(e) => set({ description: e.target.value })} />
        </Field>
      </FormSection>
      <FormSection title="Connection">
        <div className={m.wide}>
          <UrlField {...fields} />
        </div>
        <TimeoutField {...fields} />
        <div className={m.switchCell}>
          <EnabledSwitch {...fields} />
        </div>
      </FormSection>
      <FormSection title="Authentication">
        <AuthModeFields
          team={team}
          url={form.url}
          urlError={urlProblem(form.url, dev)}
          value={{ ...upstream, sendIdentity }}
          onChange={(next) => {
            if (next.sendIdentity !== sendIdentity) setIdentityTouched(true);
            setUpstream(next);
          }}
          identityNote={identityTouched ? undefined : identityBasisText(basis)}
          detected={detected}
          onDetected={(r) => {
            setDetected(r);
            setUpstream((u) => applyDetection(u, r));
          }}
          onUseUrl={(url) => set({ url })}
          secret={secret}
          setSecret={setSecret}
          errors={problems}
          secretErrors={submitted ? secretErrors : {}}
          headerFields={<CredentialFields parts={parts} setParts={setParts} errors={submitted ? partErrors : {}} noParts={submitted && noParts} />}
        />
      </FormSection>
      <ErrorAlert error={shownError} title={describeAuthError(shownError)?.title ?? "Couldn't add the server"} describe={describeAuthError} />
    </FormPage>
  );
}
