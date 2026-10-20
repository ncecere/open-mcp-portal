/*
 * Add auth provider (?form=new over the list; platform admins): first where
 * to start (a preset such as GitHub, with the values its URLs need, like
 * Microsoft's tenant, or a custom provider), then the provider's fields,
 * pre-filled by the preset (check them against the provider's
 * documentation). The redirect URI to register at the provider is shown with
 * a copy button. The new provider opens on its record.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api, unwrap } from "@/api/client";
import { adminAuthProviderQuery, adminAuthProvidersKey } from "@/api/queries";
import { type AuthProvider, type AuthProviderPreset, callbackPath, type PresetName } from "@/components/providers/labels";
import { FormPage, FormSection } from "@/components/templates/form-page";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Field } from "@/components/ui/field/field";
import { Input } from "@/components/ui/input/input";
import { RadioGroup } from "@/components/ui/radio-group/radio-group";
import { TextLink } from "@/components/ui/text-link/text-link";
import { toast } from "@/components/ui/toast/toast";
import m from "@/components/servers/servers.module.css";
import { useAuthConfig } from "@/session";
import { AppFields, EndpointFields, IdentityFields, NarrowingFields, RequestFields } from "./fields";
import { createBody, emptyForm, formFromPreset, type ProviderForm, providerProblems, serverProblems } from "./form";

const presetsKey = [...adminAuthProvidersKey, "presets"];

type Start = PresetName | "custom";

export function CreateProviderForm({ onClose }: { onClose: () => void }) {
  const presets = useQuery({ queryKey: presetsKey, queryFn: async () => unwrap(await api.GET("/v1/admin/auth-provider-presets")) });
  const [start, setStart] = useState<Start>("github");
  const [params, setParams] = useState<Record<string, string>>({});
  const [form, setForm] = useState<ProviderForm | null>(null);
  const [submitted, setSubmitted] = useState(false);
  const preset = presets.data?.find((p) => p.preset === start);
  if (form) return <DetailsStep initial={form} preset={preset} onBack={() => setForm(null)} onClose={onClose} />;

  const missing = (preset?.urlParameters ?? []).filter((p) => !(params[p.name] ?? p.default ?? "").trim());
  return (
    <FormPage
      label="Add auth provider"
      title="Add auth provider"
      description="An OAuth app people connect their accounts with, so tools can act as them. Start from a preset to pre-fill the endpoints and quirks, then check them against the provider's documentation."
      onClose={onClose}
      onSubmit={() => {
        setSubmitted(true);
        if (missing.length) return;
        const values = Object.fromEntries((preset?.urlParameters ?? []).map((p) => [p.name, params[p.name] ?? p.default ?? ""]));
        setForm(preset ? formFromPreset(preset, values) : emptyForm);
      }}
      submitLabel="Continue"
      loading={presets.isLoading}
      dirty={false}
    >
      <ErrorAlert error={presets.error} title="Couldn't load the presets" onRetry={() => void presets.refetch()} />
      <FormSection title="Start from">
        <RadioGroup<Start>
          className={m.wide}
          legend="Provider"
          description="A preset only pre-fills the form; you can change every field."
          value={start}
          onValueChange={setStart}
          options={[
            ...(presets.data ?? []).map((p) => ({ value: p.preset, label: p.name, description: p.notes })),
            { value: "custom" as const, label: "Custom OAuth 2.0 provider", description: "Any provider with the authorization code flow, including internal ones." },
          ]}
        />
        {preset?.urlParameters.map((p) => (
          <Field key={p.name} label={p.label} description={`Fills in {${p.name}} in the preset's addresses.`} error={submitted && missing.includes(p) ? "Enter a value." : undefined}>
            <Input spellCheck={false} autoComplete="off" value={params[p.name] ?? p.default ?? ""} onChange={(e) => setParams((v) => ({ ...v, [p.name]: e.target.value }))} />
          </Field>
        ))}
        {preset && (
          <p className={m.wide}>
            Create the OAuth app in{" "}
            <TextLink href={preset.docsUrl} target="_blank" rel="noreferrer">
              {preset.name}&apos;s developer settings
            </TextLink>
            .
          </p>
        )}
      </FormSection>
    </FormPage>
  );
}

type DetailsProps = { initial: ProviderForm; preset?: AuthProviderPreset; onBack: () => void; onClose: () => void };

function DetailsStep({ initial, preset, onBack, onClose }: DetailsProps) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const dev = Boolean(useAuthConfig().data?.devAuthEnabled);
  const formRef = useRef<HTMLFormElement>(null);
  const [form, setFormState] = useState(initial);
  const [secret, setSecret] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [created, setCreated] = useState<AuthProvider | null>(null);
  const create = useMutation({
    mutationFn: async () => unwrap(await api.POST("/v1/admin/auth-providers", { body: createBody(form, secret) })),
    onSuccess: (p) => {
      qc.setQueryData(adminAuthProviderQuery(p.id).queryKey, p);
      void qc.invalidateQueries({ queryKey: adminAuthProvidersKey });
      void qc.invalidateQueries({ queryKey: ["auth-providers"] });
      toast.success(`${p.name} was added`, "Register its redirect URI at the provider if you haven't yet.");
      setCreated(p);
    },
  });
  // Saved: the form no longer counts as unsaved in this render, so its guard lets the navigation through.
  useEffect(() => {
    if (created) void navigate({ to: "/admin/auth-providers/$providerId", params: { providerId: created.id }, replace: true });
  }, [created, navigate]);
  const problems = providerProblems(form, { creating: true, secret, hasSecret: false, dev });
  const refused = serverProblems(create.error);
  const errors = { ...(submitted ? problems : {}), ...refused };
  const set = (patch: Partial<ProviderForm>) => {
    if (Object.keys(refused).length) create.reset();
    setFormState((f) => ({ ...f, ...patch }));
  };
  const fields = { form, set, errors };
  return (
    <FormPage
      label="Add auth provider"
      title={preset ? `Add ${preset.name}` : "Add a custom provider"}
      description="Platform admins configure the OAuth app once; each person then connects their own account."
      onClose={onClose}
      onSubmit={() => {
        setSubmitted(true);
        if (Object.keys(problems).length) {
          requestAnimationFrame(() => formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());
          return;
        }
        create.mutate();
      }}
      submitLabel="Add provider"
      busy={create.isPending}
      dirty={created ? false : undefined}
      formRef={formRef}
      startActions={
        <Button variant="ghost" onClick={onBack}>
          <ArrowLeft aria-hidden /> Change starting point
        </Button>
      }
    >
      {preset?.notes && (
        <Alert tone="info" title={`About ${preset.name}`}>
          {preset.notes}
        </Alert>
      )}
      <FormSection title="Provider">
        <IdentityFields {...fields} creating />
      </FormSection>
      <FormSection title="OAuth app">
        <AppFields {...fields} redirectUri={`${globalThis.location?.origin ?? ""}${callbackPath}`} secret={secret} setSecret={setSecret} hasSecret={false} />
      </FormSection>
      <FormSection title="Endpoints">
        <EndpointFields {...fields} />
      </FormSection>
      <FormSection title="Authorization request">
        <RequestFields {...fields} />
      </FormSection>
      <FormSection title="Token scopes per call">
        <NarrowingFields {...fields} />
      </FormSection>
      <Alert tone="info" title="Starts restricted">
        A new provider is restricted: no team or server may require it until you list them under Access on its page, after you add it.
      </Alert>
      <ErrorAlert error={Object.keys(refused).length ? undefined : create.error} title="Couldn't add the provider" />
    </FormPage>
  );
}
