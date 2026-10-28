/*
 * Create service account (?form=new over the list; the team's owners and
 * admins): a name (lower-case letters, digits and dashes, unique in the
 * team), a description, the role used for minimum roles (member or editor,
 * decision 22) and the switch. The new account opens on its Keys tab, where
 * its first key is created.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { api, ApiError, unwrap } from "../../../api/client";
import { ScopeEditor, scopeProblem, type ToolScope } from "../../../components/tool-scope";
import { FormPage, FormSection } from "../../../components/templates/form-page";
import m from "../../../components/servers/servers.module.css";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Field } from "@/components/ui/field/field";
import { Input, Textarea } from "@/components/ui/input/input";
import { Switch } from "@/components/ui/switch/switch";
import { toast } from "@/components/ui/toast/toast";
import { RoleChoice } from "./role-choice";
import { nameProblem, type ServiceAccount, type ServiceAccountRole, storeServiceAccount, whatIsAServiceAccount } from "./labels";

export function CreateServiceAccountForm({ team, onClose }: { team: string; onClose: () => void }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const formRef = useRef<HTMLFormElement>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [role, setRole] = useState<ServiceAccountRole>("member");
  const [enabled, setEnabled] = useState(true);
  const [toolScope, setToolScope] = useState<ToolScope>(null);
  const [scopeDraftProblem, setScopeDraftProblem] = useState<string>();
  const [submitted, setSubmitted] = useState(false);
  const [created, setCreated] = useState<ServiceAccount | null>(null);
  const create = useMutation({
    mutationFn: async () =>
      unwrap(await api.POST("/v1/teams/{team}/service-accounts", { params: { path: { team } }, body: { name, description: description.trim() || undefined, role, enabled, toolScope } })),
    onSuccess: (a) => {
      storeServiceAccount(qc, a);
      toast.success(`${a.name} was created`, "Create its first key.");
      setCreated(a);
    },
  });
  // Saved: the form no longer counts as unsaved in this render, so its guard lets the navigation through.
  useEffect(() => {
    if (!created) return;
    void navigate({ to: "/teams/$team/service-accounts/$serviceAccountId", params: { team, serviceAccountId: created.id }, search: { tab: "keys" }, replace: true });
  }, [created, navigate, team]);

  const taken = create.error instanceof ApiError && create.error.code === "name_taken";
  const nameError = (submitted ? nameProblem(name) : undefined) ?? (taken ? "Another service account in this team has this name. Choose another." : undefined);
  const submit = () => {
    setSubmitted(true);
    if (nameProblem(name) || scopeProblem(toolScope) || scopeDraftProblem) {
      requestAnimationFrame(() => formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());
      return;
    }
    create.mutate();
  };
  return (
    <FormPage
      label="Create service account"
      title="Create service account"
      description={whatIsAServiceAccount}
      onClose={onClose}
      onSubmit={submit}
      submitLabel="Create service account"
      busy={create.isPending}
      dirty={created ? false : undefined}
      formRef={formRef}
    >
      <FormSection title="Service account">
        <Field label="Name" description="Lower-case letters, digits and dashes, such as ci-release-bot. Calls show it as who called." error={nameError}>
          <Input
            spellCheck={false}
            autoComplete="off"
            maxLength={64}
            value={name}
            onChange={(e) => {
              if (taken) create.reset();
              setName(e.target.value);
            }}
          />
        </Field>
        <Field label="Description" labelHint="Optional" description="What it's for and where its keys are deployed, so the next owner knows." className={m.wide}>
          <Textarea maxLength={2000} value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        <div className={m.wide}>
          <RoleChoice value={role} onChange={setRole} />
        </div>
        <div className={m.wide}>
          <Switch label="Enabled" description="Turned off, its keys are refused until it's turned on again." checked={enabled} onCheckedChange={setEnabled} />
        </div>
      </FormSection>
      <FormSection title="Account tool ceiling">
        <ScopeEditor value={toolScope} onChange={setToolScope} onProblemChange={setScopeDraftProblem} disabled={create.isPending} />
      </FormSection>
      <ErrorAlert error={taken ? undefined : create.error} title="Couldn't create the service account" />
    </FormPage>
  );
}
