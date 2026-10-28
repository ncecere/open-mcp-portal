/*
 * Add grant (platform gateways, platform admins): a team (all its members,
 * now and later, and its service accounts: decision 23), a person by email
 * (someone who has signed in), or an SSO group by its name in the identity
 * provider's groups claim.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiError, type Schemas, unwrap } from "../../api/client";
import { adminGatewaysKey } from "../../api/queries";
import { ScopeEditor, scopeProblem, type ToolScope } from "../tool-scope";
import { FormDialog } from "../form-dialog";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Field } from "@/components/ui/field/field";
import { Input, NativeSelect } from "@/components/ui/input/input";
import { RadioGroup } from "@/components/ui/radio-group/radio-group";
import { toast } from "@/components/ui/toast/toast";
import type { Gateway } from "./labels";
import { grantsQuery } from "./scope";

type Kind = Schemas["GatewayGrantSubjectKind"];

const kindOptions: { value: Kind; label: string; description: string }[] = [
  { value: "team", label: "A team", description: "Everyone on the team, including people who join later, and the team's service accounts." },
  { value: "user", label: "A person", description: "Someone who has signed in at least once, by email." },
  { value: "group", label: "An SSO group", description: "Everyone in the group, as your identity provider reports at sign-in." },
];

/** The refusal for the field it's about (an unknown team or person), else undefined. */
function fieldError(err: unknown, kind: Kind): string | undefined {
  if (!(err instanceof ApiError)) return undefined;
  if (err.code === "subject_not_found") return kind === "team" ? "There's no such team." : "Nobody with this email has signed in yet.";
  if (err.code === "grant_exists") return kind === "team" ? "This team already has access." : kind === "user" ? "This person already has access." : "This group already has access.";
  return undefined;
}

export function AddGrantDialog({ gateway, onClose }: { gateway: Gateway; onClose: () => void }) {
  const qc = useQueryClient();
  const [kind, setKind] = useState<Kind>("team");
  const [team, setTeam] = useState("");
  const [email, setEmail] = useState("");
  const [group, setGroup] = useState("");
  const [toolScope, setToolScope] = useState<ToolScope>(null);
  const [submitted, setSubmitted] = useState(false);
  const teams = useQuery({
    queryKey: ["admin", "teams", "grant-options"],
    queryFn: async () => unwrap(await api.GET("/v1/admin/teams", { params: { query: { limit: 200 } } })),
    enabled: kind === "team",
  });
  const add = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/admin/gateways/{gatewayId}/grants", {
          params: { path: { gatewayId: gateway.id } },
          body: { ...(kind === "team" ? { subjectKind: kind, team } : kind === "user" ? { subjectKind: kind, userEmail: email.trim() } : { subjectKind: kind, group: group.trim() }), toolScope },
        }),
      ),
    onSuccess: (grant) => {
      void qc.invalidateQueries({ queryKey: grantsQuery(gateway.id).queryKey });
      void qc.invalidateQueries({ queryKey: adminGatewaysKey });
      toast.success("Access granted", `${subjectName(grant)} can use ${gateway.name} from their next request.`);
      onClose();
    },
  });
  const value = kind === "team" ? team : kind === "user" ? email.trim() : group.trim();
  const missing = submitted && !value ? (kind === "team" ? "Choose a team." : kind === "user" ? "Enter an email." : "Enter the group's name.") : undefined;
  const refused = fieldError(add.error, kind);
  const error = missing ?? refused;
  const change = (f: (v: string) => void) => (v: string) => {
    if (refused) add.reset();
    f(v);
  };
  return (
    <FormDialog
      title={`Grant access to ${gateway.name}`}
      description="Access takes effect on the next request. The people it covers see the gateway under My gateways."
      onClose={onClose}
      onSubmit={() => {
        setSubmitted(true);
        if (value && !scopeProblem(toolScope)) add.mutate();
      }}
      submitLabel="Grant access"
      busy={add.isPending}
      formProps={{ noValidate: true }}
    >
      <RadioGroup<Kind>
        legend="Grant to"
        value={kind}
        onValueChange={(k) => {
          setKind(k);
          setSubmitted(false);
          add.reset();
        }}
        options={kindOptions}
      />
      {kind === "team" && (
        <Field label="Team" error={error}>
          <NativeSelect value={team} onChange={(e) => change(setTeam)(e.target.value)}>
            <option value="">{teams.isLoading ? "Loading teams…" : "Choose a team"}</option>
            {(teams.data?.items ?? []).map((t) => (
              <option key={t.team.id} value={t.team.slug}>
                {t.team.name}
              </option>
            ))}
          </NativeSelect>
        </Field>
      )}
      {kind === "user" && (
        <Field label="Email" error={error}>
          <Input type="email" autoComplete="off" value={email} onChange={(e) => change(setEmail)(e.target.value)} />
        </Field>
      )}
      {kind === "group" && (
        <Field label="Group name" description="Exactly as it appears in the groups claim, such as engineering or cn=engineering,ou=groups." error={error}>
          <Input spellCheck={false} autoComplete="off" maxLength={256} value={group} onChange={(e) => change(setGroup)(e.target.value)} />
        </Field>
      )}
      <ScopeEditor value={toolScope} onChange={setToolScope} disabled={add.isPending} />
      <p>Matching grants are alternatives: another grant can allow additional tools. Independent credential limits still apply.</p>
      <ErrorAlert error={refused ? undefined : add.error} title="Couldn't grant access" />
    </FormDialog>
  );
}

/** Who a grant is for, in words. */
export function subjectName(g: Schemas["GatewayGrant"]) {
  if (g.subjectKind === "team") return g.team?.name ?? "A team";
  if (g.subjectKind === "user") return g.user?.displayName || g.user?.email || "A person";
  return g.group ?? "A group";
}
