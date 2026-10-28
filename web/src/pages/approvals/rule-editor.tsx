import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { ApiError, type Schemas } from "../../api/client";
import { rulesKey, saveApprovalRule, type ApprovalRule, type RuleInput, type RuleSubmission } from "../../api/approvals";
import { FormPage, FormSection } from "../../components/templates/form-page";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Checkbox, CheckboxGroup } from "@/components/ui/checkbox/checkbox";
import { Field } from "@/components/ui/field/field";
import { Input, NativeSelect, Textarea } from "@/components/ui/input/input";
import { TargetPicker } from "./target-picker";

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const lines = (text: string) => text.split("\n").map((s) => s.trim()).filter(Boolean);
const defaults = (team?: string): RuleInput => ({ name: "", targetKind: team ? "server" : "gateway", targetId: "", capabilityId: null, classes: ["destructive"], enabled: true, pendingMinutes: 1440, validMinutes: 15, allowServiceAccountAdmins: false, approvers: [] });

export function RuleEditor({ team, rule, onClose }: { team?: string; rule?: ApprovalRule; onClose: () => void }) {
  return <Editor key={`${team}:${rule?.id ?? "new"}:${rule?.revision ?? 0}`} team={team} rule={rule} onClose={onClose} />;
}
function Editor({ team, rule, onClose }: { team?: string; rule?: ApprovalRule; onClose: () => void }) {
  const qc = useQueryClient();
  const mounted = useRef(false);
  const sending = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const [input, setInput] = useState<RuleInput>(rule ? { ...rule, classes: [...rule.classes], approvers: rule.approvers.map((a) => ({ ...a })) } : defaults(team));
  const [selector, setSelector] = useState(rule?.capabilityId ? "capability" : "classes");
  const [users, setUsers] = useState(rule?.approvers.filter((a) => a.kind === "user").map((a) => a.userId).join("\n") ?? "");
  const [groups, setGroups] = useState(rule?.approvers.filter((a) => a.kind === "group").map((a) => a.groupName).join("\n") ?? "");
  const [validation, setValidation] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: saveApprovalRule,
    onSuccess: (_data, submitted) => {
      void qc.invalidateQueries({ queryKey: rulesKey(submitted.team) });
      if (mounted.current) onClose();
    },
    onSettled: () => { sending.current = false; },
  });
  const conflict = save.error instanceof ApiError && save.error.status === 412;
  const busy = save.isPending;
  const set = <K extends keyof RuleInput>(key: K, value: RuleInput[K]) => setInput((old) => ({ ...old, [key]: value }));
  const submit = () => {
    if (sending.current || busy || conflict) return;
    const userIds = lines(users), groupNames = lines(groups);
    let error: string | null = null;
    if (!input.name.trim()) error = "Enter a rule name.";
    else if (!uuid.test(input.targetId)) error = "Choose a target owned by this scope.";
    else if (selector === "capability" && !uuid.test(input.capabilityId ?? "")) error = "Enter the UUID of a tool capability belonging to this target (or selected through this gateway).";
    else if (selector === "classes" && input.classes.length === 0) error = "Choose at least one tool class, or select a capability instead.";
    else if (!Number.isInteger(input.pendingMinutes) || input.pendingMinutes < 5 || input.pendingMinutes > 1440) error = "Pending lifetime must be a whole number from 5 to 1440 minutes (24 hours).";
    else if (!Number.isInteger(input.validMinutes) || input.validMinutes < 1 || input.validMinutes > 60) error = "Approved validity must be a whole number from 1 to 60 minutes.";
    else if (userIds.some((id) => !uuid.test(id))) error = "Each approver user must be an active user's UUID, one per line; use the separate group field for exact SSO group names.";
    else if (new Set(userIds).size !== userIds.length || new Set(groupNames).size !== groupNames.length) error = "Remove duplicate approver users or groups.";
    setValidation(error);
    if (error) return;
    // The immutable target and If-Match revision are captured with this complete body.
    // Never serialize the ApprovalRule itself (which contains read-only metadata).
    const body: RuleInput = {
      name: input.name.trim(), targetKind: rule?.targetKind ?? input.targetKind, targetId: rule?.targetId ?? input.targetId,
      capabilityId: selector === "capability" ? input.capabilityId : null, classes: selector === "classes" ? [...input.classes] : [],
      enabled: input.enabled, pendingMinutes: input.pendingMinutes, validMinutes: input.validMinutes,
      allowServiceAccountAdmins: input.allowServiceAccountAdmins,
      approvers: [...userIds.map((userId): Schemas["ApprovalApprover"] => ({ kind: "user", userId, groupName: null })), ...groupNames.map((groupName): Schemas["ApprovalApprover"] => ({ kind: "group", userId: null, groupName }))],
    };
    const submitted: RuleSubmission = { team, id: rule?.id, revision: rule?.revision, body };
    sending.current = true;
    save.mutate(submitted);
  };
  return <FormPage label={rule ? "Edit approval rule" : "Create approval rule"} title={rule ? `Edit ${rule.name}` : "Create approval rule"} description="Rules require approval; they never grant tool access. Server rules outrank gateway rules. Within each tier, capability-specific rules outrank class rules. Equal-priority overlaps are rejected." onClose={onClose} onSubmit={submit} submitLabel={rule ? "Save rule" : "Create rule"} busy={busy} submitDisabled={conflict}>
    {validation && <Alert tone="danger" title="Check this rule">{validation}</Alert>}
    <ErrorAlert error={save.error} title="Couldn't save rule" />
    {conflict && <Alert tone="warning">This revision changed. Close this editor, reload the rules and reopen it to review the latest revision. Your edits will not be resubmitted automatically.</Alert>}
    {save.error instanceof ApiError && save.error.status === 409 && <Alert tone="warning">The portal rejected this rule, including any ambiguous or overlapping policy. Review the error and existing rules before saving again.</Alert>}
    <FormSection title="Rule and immutable target">
      <Field label="Rule name"><Input required maxLength={200} value={input.name} disabled={busy} onValueChange={(v) => set("name", v)} /></Field>
      {rule ? <p>Target: {rule.targetKind} · {rule.targetId}. This target cannot be changed.</p> : <>
        <Field label="Target kind"><NativeSelect value={input.targetKind} disabled={busy || !team} onChange={(e) => setInput((old) => ({ ...old, targetKind: e.target.value as RuleInput["targetKind"], targetId: "", capabilityId: null }))}>
          {team && <option value="server">Server</option>}<option value="gateway">Gateway</option>
        </NativeSelect></Field>
        <TargetPicker key={input.targetKind} team={team} kind={input.targetKind} value={input.targetId} onChange={(v) => set("targetId", v)} disabled={busy} />
      </>}
      <Checkbox label="Enabled" checked={input.enabled} disabled={busy} onCheckedChange={(v) => set("enabled", v)} />
    </FormSection>
    <FormSection title="Exactly one tool selector">
      <Field label="Match by"><NativeSelect value={selector} disabled={busy} onChange={(e) => setSelector(e.target.value)}><option value="classes">Tool classes</option><option value="capability">Specific tool capability</option></NativeSelect></Field>
      {selector === "capability" ? <Field label="Tool capability ID" description="Use a tool UUID belonging to the server, or selected through this gateway. The portal validates it; resource and prompt IDs are not eligible."><Input required value={input.capabilityId ?? ""} disabled={busy} onValueChange={(v) => set("capabilityId", v.trim())} /></Field> : <CheckboxGroup legend="Tool classes" value={input.classes} disabled={busy} onValueChange={(v) => set("classes", v as RuleInput["classes"])}>
        <Checkbox label="Read" value="read" /><Checkbox label="Write" value="write" /><Checkbox label="Destructive" value="destructive" />
      </CheckboxGroup>}
      <p>Unclassified tools match destructive rules for approval only. Their actual class and tool scopes do not change.</p>
    </FormSection>
    <FormSection title="Deadlines and reviewers">
      <Field label="Pending lifetime (minutes)" description="5–1440 minutes; default 1440 (24 hours)."><Input type="number" min={5} max={1440} step={1} value={input.pendingMinutes} disabled={busy} onValueChange={(v) => set("pendingMinutes", Number(v))} /></Field>
      <Field label="Approved validity (minutes)" description="1–60 minutes; default 15. Never extends the pending request's absolute expiry."><Input type="number" min={1} max={60} step={1} value={input.validMinutes} disabled={busy} onValueChange={(v) => set("validMinutes", Number(v))} /></Field>
      <Field label="Approver user IDs" description="Optional active user UUIDs, one per line. Current eligibility and access are checked again at review and use."><Textarea value={users} disabled={busy} onChange={(e) => setUsers(e.target.value)} /></Field>
      <Field label="Approver SSO groups" description="Optional exact group names, one per line; case matters. No comma splitting."><Textarea value={groups} disabled={busy} onChange={(e) => setGroups(e.target.value)} /></Field>
      <p>Leave both approver fields empty to use the server team's active owners/admins. A non-requester platform-admin fallback applies only when there are no eligible primary reviewers. Gateway ownership is not review authority; no eligible reviewer means the call is refused.</p>
      <Checkbox label="Allow requesting service account's owners/admins to review" description="Off by default. This is an explicit separation-of-duties exception, not permission for human self-approval." checked={input.allowServiceAccountAdmins} disabled={busy} onCheckedChange={(v) => set("allowServiceAccountAdmins", v)} />
      <Alert tone="warning">{input.allowServiceAccountAdmins ? "Exception enabled: otherwise eligible owners/admins of the requesting service account may review its calls. Human requesters can never approve themselves." : "Separation of duties: requesting service account owners/admins are excluded from review, including fallback, unless you explicitly enable the exception above."}</Alert>
    </FormSection>
  </FormPage>;
}
