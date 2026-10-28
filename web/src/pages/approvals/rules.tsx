import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { approvalRulesQuery, deleteApprovalRule, rulesKey, type ApprovalRule } from "../../api/approvals";
import { ApiError } from "../../api/client";
import { useCurrentUser } from "../../session";
import { useTeam } from "../team/common";
import { ConfirmMutationDialog } from "../../components/confirm-dialog";
import { PagerBar, useCursorPager } from "../../components/pager";
import { PageSkeleton } from "../../components/page-skeleton";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import { RuleEditor } from "./rule-editor";
import s from "../shared.module.css";
import a from "./approvals.module.css";

export function TeamApprovalRulesPage() {
  const ctx = useTeam();
  const { capabilities } = useCurrentUser();
  const staff = capabilities.platformAdmin || capabilities.platformAuditor;
  if (!ctx.isManager && !staff) return <Stack gap={6} className={s.page}><PageHeader title="No access" /><Alert tone="info">Approval rules are available to this team's owners/admins and read-only platform staff.</Alert></Stack>;
  return <Rules key={ctx.slug} team={ctx.slug} canWrite={ctx.isManager && !ctx.archived} />;
}
export function AdminApprovalRulesPage() {
  const { capabilities } = useCurrentUser();
  return <Rules canWrite={capabilities.platformAdmin} />;
}
function Rules({ team, canWrite }: { team?: string; canWrite: boolean }) {
  const qc = useQueryClient();
  const mounted = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const pager = useCursorPager();
  const query = useQuery(approvalRulesQuery(team, pager.cursor));
  const [editing, setEditing] = useState<ApprovalRule | "new" | null>(null);
  const [deleting, setDeleting] = useState<ApprovalRule | null>(null);
  const [deletedConflict, setDeletedConflict] = useState(false);
  const remove = useMutation({
    mutationFn: deleteApprovalRule,
    onSuccess: (_data, submitted) => {
      void qc.invalidateQueries({ queryKey: rulesKey(submitted.team) });
      if (mounted.current) setDeleting(null);
    },
    onError: (error) => { if (mounted.current && error instanceof ApiError && error.status === 412) setDeletedConflict(true); },
  });
  const writable = (r: ApprovalRule) => canWrite && (team !== undefined || (r.teamId === null && r.targetKind === "gateway"));
  return <Stack gap={6} className={s.page}>
    <PageHeader title="Approval rules" description={team ? "Require human review for this team's exact tool calls." : "Portal-wide rule metadata. Platform rule writes are limited to platform-owned gateways; team rules must be managed with team owner/admin membership."} actions={canWrite ? <Button onClick={() => setEditing("new")}>Create approval rule</Button> : undefined} />
    {!canWrite && <Alert tone="info">Read-only. Team rule writes require active owner/admin membership; platform oversight alone never grants team write access.</Alert>}
    <p>Server rules win over gateway rules. In each tier, a specific capability wins over a class selector. Overlapping rules at equal priority are rejected. Rules never grant tool access.</p>
    <div className={a.actions}><Button variant="secondary" disabled={query.isFetching || remove.isPending} onClick={() => { pager.reset(); void query.refetch(); }}>Reload rules</Button></div>
    {query.isLoading && <PageSkeleton />}
    <ErrorAlert error={query.error} title="Couldn't load approval rules" />
    {query.data?.items.length === 0 && <p>No approval rules in this view.</p>}
    {query.data?.items.map((r) => <Card key={r.id} className={a.rule} title={r.name} actions={writable(r) ? <div className={a.actions}>
      <Button variant="secondary" disabled={remove.isPending} onClick={() => setEditing(r)}>Edit {r.name}</Button>
      <Button variant="danger" disabled={remove.isPending} onClick={() => { remove.reset(); setDeletedConflict(false); setDeleting(r); }}>Delete {r.name}</Button>
    </div> : undefined}>
      <Stack gap={3}>
        <p className={a.digest}>{r.enabled ? "Enabled" : "Disabled"} · {r.targetKind}: {r.targetId} · revision {r.revision}</p>
        <p>{r.capabilityId ? `Tool capability: ${r.capabilityId}` : `Classes: ${r.classes.join(", ")}`}</p>
        <p>Pending: {r.pendingMinutes} minutes · Approved: {r.validMinutes} minutes</p>
        <p>{r.approvers.length ? r.approvers.map((x) => x.kind === "user" ? `User ${x.userId}` : `SSO group ${x.groupName}`).join(" · ") : "Reviewers: server team's active owners/admins (eligibility and fallback checked by the portal)"}</p>
        <p>Service-account owner/admin exception: {r.allowServiceAccountAdmins ? "enabled" : "off"}</p>
        {!team && r.teamId && <p className={s.note}>Team-owned rule · team {r.teamId}. Open the team's Approval rules page to manage it with owner/admin membership.</p>}
      </Stack>
    </Card>)}
    <PagerBar pager={pager} pageSize={25} shown={query.data?.items.length ?? 0} nextCursor={query.data?.nextCursor} label="Approval rule pages" />
    {editing && canWrite && <RuleEditor team={team} rule={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />}
    <ConfirmMutationDialog target={deleting} mutation={remove} onClose={() => setDeleting(null)} title="Delete approval rule?" description={deletedConflict ? "This revision changed. Close this dialog, reload the rules and review again before deleting." : `Delete ${deleting?.name ?? "this rule"}? Policy changes invalidate existing approvals. This does not undo an already authorized dispatch.`} confirmLabel={deletedConflict ? "Reload rules" : "Delete rule"} tone={deletedConflict ? "primary" : "danger"} onConfirm={(r) => {
      if (remove.isPending) return;
      if (deletedConflict) { setDeleting(null); remove.reset(); void query.refetch(); return; }
      remove.mutate({ team, id: r.id, revision: r.revision });
    }} />
  </Stack>;
}
