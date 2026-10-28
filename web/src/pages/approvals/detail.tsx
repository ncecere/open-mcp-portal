import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { ApiError } from "../../api/client";
import { approvalKey, approvalQuery, approvalsKey, safeReceipt, submitReview, type Approval, type ApprovalAction, type ReviewSubmission } from "../../api/approvals";
import { NotFoundState, isNotFound } from "../../components/not-found";
import { PageSkeleton } from "../../components/page-skeleton";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { DescriptionList } from "@/components/ui/description-list/description-list";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import s from "../shared.module.css";
import a from "./approvals.module.css";

export function ApprovalPage() {
  const { approvalId } = useParams({ from: "/app/approvals/$approvalId" });
  return <Review key={approvalId} id={approvalId} />;
}
function Review({ id }: { id: string }) {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const mounted = useRef(false);
  const sending = useRef(false);
  const [reviewAgain, setReviewAgain] = useState(false);
  const [now, setNow] = useState(Date.now());
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const query = useQuery(approvalQuery(id));
  const receipt = query.data;
  const deadline = receipt ? Math.min(Date.parse(receipt.expiresAt), receipt.status === "approved" && receipt.validUntil ? Date.parse(receipt.validUntil) : Infinity) : Infinity;
  useEffect(() => {
    if (!Number.isFinite(deadline)) return;
    const timer = setTimeout(() => {
      setNow(Date.now());
      qc.setQueryData<Approval>(approvalKey(id), (old) => old ? { ...old, preview: undefined } : old);
      void qc.invalidateQueries({ queryKey: approvalKey(id) });
    }, Math.max(0, deadline - Date.now()) + 10);
    return () => clearTimeout(timer);
  }, [deadline, id, qc]);
  const mutation = useMutation({
    mutationFn: async (submitted: ReviewSubmission) => {
      await qc.cancelQueries({ queryKey: approvalKey(submitted.id) });
      qc.setQueryData<Approval>(approvalKey(submitted.id), (old) => old ? { ...old, preview: undefined } : old);
      return submitReview(submitted);
    },
    onSuccess: (data, submitted) => {
      // Invalidate the submitted target, never the current route's target. A retired
      // review must not navigate or overwrite a newly opened receipt with a late result.
      void qc.invalidateQueries({ queryKey: approvalsKey });
      if (!mounted.current) return;
      setReviewAgain(true);
      if (data.id === submitted.id) qc.setQueryData(approvalKey(submitted.id), safeReceipt(data));
      if (submitted.action === "renew" && data.id !== submitted.id) void navigate({ to: "/approvals/$approvalId", params: { approvalId: data.id } });
    },
    onError: () => { if (mounted.current) setReviewAgain(true); },
    onSettled: () => { sending.current = false; },
  });
  const busy = mutation.isPending;
  const expired = deadline <= Math.max(now, Date.now());
  const conflict = mutation.error instanceof ApiError && mutation.error.status === 409;
  const act = (action: ApprovalAction) => {
    if (!receipt || sending.current || busy || reviewAgain || query.isFetching) return;
    sending.current = true;
    mutation.mutate({ id: receipt.id, action, revision: receipt.reviewRevision, digest: receipt.argsDigest });
  };
  const reload = async () => {
    const result = await query.refetch();
    if (mounted.current && result.isSuccess) { mutation.reset(); setReviewAgain(false); setNow(Date.now()); }
  };
  if (query.isLoading) return <PageSkeleton />;
  if (isNotFound(query.error)) return <NotFoundState what="object" />;
  // On a failed authority refresh, never fall back to a previously cached preview.
  if (query.error) return <ErrorAlert error={query.error} title="Couldn't load this approval" />;
  if (!receipt) return null;
  const preview = !busy && !reviewAgain && !query.isFetching && !expired ? safeReceipt(receipt).preview : undefined;
  return <Stack gap={6} className={s.page}>
    <Button variant="secondary" render={<Link to="/approvals" />}>Back to approvals</Button>
    <PageHeader title={receipt.exposedName} description={`Approval ${receipt.id}`} />
    {receipt.stale && <Alert tone="warning" title="This review is stale">Policy, access or the call binding changed. This approval cannot authorize a call. Reload and review again.</Alert>}
    {expired && <Alert tone="warning" title="The displayed deadline has passed">Reload to check the current status. No decision can extend this deadline.</Alert>}
    {receipt.status === "used" && <Alert tone="warning" title="Authorization spent — execution is not confirmed">An upstream result may be unknown, including after a lost response. Retrying may duplicate effects. Check the destination before explicitly requesting another attempt.</Alert>}
    <Card title="Call receipt"><DescriptionList items={[
      { label: "Status", value: receipt.status === "used" ? "Authorization spent (used)" : receipt.status },
      { label: "Requester", value: `${receipt.requesterKind === "user" ? "User" : "Service account"}: ${receipt.requesterId}` },
      { label: "Requester team", value: receipt.requesterTeamId ?? "Not applicable" },
      { label: "Tool", value: `${receipt.exposedName} · ${receipt.capabilityId}` },
      { label: "Actual class", value: receipt.toolClass ?? "Unclassified (matches destructive rules for approval only)" },
      { label: "Gateway", value: receipt.gatewayId }, { label: "Server", value: receipt.serverId },
      { label: "Server origin", value: receipt.serverOrigin },
      { label: "Rule", value: `${receipt.ruleId} · revision ${receipt.ruleRevision}` },
      { label: "Argument digest", value: <code className={a.digest}>{receipt.argsDigest}</code> },
      { label: "Capability fingerprint", value: <code className={a.digest}>{receipt.capabilityFingerprint}</code> },
      { label: "Review revision / context epoch", value: `${receipt.reviewRevision} / ${receipt.contextEpoch}` },
      { label: "Requested", value: new Date(receipt.createdAt).toLocaleString() },
      { label: "Pending expiry", value: new Date(receipt.expiresAt).toLocaleString() },
      { label: "Approved until", value: receipt.validUntil ? new Date(receipt.validUntil).toLocaleString() : "Not approved" },
      { label: "Decision", value: receipt.decidedBy ? `${receipt.decidedBy} · ${receipt.decidedAt}` : "No decision" },
      { label: "Spent at", value: receipt.usedAt ?? "Not spent" }, { label: "Terminal at", value: receipt.terminalAt ?? "Not terminal" },
    ]} dividers /></Card>
    {preview !== undefined && <Card title="Redacted argument preview">
      <Stack gap={3}>
        <Alert tone="warning">This is an escaped text preview, not the full arguments. The digest binds the exact merged call.</Alert>
        {receipt.previewRedacted && <p>Credential or sensitive values were redacted.</p>}
        {receipt.previewTruncated && <Alert tone="warning">Preview truncated. Not all arguments are shown.</Alert>}
        <pre className={a.preview} role="region" tabIndex={0} aria-label="Redacted argument preview text">{preview}</pre>
      </Stack>
    </Card>}
    <Card title="Actions"><Stack gap={4}>
      <p>Only currently eligible reviewers may decide. Human self-approval is never allowed. Service-account owner/admin eligibility, separation of duties and fallback are checked by the portal, not inferred from your platform role.</p>
      {conflict || reviewAgain ? <Alert tone="warning" title={conflict ? "Changed since review" : "Reload before another action"}>Reload the receipt and review it again. Nothing will be resubmitted automatically.</Alert> : null}
      <ErrorAlert error={mutation.error} title="Couldn't update approval" />
      <div className={a.actions}>
        {receipt.canDecide && <><Button disabled={busy || reviewAgain || query.isFetching || expired || receipt.stale} onClick={() => act("approve")}>Approve exact call</Button><Button variant="danger" disabled={busy || reviewAgain || query.isFetching || expired || receipt.stale} onClick={() => act("deny")}>Deny</Button></>}
        {receipt.canCancel && <Button variant="secondary" disabled={busy || reviewAgain || query.isFetching} onClick={() => act("cancel")}>Cancel request</Button>}
        {receipt.canRenew && <Button variant="secondary" disabled={busy || reviewAgain || query.isFetching} onClick={() => act("renew")}>Request new attempt</Button>}
        <Button variant="secondary" disabled={busy || query.isFetching} onClick={() => void reload()}>Reload receipt</Button>
      </div>
      {!receipt.canDecide && !receipt.canCancel && !receipt.canRenew && <p>No actions are available to you for this receipt.</p>}
      {busy && <p role="status">Saving the displayed review… Controls are frozen until it completes.</p>}
      {receipt.canRenew && <p className={s.note}>Renewal is explicit: it creates a new attempt, not a replay or restoration of this authorization.</p>}
    </Stack></Card>
  </Stack>;
}
