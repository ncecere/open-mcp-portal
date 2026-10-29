import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { useRef, useState } from "react";
import { accessRequestKey, accessRequestQuery, accessRequestsKey, decideAccessRequest, withdrawAccessRequest } from "../../api/access-requests";
import { adminGatewaysKey, myGatewaysKey } from "../../api/queries";
import { NotFoundState, isNotFound } from "../../components/not-found";
import { PageSkeleton } from "../../components/page-skeleton";
import { useCurrentUser } from "../../session";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { DescriptionList } from "@/components/ui/description-list/description-list";
import { Field } from "@/components/ui/field/field";
import { Input, Textarea } from "@/components/ui/input/input";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import s from "../shared.module.css";
import a from "./requests.module.css";

export function AccessRequestPage() {
  const { requestId } = useParams({ from: "/app/access-requests/$requestId" });
  return <AccessRequestDetail key={requestId} id={requestId} />;
}

export function AccessRequestDetail({ id }: { id: string }) {
  const me = useCurrentUser();
  const qc = useQueryClient();
  const query = useQuery(accessRequestQuery(id));
  const [note, setNote] = useState("");
  const [days, setDays] = useState("");
  const [reloadRequired, setReloadRequired] = useState(false);
  const sending = useRef(false);
  const r = query.data;
  const mutation = useMutation({
    mutationFn: async (submitted: { id: string; action: "approve" | "deny" | "withdraw"; note: string; days?: number }) => submitted.action === "withdraw"
      ? withdrawAccessRequest(submitted.id)
      : decideAccessRequest({ id: submitted.id, body: { decision: submitted.action, note: submitted.note, ...(submitted.action === "approve" && submitted.days !== undefined ? { expiresInDays: submitted.days } : {}) } }),
    onSuccess: (data, submitted) => {
      qc.setQueryData(accessRequestKey(submitted.id), data);
      void qc.invalidateQueries({ queryKey: accessRequestsKey });
      void qc.invalidateQueries({ queryKey: myGatewaysKey });
      void qc.invalidateQueries({ queryKey: adminGatewaysKey });
    },
    onError: () => setReloadRequired(true),
    onSettled: () => { sending.current = false; },
  });
  if (query.isLoading) return <PageSkeleton />;
  if (isNotFound(query.error)) return <NotFoundState what="object" />;
  // Never show cached private text after a failed live authority refresh.
  if (query.error) return <ErrorAlert error={query.error} title="Couldn't load this access request" />;
  if (!r) return null;
  const busy = mutation.isPending;
  const validDays = days === "" || (Number.isInteger(Number(days)) && Number(days) >= 1 && Number(days) <= 365);
  const blocked = busy || query.isFetching || reloadRequired;
  const act = (action: "approve" | "deny" | "withdraw") => {
    if (sending.current || blocked || (action === "approve" && !validDays)) return;
    sending.current = true;
    mutation.mutate({ id: r.id, action, note, ...(days ? { days: Number(days) } : {}) });
  };
  return <Stack gap={6} className={s.page}>
    <Button variant="secondary" render={<Link to="/access-requests" />}>Back to access requests</Button>
    <PageHeader title={r.gatewayName} description="Private gateway access request" />
    <Card title="Request"><DescriptionList items={[
      { label: "Status", value: r.status }, { label: "Requester", value: r.requesterName || r.requesterId },
      { label: "Access for", value: r.subjectKind === "team" ? `${r.teamName} — all current/future members and service accounts` : "The requester only" },
      { label: "Requested", value: new Date(r.createdAt).toLocaleString() },
      { label: "Decided", value: r.decidedAt ? new Date(r.decidedAt).toLocaleString() : "Not decided" },
      { label: "Grant expires", value: r.status === "approved" ? (r.grantExpiresAt ? new Date(r.grantExpiresAt).toLocaleString() : "Permanent") : "No grant" },
    ]} dividers /></Card>
    <Card title="Private reason"><p className={a.privateText}>{r.reason}</p></Card>
    {r.decisionNote && <Card title="Private decision note"><p className={a.privateText}>{r.decisionNote}</p></Card>}
    {r.status === "approved" && <Alert tone="info">Access was granted. It can expire or be revoked; this receipt is history, not proof of current access. Credential scopes and sensitive-call approval rules still apply.</Alert>}
    {r.status === "denied" && <Alert tone="info">No access was granted. Wait 24 hours before requesting this access again.</Alert>}
    {r.status === "pending" && <Card title="Actions"><Stack gap={4}>
      {r.canDecide && <>
        <Alert tone="warning">You are deciding gateway access, not an exact tool call. A team grant includes the team's current/future people and service accounts. You cannot decide your own request.</Alert>
        <Field label="Grant lifetime (days)" description="Optional, 1–365 days. Leave empty for permanent access." error={!validDays ? "Enter a whole number from 1 to 365, or leave empty." : undefined}><Input type="number" min={1} max={365} step={1} value={days} disabled={blocked} onValueChange={setDays} /></Field>
        <Field label="Decision note" description="Optional private note, up to 1000 characters. Never enter secrets."><Textarea value={note} maxLength={1000} disabled={blocked} onChange={(e) => setNote(e.target.value)} /></Field>
        <div className={s.toolbar}><Button disabled={blocked || !validDays} onClick={() => act("approve")}>Approve gateway access</Button><Button variant="danger" disabled={blocked} onClick={() => act("deny")}>Deny access</Button></div>
      </>}
      {r.requesterId === me.user.id && <Button variant="secondary" disabled={blocked} onClick={() => act("withdraw")}>Withdraw request</Button>}
      {!r.canDecide && r.requesterId !== me.user.id && <p>This request is not currently actionable. Reviewer and requester authority are checked live.</p>}
      {reloadRequired && <Alert tone="warning">Reload and review the request again before another action. Nothing will be resubmitted automatically.</Alert>}
      <ErrorAlert error={mutation.error} title="Couldn't update access request" />
      <Button variant="secondary" disabled={busy || query.isFetching} onClick={() => { void query.refetch().then((result) => { if (result.isSuccess) { setReloadRequired(false); mutation.reset(); } }); }}>Reload request</Button>
      {busy && <p role="status">Saving the displayed decision…</p>}
    </Stack></Card>}
  </Stack>;
}
