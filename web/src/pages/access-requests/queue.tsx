import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { accessRequestsKey, accessRequestsQuery, createAccessRequest, requestableQuery, type RequestableGateway } from "../../api/access-requests";
import { FormDialog } from "../../components/form-dialog";
import { PagerBar, useCursorPager } from "../../components/pager";
import { PageSkeleton } from "../../components/page-skeleton";
import { useCurrentUser } from "../../session";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { Field } from "@/components/ui/field/field";
import { NativeSelect, Textarea } from "@/components/ui/input/input";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import { Tab, Tabs, TabsList, TabsPanel } from "@/components/ui/tabs/tabs";
import s from "../shared.module.css";

export function AccessRequestsPage() {
  const [view, setView] = useState("discover");
  return <Stack gap={6} className={s.page}>
    <PageHeader title="Gateway access requests" description="Discover gateways that explicitly accept requests, follow your requests, or review requests for gateways you steward. Access never bypasses tool scopes, credentials or sensitive-call approvals." />
    <Tabs value={view} onValueChange={(v) => setView(String(v))}>
      <TabsList aria-label="Gateway access queues"><Tab value="discover">Request access</Tab><Tab value="requested">My requests</Tab><Tab value="review">Review requests</Tab></TabsList>
      <TabsPanel value={view}>{view === "discover" ? <Discover /> : <Queue key={view} view={view === "review" ? "review" : "requested"} />}</TabsPanel>
    </Tabs>
  </Stack>;
}

function Discover() {
  const pager = useCursorPager();
  const query = useQuery(requestableQuery(pager.cursor));
  const [target, setTarget] = useState<RequestableGateway>();
  if (query.isLoading) return <PageSkeleton />;
  if (query.error) return <ErrorAlert error={query.error} title="Couldn't load requestable gateways" />;
  return <Stack gap={4}>
    <p>Only platform gateways whose administrators opted into discoverability appear here. Listing a gateway does not grant access to it.</p>
    {query.data?.items.length === 0 && <p>No gateways are accepting access requests.</p>}
    {query.data?.items.map((g) => <Card key={g.id} title={g.name} description={g.description} actions={<Button aria-label={`Request access to ${g.name}`} onClick={() => setTarget(g)}>Request access</Button>} />)}
    <PagerBar pager={pager} pageSize={25} shown={query.data?.items.length ?? 0} nextCursor={query.data?.nextCursor} label="Requestable gateway pages" />
    {target && <RequestDialog key={target.id} gateway={target} onClose={() => setTarget(undefined)} />}
  </Stack>;
}

export function RequestDialog({ gateway, onClose }: { gateway: RequestableGateway; onClose: () => void }) {
  const me = useCurrentUser();
  const qc = useQueryClient();
  const [reason, setReason] = useState("");
  const [team, setTeam] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const teams = me.teams.filter((t) => t.status === "active" && ["owner", "admin"].includes(t.role));
  const mutation = useMutation({
    mutationFn: createAccessRequest,
    onSuccess: () => { void qc.invalidateQueries({ queryKey: accessRequestsKey }); onClose(); },
  });
  const busy = mutation.isPending;
  return <FormDialog title={`Request access to ${gateway.name}`} description="Your reason is private to you and current reviewers. At most 10 requests can be pending; after a denial, wait 24 hours before requesting the same access again." onClose={onClose} busy={busy} closeDisabled={busy} submitLabel="Submit access request" onSubmit={() => {
    setSubmitted(true);
    if (!busy && reason.trim()) mutation.mutate({ gatewayId: gateway.id, reason: reason.trim(), ...(team ? { teamId: team } : {}) });
  }}>
    <Field label="Request for"><NativeSelect value={team} disabled={busy} onChange={(e) => setTeam(e.target.value)}>
      <option value="">Myself</option>{teams.map((t) => <option key={t.id} value={t.id}>{t.name} (whole team)</option>)}
    </NativeSelect></Field>
    {team && <Alert tone="warning">A team grant covers all current and future members and the team's service accounts, not just you.</Alert>}
    <Field label="Reason" description="Required, up to 1000 characters. Do not enter passwords, API keys or other secrets." error={submitted && !reason.trim() ? "Enter why you need access." : undefined}><Textarea required maxLength={1000} value={reason} disabled={busy} onChange={(e) => setReason(e.target.value)} /></Field>
    <ErrorAlert error={mutation.error} title="Couldn't request access" />
    {mutation.isSuccess && <p role="status">Request submitted. Follow it under My requests.</p>}
  </FormDialog>;
}

function Queue({ view }: { view: "requested" | "review" }) {
  const pager = useCursorPager();
  const query = useQuery(accessRequestsQuery(view, pager.cursor));
  if (query.isLoading) return <PageSkeleton />;
  if (query.error) return <ErrorAlert error={query.error} title="Couldn't load access requests" />;
  return <Stack gap={4}>
    {view === "review" && <p>{query.data?.pendingReviewCount ?? 0} pending requests you can review now. Eligibility is checked again when deciding. Stewardship grants no direct gateway or administration access.</p>}
    {query.data?.items.length === 0 && <p>No {view === "review" ? "reviewable" : "submitted"} access requests.</p>}
    {query.data?.items.map((r) => <Card key={r.id} title={<Link to="/access-requests/$requestId" params={{ requestId: r.id }}>{r.gatewayName}</Link>}>
      <p>{r.status} · {r.subjectKind === "team" ? r.teamName : r.requesterName || "Personal access"}</p>
      <p className={s.note}>Requested {new Date(r.createdAt).toLocaleString()}. Open the private request to read its reason and decision.</p>
    </Card>)}
    <PagerBar pager={pager} pageSize={25} shown={query.data?.items.length ?? 0} nextCursor={query.data?.nextCursor} label="Access request pages" />
  </Stack>;
}
