import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { approvalsQuery } from "../../api/approvals";
import { PagerBar, useCursorPager } from "../../components/pager";
import { PageSkeleton } from "../../components/page-skeleton";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Card } from "@/components/ui/card/card";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import { Tab, Tabs, TabsList, TabsPanel } from "@/components/ui/tabs/tabs";
import s from "../shared.module.css";
import a from "./approvals.module.css";

export function ApprovalsPage() {
  const [view, setView] = useState<"actionable" | "requested">("actionable");
  return <Stack gap={6} className={s.page}>
    <PageHeader title="Approvals" description="Review exact tool-call requests, or follow requests you control. Approval never grants access to a tool." />
    <Tabs value={view} onValueChange={(v) => setView(v as typeof view)}>
      <TabsList aria-label="Approval queues"><Tab value="actionable">Actionable</Tab><Tab value="requested">Requested</Tab></TabsList>
      <TabsPanel value={view}><Queue key={view} view={view} /></TabsPanel>
    </Tabs>
  </Stack>;
}
function Queue({ view }: { view: "actionable" | "requested" }) {
  const pager = useCursorPager();
  const query = useQuery(approvalsQuery(view, pager.cursor));
  if (query.isLoading) return <PageSkeleton />;
  if (query.error) return <ErrorAlert error={query.error} title="Couldn't load approvals" />;
  const page = query.data;
  return <Stack gap={4}>
    <p className={s.note}>{view === "actionable" ? "Requests you can act on now. Eligibility is checked again when you decide." : "Requests made by you or service accounts you control."} Open a request to review its receipt; previews are never shown in this queue.</p>
    {page?.items.length === 0 && <p>No {view} approvals.</p>}
    {page?.items.map((r) => <Card key={r.id} title={<Link to="/approvals/$approvalId" params={{ approvalId: r.id }}>{r.exposedName}</Link>}>
      <div className={a.summary}><span>{r.status === "used" ? "Authorization spent" : r.status}{r.stale ? " · Stale" : ""}</span><span>{r.toolClass ?? "Unclassified"}</span><span>Expires {new Date(r.expiresAt).toLocaleString()}</span></div>
      <p className={s.secondary}>{r.requesterKind === "user" ? "User" : "Service account"}: {r.requesterId}</p>
    </Card>)}
    <PagerBar pager={pager} pageSize={25} shown={page?.items.length ?? 0} nextCursor={page?.nextCursor} label="Approval pages" />
  </Stack>;
}
