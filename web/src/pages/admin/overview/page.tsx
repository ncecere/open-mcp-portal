/*
 * Admin › Overview (/admin), the admin portal's first page: what needs attention across the platform (failing
 * published servers, reviews waiting, changed capabilities, expiring keys, lapsed sign-ins, failing notifications…),
 * the headline counts and the last 24 hours of calls. Read-only: auditors see the same page, and every button leads
 * to a screen that is read-only for them. Asked again every minute while visible and when the window gets focus.
 */
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { BadgeCheck, Bot, Boxes, Network, Server, Terminal, Users } from "lucide-react";
import { adminOverviewQuery } from "@/api/attention";
import type { Schemas } from "@/api/client";
import { AttentionList } from "@/components/attention/attention-list";
import { PageSkeleton } from "@/components/page-skeleton";
import { RelativeTime } from "@/components/templates/relative-time";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Badge } from "@/components/ui/badge/badge";
import { Card } from "@/components/ui/card/card";
import { EmptyState } from "@/components/ui/empty-state/empty-state";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import { StatCard } from "@/components/ui/stat-card/stat-card";
import { terms } from "@/lib/terms";
import s from "../../shared.module.css";

export function AdminOverviewPage() {
  const overview = useQuery(adminOverviewQuery());
  return (
    <Stack gap={6} className={s.page}>
      <PageHeader title={terms.adminOverview} description="What needs attention across the platform, and how it's running." />
      {overview.isLoading ? (
        <PageSkeleton />
      ) : overview.data ? (
        <OverviewBody overview={overview.data} />
      ) : (
        <ErrorAlert error={overview.error} title="Couldn't load the overview" onRetry={() => void overview.refetch()} />
      )}
    </Stack>
  );
}

const percent = (rate: number) => `${(rate * 100).toLocaleString(undefined, { maximumFractionDigits: rate < 0.1 ? 1 : 0 })}%`;

function OverviewBody({ overview }: { overview: Schemas["AdminOverview"] }) {
  const { counts, last24h, attention, totals } = overview;
  return (
    <>
      <Card title="Needs attention" description="Items are listed most severe first. Each button opens the screen where it is dealt with." actions={attention.length > 0 && <Badge tone="warning">{attention.length}</Badge>}>
        {attention.length === 0 ? (
          <EmptyState icon={<BadgeCheck />} title="Nothing needs attention" description="No server is failing, nothing is waiting for review and no key is about to expire." />
        ) : (
          <AttentionList items={attention} totals={totals} moreTo={{ kind: "admin" }} />
        )}
      </Card>
      <div className={s.stats3} role="group" aria-label="Platform counts">
        <StatCard label="People" value={counts.users.toLocaleString()} hint="Active" icon={<Users />} render={<Link to="/admin/users" />} />
        <StatCard label="Teams" value={counts.teams.toLocaleString()} hint="Active" icon={<Boxes />} render={<Link to="/admin/teams" />} />
        <StatCard label={terms.mcpServers} value={counts.servers.toLocaleString()} hint={`${counts.publishedServers.toLocaleString()} published`} icon={<Server />} render={<Link to="/admin/servers" />} />
        <StatCard label={terms.gateways} value={counts.gateways.toLocaleString()} icon={<Network />} render={<Link to="/admin/gateways" />} />
        <StatCard label={terms.serviceAccounts} value={counts.serviceAccounts.toLocaleString()} icon={<Bot />} />
        <StatCard label={terms.automationTokens} value={counts.automationTokens.toLocaleString()} hint="Active" icon={<Terminal />} render={<Link to="/admin/automation-tokens" />} />
      </div>
      <Card
        title="Last 24 hours"
        description={
          last24h.rolledUpTo ? (
            <>
              As of <RelativeTime value={last24h.rolledUpTo} />: usage is summed every few minutes. Errors count every outcome but ok, as in Usage.
            </>
          ) : (
            "No usage has been summed yet."
          )
        }
      >
        <div className={s.stats3} role="group" aria-label="Last 24 hours">
          <StatCard label="Calls" value={last24h.calls.toLocaleString()} render={<Link to="/admin/usage" />} />
          <StatCard label="Error rate" value={last24h.errorRate === null ? "No calls" : percent(last24h.errorRate)} hint={`${last24h.errors.toLocaleString()} errors`} />
          <StatCard label="Rate-limited calls" value={last24h.rateLimited.toLocaleString()} />
        </div>
      </Card>
    </>
  );
}
