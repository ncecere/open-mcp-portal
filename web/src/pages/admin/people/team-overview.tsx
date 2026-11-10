/* Admin team › Overview: its members and owners at a glance, its description and its recent changes. */
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowRight, Crown, MailPlus, UsersRound } from "lucide-react";
import { api, unwrap, type Schemas } from "@/api/client";
import { changeSummary } from "@/components/audit/changes";
import { actionLabel, entryTitle } from "@/components/audit/labels";
import { actorName } from "@/components/audit/actors";
import { RelativeTime } from "@/components/templates/relative-time";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { DescriptionList } from "@/components/ui/description-list/description-list";
import { Item, ItemContent, ItemDescription, ItemGroup, ItemTitle } from "@/components/ui/item/item";
import { SkeletonText } from "@/components/ui/skeleton/skeleton";
import { StatCard } from "@/components/ui/stat-card/stat-card";
import { Time } from "@/components/ui/time/time";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { ownersHint } from "./common";
import t from "./people.module.css";

type Summary = Schemas["TeamSummary"];

export function TeamOverviewTab({ summary }: { summary: Summary }) {
  const slug = summary.team.slug;
  const audit = useQuery({
    queryKey: ["team", slug, "audit", "recent"],
    queryFn: async () => unwrap(await api.GET("/v1/teams/{team}/audit", { params: { path: { team: slug }, query: { limit: 5 } } })),
  });
  const changeTitle = (e: Schemas["AuditEntry"]) => {
    const change = changeSummary(e);
    const title = e.targetId === summary.team.id ? actionLabel(e.action, e) : entryTitle(e);
    return change ? `${title}: ${change}` : title;
  };
  const items = audit.data?.items ?? [];
  return (
    <div className={t.overview}>
      <div className={t.stats}>
        <StatCard
          label="Members"
          value={summary.memberCount.toLocaleString()}
          icon={<UsersRound />}
          hint={ownersHint(summary)}
          render={<Link to="/admin/teams/$team" params={{ team: slug }} search={{ tab: "members" }} />}
        />
        <StatCard label="Owners" value={summary.ownerCount.toLocaleString()} icon={<Crown />} />
        <StatCard label="Owner invites" value={summary.ownerInvites.toLocaleString()} icon={<MailPlus />} hint="Invited by email, not signed in yet" />
      </div>
      <div className={t.columns}>
        <Card title="Recent changes" flush={items.length > 0}>
          {audit.isLoading ? (
            <SkeletonText lines={3} />
          ) : audit.error ? (
            <ErrorAlert error={audit.error} title="Couldn't load recent changes" />
          ) : items.length === 0 ? (
            <p className={t.muted}>No changes yet.</p>
          ) : (
            <ItemGroup>
              {items.map((e) => (
                <Item key={e.id} size="xs" className={t.row}>
                  <ItemContent>
                    {/* A simple change in one line, like the audit log ("Role Member → Editor"); the team is this page's. */}
                    <ItemTitle>{changeTitle(e)}</ItemTitle>
                    <ItemDescription>
                      {actorName(e.actor, e)} · <RelativeTime value={e.occurredAt} />
                    </ItemDescription>
                  </ItemContent>
                </Item>
              ))}
            </ItemGroup>
          )}
        </Card>
        <Card
          title="About"
          actions={
            <Button size="sm" variant="ghost" render={<Link to="/admin/teams/$team" params={{ team: slug }} search={{ tab: "settings" }} />}>
              Settings <ArrowRight aria-hidden />
            </Button>
          }
        >
          <DescriptionList
            items={[
              { label: "Description", value: summary.team.description || "No description" },
              { label: "Created", value: <Time value={summary.team.createdAt} format="date" /> },
              ...(summary.team.archivedAt ? [{ label: "Archived", value: <Time value={summary.team.archivedAt} format="date" /> }] : []),
            ]}
          />
        </Card>
      </div>
    </div>
  );
}
