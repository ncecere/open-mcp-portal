/*
 * Recent changes on the team overview: the last five audit entries as
 * compact rows (who · action · target · when). A row opens the entry in Team
 * settings › Audit log; "View all" opens the log.
 */
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ArrowRight, FileClock } from "lucide-react";
import { api, unwrap } from "../../../api/client";
import { actionLabel, actorName, auditKey, targetTypeLabel } from "../../../components/audit/labels";
import { RelativeTime } from "../../../components/templates/relative-time";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { EmptyState } from "@/components/ui/empty-state/empty-state";
import { SkeletonText } from "@/components/ui/skeleton/skeleton";
import { useTeam } from "../common";
import o from "./overview.module.css";

export function RecentChanges() {
  const { slug: team } = useTeam();
  const recent = useQuery({
    queryKey: [...auditKey({ kind: "team", team }), "recent"],
    queryFn: async () => unwrap(await api.GET("/v1/teams/{team}/audit", { params: { path: { team }, query: { limit: 5 } } })),
  });
  const items = recent.data?.items ?? [];
  return (
    <Card
      title="Recent changes"
      actions={
        <Button size="sm" variant="ghost" render={<Link to="/teams/$team/settings" params={{ team }} search={{ tab: "audit" }} aria-label="View all changes" />}>
          View all <ArrowRight aria-hidden />
        </Button>
      }
    >
      {recent.isLoading ? (
        <div role="status" aria-label="Loading recent changes…">
          <SkeletonText lines={3} />
        </div>
      ) : recent.error ? (
        <ErrorAlert error={recent.error} title="Couldn't load recent changes" />
      ) : items.length === 0 ? (
        <EmptyState size="compact" icon={<FileClock />} title="No changes yet." />
      ) : (
        <ul className={o.changes} aria-label="Recent changes">
          {items.map((e) => (
            <li key={e.id}>
              <Link to="/teams/$team/settings" params={{ team }} search={{ tab: "audit", record: e.id } as { tab: "audit" }} className={o.change}>
                <span className={o.changeText}>
                  <span className={o.changeWho}>{actorName(e.actor, e)}</span>
                  <span className={o.changeSep}>·</span>
                  <span>{actionLabel(e.action, e)}</span>
                  {(e.targetLabel || e.targetType) && (
                    <>
                      <span className={o.changeSep}>·</span>
                      <span className={o.changeTarget}>{e.targetLabel ?? targetTypeLabel(e.targetType)}</span>
                    </>
                  )}
                </span>
                <span className={o.changeWhen}>
                  <RelativeTime value={e.occurredAt} />
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
