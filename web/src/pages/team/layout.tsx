import { useQuery } from "@tanstack/react-query";
import { Link, Outlet, useParams, useRouterState } from "@tanstack/react-router";
import { Lock } from "lucide-react";
import type { ReactNode } from "react";
import { teamQuery } from "../../api/queries";
import { NotFoundState, isNotFound } from "../../components/not-found";
import { PageSkeleton } from "../../components/page-skeleton";
import { useCurrentUser } from "../../session";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { EmptyState } from "@/components/ui/empty-state/empty-state";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import s from "../shared.module.css";
import { TeamContext, teamCtx, useTeam } from "./common";

/**
 * Pages platform staff who aren't members may open: the overview, team settings, usage, the MCP servers, the
 * gateways, the service accounts and call records (which platform staff read, as the API allows). Later team
 * pages are members only.
 */
const staffPage = (path: string) => /^\/teams\/[^/]+(\/settings|\/usage|\/approval-rules|\/(servers|gateways|service-accounts|calls)(\/[^/]+)?)?\/?$/.test(path);

/** The team area: loads the team and provides it to the current team page. */
export function TeamLayout() {
  const { team } = useParams({ from: "/app/teams/$team" });
  const view = useQuery(teamQuery(team));
  const me = useCurrentUser();
  const path = useRouterState({ select: (st) => st.location.pathname });

  if (view.isLoading) return <PageSkeleton />;
  if (isNotFound(view.error) || (!view.error && !view.data)) return <NotFoundState what="team" />;
  if (view.error) return <ErrorAlert error={view.error} title="Couldn't load this team" />;
  if (!view.data) return null;
  const ctx = teamCtx(view.data.team, view.data.role);
  // Platform staff can see a team's overview, settings and members but not its content,
  // which is private to members. Say so instead of showing a load error.
  if (!view.data.role && !staffPage(path)) {
    return (
      <Stack gap={6} className={s.page}>
        <PageHeader title={view.data.team.name} />
        <Card>
          <EmptyState
            icon={<Lock />}
            title="Only team members can see this."
            description={`This page of ${view.data.team.name} is private to its members. As platform staff you can ${me.capabilities.platformAdmin ? "manage" : "see"} the team's settings and members.`}
            action={
              <Button render={<Link to="/admin/teams/$team" params={{ team }} />} variant="secondary">
                Open in Admin
              </Button>
            }
          />
        </Card>
      </Stack>
    );
  }

  return (
    <TeamContext.Provider value={ctx}>
      <Outlet />
    </TeamContext.Provider>
  );
}

/** The "archived" notice shown on every team page of an archived team. */
export function ArchivedNotice({ children }: { children?: ReactNode }) {
  const { archived } = useTeam();
  if (!archived) return null;
  return (
    <Alert tone="warning" title="This team is archived">
      {children ?? "Its members and settings can be viewed but not changed."}
    </Alert>
  );
}

export { TeamOverviewPage } from "./overview/page";
