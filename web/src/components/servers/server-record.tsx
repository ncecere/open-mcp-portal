/*
 * An MCP server's record, the same in the team's pages and in Admin: a
 * DetailPage with Overview (what it offers, the connection, Test and
 * Refresh, the catalog), Capabilities, Health and Settings (read-only in
 * Admin). What the viewer may do comes in `abilities` (scope.ts).
 */
import { Link } from "@tanstack/react-router";
import { Activity, ExternalLink, LayoutDashboard, ListTree, Settings2, Shield } from "lucide-react";
import type { ReactNode } from "react";
import { serverTabs } from "../../lib/tabs";
import { needsText } from "../providers/labels";
import { DetailPage } from "../templates/detail-page";
import type { ActionItem } from "../templates/action-menu";
import { TextLink } from "@/components/ui/text-link/text-link";
import s from "../../pages/shared.module.css";
import { CaptureBadge } from "../capture";
import { EnabledBadge, PendingChangesBadge, PublishStateBadge, SignInBadge } from "./badges";
import { CapabilitiesTab } from "./capabilities-tab";
import { ServerNotices } from "./catalog-card";
import { HealthTab } from "./health-tab";
import { countsText, type McpServer, totalCount, urlHost } from "./labels";
import { OverviewTab } from "./overview-tab";
import { type ServerAbilities, type ServerScope } from "./scope";
import { ServerSettingsTab } from "./settings-tab";
import { readAsText } from "./upstream-auth";
import m from "./servers.module.css";

type Props = {
  server: McpServer;
  scope: ServerScope;
  abilities: ServerAbilities;
  /** More notices above the record's own (an archived team). */
  notices?: ReactNode;
  /** Links in the "…" menu (open in Admin, open the team's page). */
  links?: ActionItem[];
};

export function ServerRecord({ server, scope, abilities, notices, links = [] }: Props) {
  const props = { server, scope, abilities };
  return (
    <DetailPage
      title={server.name}
      meta={
        <span className={s.badges}>
          <PublishStateBadge state={server.publishState} />
          <PendingChangesBadge count={server.pendingChanges} />
          <SignInBadge authMode={server.authMode} />
          {!server.enabled && <EnabledBadge enabled={false} />}
          {server.capturePayloads && <CaptureBadge />}
        </span>
      }
      description={server.description || undefined}
      facts={[
        { label: "Slug", value: <code className={s.mono}>{server.slug}</code> },
        { label: "Host", value: <span className={m.host}>{urlHost(server.url)}</span> },
        ...(scope.kind === "admin"
          ? [{ label: "Team", value: <TextLink render={<Link to="/admin/teams/$team" params={{ team: server.teamSlug }} />}>{server.teamName}</TextLink> }]
          : []),
        { label: "Capabilities", value: server.refreshedAt ? countsText(server.counts) : "Not read yet" },
        { label: "User authorization", value: server.requirement ? needsText(server.requirement) : undefined },
        { label: "Sign-in", value: server.authMode === "oauth" && server.oauth ? `At ${urlHost(server.oauth.authorizationServer)} · read as ${readAsText(server.oauth.setupConnection)}` : undefined },
        { label: "Keys", value: server.personSecret ? `Each person's own · ${server.personSecret.people} entered` : undefined },
      ]}
      menuLabel="More server actions"
      menuActions={links}
      notices={
        <>
          {notices}
          <ServerNotices server={server} scope={scope} />
        </>
      }
      tabIds={serverTabs}
      tabsLabel="Server sections"
      tabs={[
        { value: "overview", label: "Overview", icon: <LayoutDashboard aria-hidden />, content: <OverviewTab {...props} /> },
        { value: "capabilities", label: "Capabilities", icon: <ListTree aria-hidden />, count: totalCount(server.counts), content: <CapabilitiesTab {...props} /> },
        { value: "health", label: "Health", icon: <Activity aria-hidden />, content: <HealthTab server={server} scope={scope} /> },
        { value: "settings", label: "Settings", icon: <Settings2 aria-hidden />, content: <ServerSettingsTab {...props} /> },
      ]}
    />
  );
}

/** The "…" menu's link between the team's record and Admin's, for whoever can open both. */
export function adminLink(server: McpServer): ActionItem {
  return { label: "Open in Admin", icon: <Shield aria-hidden />, render: <Link to="/admin/servers/$serverId" params={{ serverId: server.id }} /> };
}

export function teamLink(server: McpServer): ActionItem {
  return { label: "Open the team's page", icon: <ExternalLink aria-hidden />, render: <Link to="/teams/$team/servers/$serverId" params={{ team: server.teamSlug, serverId: server.id }} /> };
}
