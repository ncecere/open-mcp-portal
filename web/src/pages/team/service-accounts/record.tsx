/*
 * One of the team's service accounts (/teams/$team/service-accounts/$id): a
 * DetailPage with Overview (its role and what its keys reach), Keys (create
 * once-shown keys, at most two active, revoke) and Settings (name,
 * description, role, switch; delete). Owners and admins of an active team
 * manage it; members read it (not its keys); platform staff read it and its
 * keys, and can open its calls in Admin.
 */
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { Activity, KeyRound, LayoutDashboard, Settings2 } from "lucide-react";
import { serviceAccountQuery } from "../../../api/queries";
import { EnabledBadge } from "../../../components/servers/badges";
import { isNotFound, NotFoundState } from "../../../components/not-found";
import { PageSkeleton } from "../../../components/page-skeleton";
import { RelativeTime } from "../../../components/templates/list-page";
import { DetailPage } from "../../../components/templates/detail-page";
import { serviceAccountTabs } from "../../../lib/tabs";
import { useCurrentUser } from "../../../session";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Badge } from "@/components/ui/badge/badge";
import s from "../../shared.module.css";
import { useTeam } from "../common";
import { KeysTab } from "./keys-tab";
import { activeKeysText, roleLabel, type ServiceAccount, type ServiceAccountAbilities, serviceAccountAbilities } from "./labels";
import { OverviewTab } from "./overview-tab";
import { SettingsTab } from "./settings-tab";

export function ServiceAccountPage() {
  const { serviceAccountId } = useParams({ from: "/app/teams/$team/service-accounts/$serviceAccountId" });
  const ctx = useTeam();
  const me = useCurrentUser();
  const account = useQuery(serviceAccountQuery(ctx.slug, serviceAccountId));
  if (account.isLoading) return <PageSkeleton />;
  if (isNotFound(account.error)) return <NotFoundState what="object" />;
  if (!account.data) return <ErrorAlert error={account.error} title="Couldn't load this service account" onRetry={() => void account.refetch()} />;
  const staff = me.capabilities.platformAdmin || me.capabilities.platformAuditor;
  return <Record account={account.data} abilities={serviceAccountAbilities({ ...ctx, staff })} staff={staff} />;
}

/**
 * Why its keys don't work right now, in one notice (turned off, the team archived, or both), so a phone
 * doesn't stack warnings above the tabs.
 */
function StateNotice({ account, abilities, archived }: { account: ServiceAccount; abilities: ServiceAccountAbilities; archived: boolean }) {
  if (archived) {
    return (
      <Alert tone="warning" title={account.enabled ? "This team is archived" : "Turned off, and the team is archived"}>
        {account.enabled
          ? "Its service accounts can be viewed but not changed, and their keys don't work while the team is archived."
          : "Its keys are refused. It can be viewed but not changed, or turned on again, until the team is unarchived."}
      </Alert>
    );
  }
  if (account.enabled) return null;
  return (
    <Alert tone="warning" title="Turned off">
      {`Its keys are refused until it's turned on again. ${abilities.canManage ? "Turn it on in Settings." : "The team's owners and admins can turn it on again."}`}
    </Alert>
  );
}

function Record({ account, abilities, staff }: { account: ServiceAccount; abilities: ServiceAccountAbilities; staff: boolean }) {
  const { archived } = useTeam();
  const props = { account, abilities };
  return (
    <DetailPage
      title={account.name}
      meta={
        !account.enabled || account.relayPlatform ? (
          <span className={s.badges}>
            {!account.enabled && <EnabledBadge enabled={false} />}
            {account.relayPlatform && <Badge tone="info">Relay for {account.relayPlatform.name}</Badge>}
          </span>
        ) : undefined
      }
      description={account.description || undefined}
      facts={[
        { label: "Role", value: roleLabel(account.role) },
        { label: "Keys", value: activeKeysText(account.activeKeyCount) },
        {
          label: "Last used",
          value: account.lastUsedAt ? (
            <span>
              Used <RelativeTime value={account.lastUsedAt} />
            </span>
          ) : (
            "Never used"
          ),
        },
      ]}
      menuLabel="More service account actions"
      menuActions={
        staff
          ? [
              {
                label: "Calls in Admin",
                icon: <Activity aria-hidden />,
                render: <Link to="/admin/calls" search={{ team: account.teamSlug, serviceAccount: account.id }} />,
              },
            ]
          : []
      }
      notices={<StateNotice account={account} abilities={abilities} archived={archived} />}
      tabIds={serviceAccountTabs}
      tabsLabel="Service account sections"
      tabs={[
        { value: "overview", label: "Overview", icon: <LayoutDashboard aria-hidden />, content: <OverviewTab {...props} /> },
        { value: "keys", label: "Keys", icon: <KeyRound aria-hidden />, count: account.activeKeyCount, content: <KeysTab {...props} /> },
        { value: "settings", label: "Settings", icon: <Settings2 aria-hidden />, content: <SettingsTab {...props} /> },
      ]}
    />
  );
}
