/*
 * A team's service accounts (/teams/$team/service-accounts): name, role,
 * switch, active keys and last use, searched in ?q=. The team's owners and
 * admins create accounts on a form page (?form=new); members and platform
 * staff read.
 */
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Bot, Plus } from "lucide-react";
import { serviceAccountsQuery } from "../../../api/queries";
import { EnabledBadge } from "../../../components/servers/badges";
import { useFormParam } from "../../../components/templates/form-page";
import { ListPage, RelativeTime, timeColumn } from "../../../components/templates/list-page";
import { terms } from "../../../lib/terms";
import { Badge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { CellText, type DataTableColumn } from "@/components/ui/data-table/data-table";
import { TextLink } from "@/components/ui/text-link/text-link";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import { Tabs, TabsList, TabsPanel, Tab } from "@/components/ui/tabs/tabs";
import { useSearchParams } from "@/lib/url-search";
import { TeamConnectionsTab } from "./connections-tab";
import s from "../../shared.module.css";
import { ReadOnlyNotice } from "../access";
import { useTeam } from "../common";
import { ArchivedNotice } from "../layout";
import { CreateServiceAccountForm } from "./create-form";
import { activeKeysText, roleLabel, type ServiceAccount, whatIsAServiceAccount } from "./labels";

function columns(team: string): DataTableColumn<ServiceAccount>[] {
  const link = (a: ServiceAccount) => <Link to="/teams/$team/service-accounts/$serviceAccountId" params={{ team, serviceAccountId: a.id }} />;
  return [
    {
      id: "name",
      header: "Service account",
      accessor: (a) => a.name,
      rowHeader: true,
      hideable: false,
      sortable: true,
      cell: (a) => (
        <CellText
          className={s.compactCell}
          wrap="anywhere"
          primary={<TextLink render={link(a)}>{a.name}</TextLink>}
          secondary={a.description ? <span className={s.truncate} title={a.description}>{a.description}</span> : undefined}
        />
      ),
    },
    { id: "role", header: "Role", accessor: (a) => roleLabel(a.role), sortable: true, cell: (a) => <Badge tone={a.role === "editor" ? "info" : "neutral"}>{roleLabel(a.role)}</Badge> },
    { id: "enabled", header: "Status", accessor: (a) => (a.retired ? "Retired" : a.enabled ? "Enabled" : "Disabled"), sortable: true, cell: (a) => (
        <span className={s.badges}>
          <EnabledBadge enabled={a.enabled} />
          {a.retired && <Badge tone="warning">Retired</Badge>}
        </span>
      ),
    },
    {
      id: "keys",
      header: "Keys",
      accessor: (a) => a.activeKeyCount,
      sortable: true,
      cell: (a) => <span className={a.activeKeyCount === 0 ? s.muted : s.nowrap}>{activeKeysText(a.activeKeyCount)}</span>,
    },
    {
      ...timeColumn<ServiceAccount>("lastUsedAt", "Last used", (a) => a.lastUsedAt),
      cell: (a) => (a.lastUsedAt ? <span className={s.nowrap}><RelativeTime value={a.lastUsedAt} /></span> : <span className={s.muted}>Never</span>),
    },
    { ...timeColumn<ServiceAccount>("createdAt", "Created", (a) => a.createdAt), defaultHidden: true },
  ];
}

export function ServiceAccountsPage() {
  const { slug, team, isManager, archived } = useTeam();
  const form = useFormParam();
  const [params, setParams] = useSearchParams();
  const section = params.get("tab") === "connections" ? "connections" : "accounts";
  const canCreate = isManager && !archived;
  const accounts = useQuery(serviceAccountsQuery(slug));
  const create = canCreate && (
    <Button onClick={() => form.open("new")}>
      <Plus aria-hidden /> Create service account
    </Button>
  );
  const open = (a: ServiceAccount, tab?: "keys" | "settings") => (
    <Link to="/teams/$team/service-accounts/$serviceAccountId" params={{ team: slug, serviceAccountId: a.id }} search={tab ? { tab } : {}} />
  );
  return (
    <Stack gap={6} className={s.page}>
      <PageHeader title={terms.serviceAccounts} description={`Identities ${team.name} owns for CI, scripts and headless agents. Their keys reach the team's gateways and the platform gateways granted to the team.`} actions={section === "accounts" ? create : undefined} />
      <ArchivedNotice>Its service accounts can be viewed but not changed, and their keys don&apos;t work while the team is archived.</ArchivedNotice>
      <ReadOnlyNotice what="the team's service accounts" managers change="create and manage them and their keys" />
      <Tabs value={section} onValueChange={(value) => setParams((old) => { const next = new URLSearchParams(old); if (value === "connections") next.set("tab", "connections"); else next.delete("tab"); return next; })}>
        <TabsList aria-label="Service accounts sections"><Tab value="accounts">Accounts</Tab><Tab value="connections">Connections</Tab></TabsList>
        <TabsPanel value="accounts">
      <ListPage<ServiceAccount>
        id="team-service-accounts"
        caption={terms.serviceAccounts}
        columns={columns(slug)}
        data={accounts.data ?? []}
        getRowId={(a) => a.id}
        rowLabel={(a) => a.name}
        search={{ label: "Search service accounts", placeholder: "Name or description" }}
        loading={accounts.isLoading}
        error={accounts.error}
        onRetry={() => void accounts.refetch()}
        rowActions={(a) => [
          { label: "Open", render: open(a) },
          { label: "Keys", render: open(a, "keys") },
          { label: "Settings", hidden: !canCreate, render: open(a, "settings") },
        ]}
        empty={{ icon: <Bot />, title: "No service accounts yet.", description: whatIsAServiceAccount, action: create || undefined }}
        tableProps={{ columnsMenuMin: 6 }}
      />
        </TabsPanel>
        <TabsPanel value="connections"><TeamConnectionsTab team={slug} canManage={canCreate} /></TabsPanel>
      </Tabs>
      {canCreate && form.id === "new" && <CreateServiceAccountForm team={slug} onClose={form.close} />}
    </Stack>
  );
}
