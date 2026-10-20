/*
 * Admin → Auth providers (decision 25): the OAuth apps people connect their
 * accounts with, so tools can act as them (GitHub, Google, Atlassian…).
 * Name with slug and preset, the switch, how many servers require it and
 * how many people connected it. Platform admins add one on a form page
 * (?form=new); auditors read.
 */
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { KeySquare, Plus } from "lucide-react";
import { api, unwrap } from "@/api/client";
import { adminAuthProvidersKey } from "@/api/queries";
import { accessModeLabels, type AuthProvider, presetLabels } from "@/components/providers/labels";
import { EnabledBadge } from "@/components/servers/badges";
import { Badge } from "@/components/ui/badge/badge";
import { useFormParam } from "@/components/templates/form-page";
import { ListPage, timeColumn } from "@/components/templates/list-page";
import { Button } from "@/components/ui/button/button";
import { CellText, type DataTableColumn } from "@/components/ui/data-table/data-table";
import { TextLink } from "@/components/ui/text-link/text-link";
import { plural } from "@/lib/format";
import { terms } from "@/lib/terms";
import s from "../../shared.module.css";
import { useIsPlatformAdmin } from "../hooks";
import { CreateProviderForm } from "./create-form";

const link = (p: AuthProvider) => <Link to="/admin/auth-providers/$providerId" params={{ providerId: p.id }} />;

const columns: DataTableColumn<AuthProvider>[] = [
  {
    id: "name",
    header: "Provider",
    accessor: (p) => p.name,
    rowHeader: true,
    hideable: false,
    sortable: true,
    cell: (p) => (
      <CellText
        wrap="anywhere"
        primary={<TextLink render={link(p)}>{p.name}</TextLink>}
        secondary={
          <span>
            <span className={s.mono}>{p.slug}</span>
            {p.preset ? ` · ${presetLabels[p.preset]} preset` : " · Custom"}
          </span>
        }
      />
    ),
  },
  { id: "enabled", header: "Status", accessor: (p) => (p.enabled ? "Enabled" : "Disabled"), sortable: true, cell: (p) => <EnabledBadge enabled={p.enabled} /> },
  {
    id: "access",
    header: "Access",
    accessor: (p) => accessModeLabels[p.accessMode],
    sortable: true,
    // Every provider that existed before the list stays open: flagged until an admin restricts it.
    cell: (p) => <Badge tone={p.accessMode === "open" ? "warning" : "neutral"}>{accessModeLabels[p.accessMode]}</Badge>,
  },
  {
    id: "servers",
    header: "Servers",
    accessor: (p) => p.serverCount,
    sortable: true,
    cell: (p) =>
      p.serverCount > 0 ? (
        <TextLink render={<Link to="/admin/servers" search={{ provider: p.id }} />}>{plural(p.serverCount, "server")}</TextLink>
      ) : (
        <span className={s.muted}>None</span>
      ),
  },
  { id: "connections", header: "Connections", accessor: (p) => p.connectionCount, sortable: true, cell: (p) => <span className={s.nowrap}>{p.connectionCount.toLocaleString()}</span> },
  { ...timeColumn<AuthProvider>("createdAt", "Added", (p) => p.createdAt), defaultHidden: true },
];

export function AdminAuthProvidersPage() {
  const isAdmin = useIsPlatformAdmin();
  const form = useFormParam();
  const providers = useQuery({ queryKey: [...adminAuthProvidersKey, "list"], queryFn: async () => unwrap(await api.GET("/v1/admin/auth-providers")) });
  const add = isAdmin && (
    <Button onClick={() => form.open("new")}>
      <Plus aria-hidden /> Add auth provider
    </Button>
  );
  return (
    <>
      <ListPage<AuthProvider>
        id="admin-auth-providers"
        title={terms.authProviders}
        description="OAuth apps people connect their own accounts with, so a server's tools can act as them (create a GitHub issue, read a Google Drive file). Teams choose a provider and scopes on their servers; the portal keeps the tokens and sends each one only to the server that needs it."
        primaryAction={add || undefined}
        caption={terms.authProviders}
        columns={columns}
        data={providers.data ?? []}
        getRowId={(p) => p.id}
        rowLabel={(p) => p.name}
        search={{ label: "Search providers", placeholder: "Name or slug" }}
        loading={providers.isLoading}
        error={providers.error}
        onRetry={() => void providers.refetch()}
        rowActions={(p) => [
          { label: "Open", render: link(p) },
          { label: "Settings", hidden: !isAdmin, render: <Link to="/admin/auth-providers/$providerId" params={{ providerId: p.id }} search={{ tab: "settings" }} /> },
        ]}
        empty={{
          icon: <KeySquare />,
          title: "No auth providers yet.",
          description: isAdmin
            ? "Add one so servers can act as the person who calls them on GitHub, Google, Atlassian, Slack, GitLab or your own OAuth service."
            : "Platform admins add the OAuth apps people connect their accounts with.",
          action: add || undefined,
        }}
        tableProps={{ columnsMenuMin: 5 }}
      />
      {isAdmin && form.id === "new" && <CreateProviderForm onClose={form.close} />}
    </>
  );
}
