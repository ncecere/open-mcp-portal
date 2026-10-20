/*
 * Admin → Auth providers › one provider (/admin/auth-providers/$providerId):
 * a DetailPage with Overview (the redirect URI to register, the stored
 * configuration without the secret, where it's used), Access (who may use it:
 * open to every team, or restricted to listed teams and servers, decision 69)
 * and Settings (If-Match; platform admins change and delete it, auditors read).
 */
import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "@tanstack/react-router";
import { LayoutDashboard, Server, Settings2, ShieldCheck } from "lucide-react";
import { adminAuthProviderQuery } from "@/api/queries";
import { isNotFound, NotFoundState } from "@/components/not-found";
import { PageSkeleton } from "@/components/page-skeleton";
import { type AuthProvider, presetLabels } from "@/components/providers/labels";
import { EnabledBadge } from "@/components/servers/badges";
import { Badge } from "@/components/ui/badge/badge";
import { DetailPage } from "@/components/templates/detail-page";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { plural } from "@/lib/format";
import { authProviderTabs } from "@/lib/tabs";
import s from "../../shared.module.css";
import { useIsPlatformAdmin } from "../hooks";
import { ProviderAccessTab } from "./access-tab";
import { ProviderOverviewTab } from "./overview-tab";
import { ProviderSettingsTab } from "./settings-tab";

export function AdminAuthProviderPage() {
  const { providerId } = useParams({ from: "/app/admin/auth-providers/$providerId" });
  const provider = useQuery(adminAuthProviderQuery(providerId));
  if (provider.isLoading) return <PageSkeleton />;
  if (isNotFound(provider.error)) return <NotFoundState what="object" />;
  if (!provider.data) return <ErrorAlert error={provider.error} title="Couldn't load this provider" onRetry={() => void provider.refetch()} />;
  return <Record provider={provider.data} />;
}

function Record({ provider }: { provider: AuthProvider }) {
  const isAdmin = useIsPlatformAdmin();
  return (
    <DetailPage
      title={provider.name}
      meta={
        <>
          {!provider.enabled && <EnabledBadge enabled={false} />}
          {provider.accessMode === "open" && <Badge tone="warning">Open to every team</Badge>}
        </>
      }
      facts={[
        { label: "Slug", value: <code className={s.mono}>{provider.slug}</code> },
        { label: "Preset", value: provider.preset ? presetLabels[provider.preset] : "Custom" },
        { label: "Servers", value: provider.serverCount ? plural(provider.serverCount, "server") : "No servers" },
        { label: "Connections", value: plural(provider.connectionCount, "connection") },
      ]}
      menuLabel="More provider actions"
      menuActions={[{ label: "Servers that require it", icon: <Server aria-hidden />, render: <Link to="/admin/servers" search={{ provider: provider.id }} /> }]}
      notices={
        !provider.enabled && (
          <Alert tone="warning" title="Turned off">
            Calls that need {provider.name} are refused and nobody can connect it. Connections are kept.{isAdmin ? " Turn it on in Settings." : ""}
          </Alert>
        )
      }
      tabIds={authProviderTabs}
      tabsLabel="Provider sections"
      tabs={[
        { value: "overview", label: "Overview", icon: <LayoutDashboard aria-hidden />, content: <ProviderOverviewTab provider={provider} /> },
        { value: "access", label: "Access", icon: <ShieldCheck aria-hidden />, content: <ProviderAccessTab provider={provider} /> },
        { value: "settings", label: "Settings", icon: <Settings2 aria-hidden />, content: <ProviderSettingsTab provider={provider} /> },
      ]}
    />
  );
}
