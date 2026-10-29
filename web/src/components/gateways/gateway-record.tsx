/*
 * A gateway's record, the same in the team's pages and in Admin: a
 * DetailPage with Overview (endpoint, Connect), Capabilities, Access (grants;
 * platform gateways in Admin), Activity (calls) and Settings. What the
 * viewer may do comes in `abilities` (scope.ts). In Admin a team gateway is
 * read-only except its switch, the header's primary action.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Activity, ExternalLink, LayoutDashboard, ListTree, Power, Settings2, Shield, Users } from "lucide-react";
import { type ReactNode, useState } from "react";
import { gatewayTabs } from "../../lib/tabs";
import { ConfirmMutationDialog } from "../confirm-dialog";
import type { ActionItem } from "../templates/action-menu";
import { DetailPage } from "../templates/detail-page";
import { Alert } from "@/components/ui/alert/alert";
import { Badge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { TextLink } from "@/components/ui/text-link/text-link";
import { toast } from "@/components/ui/toast/toast";
import s from "../../pages/shared.module.css";
import { GatewayAccessTab } from "./access-tab";
import { GatewayActivityTab } from "./activity-tab";
import { CaptureBadge } from "../capture";
import { EnabledBadge, UnavailableCountBadge } from "./badges";
import { GatewayCapabilitiesTab } from "./capabilities-tab";
import { capabilityCount, type Gateway, grantCountLabel, ownerKindLabels } from "./labels";
import { GatewayOverviewTab } from "./overview-tab";
import { type GatewayAbilities, type GatewayScope, storeGateway, updateGateway } from "./scope";
import { GatewaySettingsTab } from "./settings-tab";
import { GatewayRequestSettings } from "./request-settings";

type Props = {
  gateway: Gateway;
  scope: GatewayScope;
  abilities: GatewayAbilities;
  /** More notices above the record (an archived team). */
  notices?: ReactNode;
  /** Links in the "…" menu (open in Admin, open the team's page). */
  links?: ActionItem[];
};

export function GatewayRecord({ gateway, scope, abilities, notices, links = [] }: Props) {
  const props = { gateway, scope, abilities };
  const platform = gateway.ownerKind === "platform";
  return (
    <DetailPage
      title={gateway.name}
      meta={
        <span className={s.badges}>
          {scope.kind === "admin" && <Badge variant="outline">{ownerKindLabels[gateway.ownerKind]}</Badge>}
          {!gateway.enabled && <EnabledBadge enabled={false} />}
          <UnavailableCountBadge count={gateway.unavailableCount} />
          {gateway.capturePayloads && <CaptureBadge />}
        </span>
      }
      description={gateway.description || undefined}
      facts={[
        { label: "Slug", value: <code className={s.mono}>{gateway.slug}</code> },
        ...(scope.kind === "admin" && gateway.teamSlug
          ? [{ label: "Team", value: <TextLink render={<Link to="/admin/teams/$team" params={{ team: gateway.teamSlug }} />}>{gateway.teamName ?? gateway.teamSlug}</TextLink> }]
          : []),
        { label: "Capabilities", value: capabilityCount(gateway.capabilityCount) },
        ...(platform ? [{ label: "Grants", value: grantCountLabel(gateway.grantCount) }] : []),
      ]}
      primaryAction={abilities.canToggle ? <SwitchButton gateway={gateway} scope={scope} /> : undefined}
      menuLabel="More gateway actions"
      menuActions={links}
      notices={
        <>
          {scope.kind === "team" && !gateway.enabled && <TurnedOffNotice canEdit={abilities.canEdit} />}
          {notices}
        </>
      }
      tabIds={gatewayTabs}
      tabsLabel="Gateway sections"
      tabs={[
        { value: "overview", label: "Overview", icon: <LayoutDashboard aria-hidden />, content: <GatewayOverviewTab gateway={gateway} scope={scope} /> },
        { value: "capabilities", label: "Capabilities", icon: <ListTree aria-hidden />, count: gateway.capabilityCount, content: <GatewayCapabilitiesTab {...props} /> },
        { value: "access", label: "Access", icon: <Users aria-hidden />, count: gateway.grantCount, hidden: !(platform && scope.kind === "admin"), content: <GatewayAccessTab gateway={gateway} abilities={abilities} /> },
        { value: "requests", label: "Requests", icon: <Shield aria-hidden />, hidden: !(platform && scope.kind === "admin"), content: <GatewayRequestSettings gatewayId={gateway.id} readOnly={!abilities.canManageGrants} /> },
        { value: "activity", label: "Activity", icon: <Activity aria-hidden />, content: <GatewayActivityTab {...props} /> },
        { value: "settings", label: "Settings", icon: <Settings2 aria-hidden />, content: <GatewaySettingsTab {...props} /> },
      ]}
    />
  );
}

/** A team gateway that's off, on the team's page: nobody can use it, and who can turn it on. */
function TurnedOffNotice({ canEdit }: { canEdit: boolean }) {
  return (
    <Alert tone="warning" title="Turned off">
      {`Nobody can use this gateway: its endpoint answers “not found” and it's missing from everyone's My gateways. ${
        canEdit ? "Turn it on again in Settings." : "The team's owners and admins, or a platform admin, can turn it on again."
      }`}
    </Alert>
  );
}

/** Admin's switch for a team gateway: off at once after a confirmation, on again with one click. */
function SwitchButton({ gateway, scope }: { gateway: Gateway; scope: GatewayScope }) {
  const qc = useQueryClient();
  const [confirming, setConfirming] = useState<Gateway | null>(null);
  const toggle = useMutation({
    mutationFn: async (enabled: boolean) => updateGateway(scope, gateway, { enabled }),
    onSuccess: (updated) => {
      setConfirming(null);
      storeGateway(qc, updated);
      toast.success(updated.enabled ? `${updated.name} is on again` : `${updated.name} is off`, updated.enabled ? undefined : "Its endpoint answers “not found” until it's enabled again.");
    },
  });
  if (!gateway.enabled) {
    return (
      <Button loading={toggle.isPending} onClick={() => toggle.mutate(true)}>
        <Power aria-hidden /> Enable gateway
      </Button>
    );
  }
  return (
    <>
      <Button variant="secondary" onClick={() => setConfirming(gateway)}>
        <Power aria-hidden /> Disable gateway
      </Button>
      <ConfirmMutationDialog
        target={confirming}
        onClose={() => setConfirming(null)}
        mutation={toggle}
        onConfirm={() => toggle.mutate(false)}
        title={`Disable ${gateway.name}?`}
        description={`Everyone using it loses access at once: its endpoint answers “not found”. ${gateway.teamName ?? "The team"} can't use it until a platform admin or the team turns it on again.`}
        confirmLabel="Disable gateway"
      />
    </>
  );
}

/** The "…" menu's link between the team's record and Admin's, for whoever can open both. */
export function adminGatewayLink(gateway: Gateway): ActionItem {
  return { label: "Open in Admin", icon: <Shield aria-hidden />, render: <Link to="/admin/gateways/$gatewayId" params={{ gatewayId: gateway.id }} /> };
}

export function teamGatewayLink(gateway: Gateway): ActionItem | undefined {
  if (!gateway.teamSlug) return undefined;
  return { label: "Open the team's page", icon: <ExternalLink aria-hidden />, render: <Link to="/teams/$team/gateways/$gatewayId" params={{ team: gateway.teamSlug, gatewayId: gateway.id }} /> };
}
