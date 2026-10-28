/*
 * A gateway's Capabilities tab: the current selection grouped by server,
 * each with whether it's served now (and why not); on team gateways, the
 * lowest team role that may use it. Whoever may edit the gateway opens the
 * picker (capability-picker.tsx) from here.
 */
import { useQuery } from "@tanstack/react-query";
import { ListTree, Pencil } from "lucide-react";
import { useState } from "react";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { EmptyState } from "@/components/ui/empty-state/empty-state";
import { SkeletonText } from "@/components/ui/skeleton/skeleton";
import { serviceAccountsCant } from "../providers/labels";
import { untrustedText } from "../servers/labels";
import { CapabilityList } from "./capability-list";
import { CapabilityPicker } from "./capability-picker";
import { CurationDialog, ToolDefinitionDialog } from "./curation-dialog";
import { capabilityCount, type Gateway, type GatewayCapability } from "./labels";
import { type GatewayAbilities, gatewayCapabilitiesQuery, type GatewayScope } from "./scope";
import { UnavailableCallout } from "./unavailable";

type Props = { gateway: Gateway; scope: GatewayScope; abilities: GatewayAbilities };

export function GatewayCapabilitiesTab({ gateway, scope, abilities }: Props) {
  const caps = useQuery(gatewayCapabilitiesQuery(scope, gateway.id));
  const [editing, setEditing] = useState(false);
  const [curating, setCurating] = useState<GatewayCapability | null>(null);
  const [inspecting, setInspecting] = useState<GatewayCapability | null>(null);
  const roles = gateway.ownerKind === "team";
  if (caps.isLoading) {
    return (
      <div role="status" aria-label="Loading capabilities…">
        <SkeletonText lines={4} />
      </div>
    );
  }
  if (!caps.data) return <ErrorAlert error={caps.error} title="Couldn't load the capabilities" onRetry={() => void caps.refetch()} />;
  if (editing && abilities.canEdit) return <CapabilityPicker gateway={gateway} scope={scope} current={caps.data} onDone={() => setEditing(false)} />;
  const items = caps.data.items;
  const edit = abilities.canEdit && (
    <Button size="sm" variant={items.length ? "secondary" : "primary"} onClick={() => setEditing(true)}>
      <Pencil aria-hidden /> {items.length ? "Edit selection" : "Choose capabilities"}
    </Button>
  );
  return (
    <>
      <UnavailableCallout items={items} />
      {items.length > 0 && <Alert tone="info">{untrustedText}</Alert>}
      <Card
        title="Capabilities"
        description={
          items.length
            ? `${capabilityCount(items.length)} selected. Tools use server__name unless renamed for this gateway.${roles ? " A minimum role limits who on the team may use it." : ""}${
                items.some((c) => c.requires) ? ` Each person connects the accounts marked Needs once. ${serviceAccountsCant}` : ""
              }`
            : undefined
        }
        actions={items.length ? edit : undefined}
      >
        {items.length === 0 ? (
          <EmptyState
            size="compact"
            icon={<ListTree />}
            title="No capabilities selected yet."
            description={
              abilities.canEdit
                ? "Choose the tools, prompts and resources this gateway offers. Until then, clients that connect see nothing."
                : roles
                  ? "The team's owners and admins choose what this gateway offers."
                  : "Platform admins choose what this gateway offers."
            }
            action={edit || undefined}
          />
        ) : (
          <CapabilityList items={items} roles={roles} onCurate={abilities.canEdit ? setCurating : undefined} onInspect={abilities.canReadCalls ? setInspecting : undefined} />
        )}
      </Card>
      {inspecting && abilities.canReadCalls && <ToolDefinitionDialog capability={inspecting} onClose={() => setInspecting(null)} />}
      {curating && abilities.canEdit && <CurationDialog gateway={gateway} scope={scope} current={caps.data} capability={curating} onClose={() => setCurating(null)} />}
    </>
  );
}
