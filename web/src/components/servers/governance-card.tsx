/*
 * A server's Governance card (Overview tab, decision 88): who is accountable
 * for it, whom to page, how sensitive it is, when it is next reviewed and
 * whether it is being retired. A team's owners and admins edit it, or offer
 * the server to another team (the receiving team's owner accepts); an overdue
 * review asks for a new one with Publish. Editors, members and platform staff
 * read. The on-call contact and the owner are the team's: the catalog never
 * shows them.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowRightLeft, Pencil, Send } from "lucide-react";
import { useState } from "react";
import { api, unwrap } from "../../api/client";
import { Alert } from "@/components/ui/alert/alert";
import { Badge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { DescriptionList } from "@/components/ui/description-list/description-list";
import { TextLink } from "@/components/ui/text-link/text-link";
import { Time } from "@/components/ui/time/time";
import { toast } from "@/components/ui/toast/toast";
import s from "../../pages/shared.module.css";
import { GovernanceDialog } from "./governance-dialog";
import { lifecycleLabels, retirementText, type ServerLifecycle, sensitivityHelp, sensitivityLabels, sensitivityTone } from "./governance";
import type { McpServer } from "./labels";
import { invalidateServer, type ServerAbilities, type ServerScope, storeServer } from "./scope";
import m from "./servers.module.css";
import { CancelTransferDialog, RequestTransferDialog } from "./transfer-dialogs";

type Props = { server: McpServer; scope: ServerScope; abilities: ServerAbilities };

/** The on-call contact: a link when it is one, else the text. */
function Contact({ value }: { value: string }) {
  if (/^https?:\/\//.test(value)) return <TextLink href={value}>{value}</TextLink>;
  if (/^[^\s@]+@[^\s@]+$/.test(value)) return <TextLink href={`mailto:${value}`}>{value}</TextLink>;
  return <span>{value}</span>;
}

/** The banner of a deprecated or retired server, on every tab and in the catalog. */
export function RetirementBanner({ server }: { server: { name: string; governance?: { lifecycle: ServerLifecycle; sunsetAt?: string | null; replacement?: { name: string } | null } } }) {
  const g = server.governance;
  if (!g || g.lifecycle === "active") return null;
  return (
    <Alert tone={g.lifecycle === "sunset" ? "danger" : "warning"} title={g.lifecycle === "sunset" ? `${server.name} is retired` : `${server.name} is deprecated`}>
      {retirementText({ lifecycle: g.lifecycle, sunsetAt: g.sunsetAt, replacement: g.replacement })}
    </Alert>
  );
}

export function GovernanceCard({ server, scope, abilities }: Props) {
  const qc = useQueryClient();
  const [dialog, setDialog] = useState<"edit" | "transfer" | "cancel" | null>(null);
  const g = server.governance;
  const team = scope.kind === "team";
  const manage = team && abilities.canManage;
  const again = useMutation({
    mutationFn: async () => unwrap(await api.POST("/v1/teams/{team}/mcp-servers/{serverId}/publish", { params: { path: { team: server.teamSlug, serverId: server.id } }, body: {} })),
    onSuccess: (updated) => {
      storeServer(qc, updated);
      toast.success(updated.publishState === "pending" ? "Review requested" : "Review confirmed", updated.publishState === "pending" ? "A platform admin reviews the server again." : undefined);
    },
    onSettled: () => invalidateServer(qc, server),
  });
  if (!g) return null;
  const retiring = g.lifecycle !== "active";
  return (
    <Card
      title="Governance"
      description="Who is accountable for this server, whom to page, how sensitive it is and whether it is being retired."
      actions={
        manage && (
          <div className={m.actions}>
            <Button size="sm" variant="secondary" onClick={() => setDialog("edit")}>
              <Pencil aria-hidden /> Edit governance
            </Button>
            {g.pendingTransfer ? (
              <Button size="sm" variant="secondary" onClick={() => setDialog("cancel")}>
                Withdraw transfer
              </Button>
            ) : (
              <Button size="sm" variant="secondary" onClick={() => setDialog("transfer")}>
                <ArrowRightLeft aria-hidden /> Offer to another team
              </Button>
            )}
          </div>
        )
      }
    >
      <div className={m.stack}>
        {g.ownerless && server.publishState === "published" && (
          <Alert tone="warning" title="Nobody is accountable for this server">
            {g.ownerUserId ? "Its owner left the team or lost their editor role." : "No owner is named."} {manage ? "Choose an editor, admin or owner of the team as its owner." : "A team owner or admin chooses its owner."}
          </Alert>
        )}
        {g.reviewOverdue && (
          <Alert
            tone="warning"
            title="Its review is overdue"
            actions={
              manage ? (
                <Button size="sm" loading={again.isPending} onClick={() => again.mutate()}>
                  <Send aria-hidden /> {server.effectivePublishPolicy === "self_publish" ? "Confirm the review" : "Ask for a review"}
                </Button>
              ) : undefined
            }
          >
            It was due <Time value={g.reviewDueAt ?? ""} format="date" />. The server stays published meanwhile.
          </Alert>
        )}
        {g.pendingTransfer && (
          <Alert tone="info" title={`Offered to ${g.pendingTransfer.toTeamName}`}>
            Nothing moves until an owner of {g.pendingTransfer.toTeamName} accepts. Editing the server in the meantime means asking again.
          </Alert>
        )}
        <DescriptionList
          dividers
          items={[
            {
              label: "Owner",
              value: g.ownerUserId ? <span className={g.ownerless ? m.danger : undefined}>{g.ownerName ?? "Unknown"}{g.ownerless ? " (no longer an editor of the team)" : ""}</span> : <span className={s.muted}>Nobody</span>,
            },
            { label: "On call", value: g.oncallContact ? <Contact value={g.oncallContact} /> : <span className={s.muted}>Not set</span> },
            {
              label: "Sensitivity",
              value: (
                <span className={m.inline}>
                  <Badge tone={sensitivityTone[g.sensitivity]}>{sensitivityLabels[g.sensitivity]}</Badge>
                  <span className={s.muted}>{sensitivityHelp[g.sensitivity]}</span>
                </span>
              ),
            },
            ...(server.publishState === "published"
              ? [{ label: "Next review", value: g.reviewDueAt ? <Time value={g.reviewDueAt} format="date" /> : <span className={s.muted}>None scheduled</span> }]
              : []),
            ...(g.lastReviewedAt ? [{ label: "Last reviewed", value: <Time value={g.lastReviewedAt} format="date" /> }] : []),
            { label: "Lifecycle", value: lifecycleLabels[g.lifecycle] },
            ...(retiring && g.sunsetAt ? [{ label: g.lifecycle === "sunset" ? "Retired" : "Stops being served", value: <Time value={g.sunsetAt} /> }] : []),
            ...(retiring && g.replacement ? [{ label: "Replacement", value: `${g.replacement.name} (${g.replacement.teamName})` }] : []),
          ]}
        />
      </div>
      {dialog === "edit" && <GovernanceDialog server={server} scope={scope as ServerScope & { kind: "team" }} onClose={() => setDialog(null)} />}
      {dialog === "transfer" && <RequestTransferDialog server={server} onClose={() => setDialog(null)} />}
      {dialog === "cancel" && g.pendingTransfer && <CancelTransferDialog team={server.teamSlug} serverName={server.name} transfer={g.pendingTransfer} onClose={() => setDialog(null)} />}
    </Card>
  );
}
