/*
 * A server's place in the company catalog (Overview tab): its publish state
 * and what it means, the team's effective policy, the request and the
 * review, and the actions the viewer has: Publish / Request review,
 * Withdraw, Remove from catalog, Make private (the team's owners and
 * admins), or Approve / Reject / Remove (platform admins). Also the record's
 * notices. A private server shows no history: it's not on its way anywhere.
 */
import { useQuery } from "@tanstack/react-query";
import { Check, Lock, Send, Undo2, X } from "lucide-react";
import { useState } from "react";
import { Alert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { DescriptionList } from "@/components/ui/description-list/description-list";
import { Time } from "@/components/ui/time/time";
import s from "../../pages/shared.module.css";
import { PublishStateBadge } from "./badges";
import { RetirementBanner } from "./governance-card";
import { type McpServer, policyHelp, policyLabels, publishStateText } from "./labels";
import { approveBlocked, PublishDialog, publishBlocked, ReviewDialog, type ReviewDecision, UnpublishDialog } from "./publish-dialogs";
import { type ServerAbilities, type ServerScope, teamPublishingQuery } from "./scope";
import m from "./servers.module.css";

/** The record's notices, on every tab: rejected (with the note), waiting for review, changes waiting, disabled. */
export function ServerNotices({ server, scope }: { server: McpServer; scope: ServerScope }) {
  const admin = scope.kind === "admin";
  const approval =
    server.effectivePublishPolicy === "self_publish"
      ? `the team's owners and admins${admin ? " or a platform admin" : ""} approve the change`
      : "a platform admin approves the change";
  return (
    <>
      <RetirementBanner server={server} />
      {server.publishState === "rejected" && (
        <Alert tone="danger" title="Rejected for the catalog">
          {server.publishReviewedByName ?? "A platform admin"}
          {server.publishReviewedAt && (
            <>
              {" "}
              on <Time value={server.publishReviewedAt} format="date" />
            </>
          )}
          {server.publishReviewNote ? <>: “{server.publishReviewNote}”</> : "."} The server stays private to its team.
        </Alert>
      )}
      {server.publishState === "pending" && (
        <Alert tone="info" title="Waiting for review">
          {admin
            ? `The team asked to publish this server${server.publishReviewedAt ? " again" : ""}. Read its capabilities, then approve or reject it on the Overview tab.`
            : server.publishReviewedAt
              ? "A platform admin reviews the server again before it's in the catalog."
              : "A platform admin reviews the server before it appears in the catalog."}
        </Alert>
      )}
      {server.pendingChanges > 0 && (
        <Alert tone="warning" title={server.pendingChanges === 1 ? "1 capability changed since it was approved" : `${server.pendingChanges} capabilities changed since they were approved`}>
          The catalog leaves them out until {approval} on the Capabilities tab.
        </Alert>
      )}
      {!server.enabled && (
        <Alert tone="warning" title="Disabled">
          Nothing connects to the server while it's disabled, and it can't be published.
        </Alert>
      )}
    </>
  );
}

type Dialog = "publish" | "unpublish" | ReviewDecision | null;

export function CatalogCard({ server, scope, abilities }: { server: McpServer; scope: ServerScope; abilities: ServerAbilities }) {
  const [dialog, setDialog] = useState<Dialog>(null);
  const publishing = useQuery({ ...teamPublishingQuery(scope.kind === "team" ? scope.team : ""), enabled: scope.kind === "team" });
  const state = server.publishState;
  const self = server.effectivePublishPolicy === "self_publish";
  const blocked = publishBlocked(server);
  const noApprove = approveBlocked(server);
  const source = publishing.data ? (publishing.data.override ? "Set for this team by a platform admin." : "The platform default.") : "";

  const actions = (
    <div className={m.actions}>
      {abilities.canManage && (state === "private" || state === "rejected") && (
        <Button size="sm" disabled={Boolean(blocked)} title={blocked} onClick={() => setDialog("publish")}>
          <Send aria-hidden /> {self ? "Publish…" : state === "rejected" ? "Request review again…" : "Request review…"}
        </Button>
      )}
      {abilities.canManage && state === "rejected" && (
        <Button size="sm" variant="secondary" onClick={() => setDialog("unpublish")}>
          <Lock aria-hidden /> Make private…
        </Button>
      )}
      {abilities.canManage && state === "pending" && (
        <Button size="sm" variant="secondary" onClick={() => setDialog("unpublish")}>
          <Undo2 aria-hidden /> Withdraw request
        </Button>
      )}
      {abilities.canManage && state === "published" && (
        <Button size="sm" variant="secondary" onClick={() => setDialog("unpublish")}>
          Remove from catalog…
        </Button>
      )}
      {abilities.canReview && state === "pending" && (
        <>
          <Button size="sm" variant="secondary" onClick={() => setDialog("reject")}>
            <X aria-hidden /> Reject…
          </Button>
          <Button size="sm" disabled={Boolean(noApprove)} title={noApprove} onClick={() => setDialog("approve")}>
            <Check aria-hidden /> Approve…
          </Button>
        </>
      )}
      {abilities.canReview && state === "published" && (
        <Button size="sm" variant="secondary" onClick={() => setDialog("remove")}>
          Remove from catalog…
        </Button>
      )}
    </div>
  );

  return (
    <Card title="Company catalog" description={publishStateText(server)} actions={actions}>
      <DescriptionList
        dividers
        items={[
          { label: "State", value: <PublishStateBadge state={state} /> },
          {
            label: "Policy",
            value: (
              <span className={m.stack}>
                <span className={s.primary}>{policyLabels[server.effectivePublishPolicy]}</span>
                <span className={s.secondary}>
                  {policyHelp(server.effectivePublishPolicy, scope.kind === "team" ? "your team's" : "the team's")} {source}
                </span>
              </span>
            ),
          },
          ...history(server),
        ]}
      />
      {abilities.canReview && state === "pending" && noApprove && <p className={s.note}>To approve: {noApprove.charAt(0).toLowerCase() + noApprove.slice(1)}</p>}
      {abilities.canManage && (state === "private" || state === "rejected") && blocked && <p className={s.note}>To publish: {blocked.charAt(0).toLowerCase() + blocked.slice(1)}</p>}
      {scope.kind === "team" && !abilities.canManage && <p className={s.note}>The team's owners and admins publish servers and take them off the catalog.</p>}
      {dialog === "publish" && <PublishDialog server={server} onClose={() => setDialog(null)} />}
      <UnpublishDialog server={server} open={dialog === "unpublish"} onClose={() => setDialog(null)} />
      {(dialog === "approve" || dialog === "reject" || dialog === "remove") && <ReviewDialog server={server} decision={dialog} onClose={() => setDialog(null)} />}
    </Card>
  );
}

/**
 * The request and the review, as far as they matter now: none for a private server; a server published without a
 * review (self_publish) shows when it was published, not a request; a pending one shows only its request (an
 * earlier review is over).
 */
function history(server: McpServer) {
  const state = server.publishState;
  if (state === "private") return [];
  const requestedAt = server.publishRequestedAt;
  // A review from before the latest request (a rejection, then a self-publish) is over too.
  const reviewed = server.publishReviewedAt && (!requestedAt || Date.parse(server.publishReviewedAt) >= Date.parse(requestedAt)) ? server.publishReviewedAt : null;
  const reviewedAt = state === "published" || state === "rejected" ? reviewed : null;
  const selfPublished = state === "published" && !reviewedAt;
  return [
    ...(requestedAt
      ? [{ label: selfPublished ? "Published" : "Requested", value: <RequestLine at={requestedAt} note={server.publishRequestNote} /> }]
      : []),
    ...(reviewedAt ? [{ label: "Reviewed", value: <RequestLine at={reviewedAt} by={server.publishReviewedByName} note={server.publishReviewNote} /> }] : []),
  ];
}

function RequestLine({ at, by, note }: { at: string; by?: string | null; note?: string | null }) {
  return (
    <span className={m.stack}>
      <span>
        <Time value={at} />
        {by ? ` by ${by}` : ""}
      </span>
      {note && <span className={m.message}>“{note}”</span>}
    </span>
  );
}
