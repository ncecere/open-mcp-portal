/*
 * Publishing: a team's owners and admins publish a server (a request under
 * approval_required, at once under self_publish), withdraw a request, take
 * a published server off the catalog or make a rejected one private again;
 * platform admins approve or reject a request, or remove a published server
 * from the catalog (a reject). Approve needs the capabilities read from the
 * current URL (409 not_refreshed otherwise).
 *
 * An approval is bound to what its reader saw: the dialogs send the server's
 * reviewDigest as it was when they opened, and a 409 changed_since_review
 * (a refresh or an edit in between) approves nothing and says to reload.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError, api, unwrap } from "../../api/client";
import { plural } from "../../lib/format";
import { ConfirmMutationDialog } from "../confirm-dialog";
import { FormDialog } from "../form-dialog";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Field } from "@/components/ui/field/field";
import { Textarea } from "@/components/ui/input/input";
import { toast } from "@/components/ui/toast/toast";
import { type McpServer, totalCount } from "./labels";
import { RequirementSummary } from "./requirement-card";
import { invalidateServer, type ServerScope, storeServer } from "./scope";
import { SignInSummary } from "./sign-in-card";
import { authModeOf } from "./upstream-auth";

const maxNote = 2000;

/** The text for a 409 changed_since_review: what was reviewed isn't what the server holds now. */
export const changedSinceReviewText = "This changed since you opened it. Reload and review it again.";

/** Maps changed_since_review to its fixed text (for ErrorAlert's describe). */
export const describeChangedSinceReview = (e: unknown) => (e instanceof ApiError && e.code === "changed_since_review" ? { message: changedSinceReviewText, tone: "warning" as const } : undefined);

/** What the server receives with each call: how the portal authenticates (sign-in, identity) and, without OAuth, the callers' accounts. */
function ServerReceives({ server, scope }: { server: McpServer; scope: ServerScope }) {
  return (
    <section aria-label="What the server receives">
      <p>
        <strong>What the server receives</strong>
      </p>
      <SignInSummary server={server} />
      {authModeOf(server) !== "oauth" && authModeOf(server) !== "machine_oauth" && (
        <>
          <p>
            <strong>On behalf of callers</strong>
          </p>
          <RequirementSummary server={server} scope={scope} />
        </>
      )}
    </section>
  );
}

/** Why Publish can't run yet (the server answers 409 for these), or undefined. */
export function publishBlocked(server: McpServer) {
  if (!server.enabled) return "Enable the server first.";
  if (!server.refreshedAt) return authModeOf(server) === "oauth" ? "Authorize to read its tools first." : "Refresh its capabilities first.";
  return undefined;
}

/** Why a platform admin can't approve yet: the capabilities weren't read from the current URL. */
export function approveBlocked(server: McpServer) {
  if (server.refreshedAt) return undefined;
  return authModeOf(server) === "oauth"
    ? "Its capabilities haven't been read yet: someone on the team signs in to read them first."
    : "Its capabilities haven't been read from its current URL yet. The team refreshes the server first.";
}

/** Publish (self_publish) or request a review (approval_required), with an optional note. */
export function PublishDialog({ server, onClose }: { server: McpServer; onClose: () => void }) {
  const qc = useQueryClient();
  const [note, setNote] = useState("");
  // The digest of what this dialog showed when it opened: a refetch while it is open must not replace it.
  const [seen] = useState(server.reviewDigest);
  const self = server.effectivePublishPolicy === "self_publish";
  const publish = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/teams/{team}/mcp-servers/{serverId}/publish", {
          params: { path: { team: server.teamSlug, serverId: server.id } },
          body: { ...(note.trim() ? { note: note.trim() } : {}), ...(seen ? { expectedDigest: seen } : {}) },
        }),
      ),
    onSuccess: (s) => {
      storeServer(qc, s);
      toast.success(s.publishState === "published" ? `${s.name} is in the catalog` : "Review requested", s.publishState === "published" ? undefined : "A platform admin reviews it next.");
      onClose();
    },
    onError: (err) => {
      if (err instanceof ApiError && err.status === 409) invalidateServer(qc, server);
    },
  });
  const count = plural(totalCount(server.counts), "capability", "capabilities");
  return (
    <FormDialog
      title={self ? `Publish ${server.name} to the catalog?` : `Request publishing ${server.name}`}
      description={
        self
          ? `Your team publishes without a review: ${server.name} appears in the company catalog now, and its ${count} are approved as they are. Everyone signed in can see them.`
          : `A platform admin reviews ${server.name}, its ${count} and what it receives on behalf of callers before it appears in the company catalog. You can withdraw the request until then.`
      }
      onClose={onClose}
      onSubmit={() => publish.mutate()}
      submitLabel={self ? "Publish" : "Request review"}
      busy={publish.isPending}
    >
      <ServerReceives server={server} scope={{ kind: "team", team: server.teamSlug }} />
      <Field label={self ? "Note" : "Note for the reviewer"} labelHint="Optional" description={self ? "Kept with the server's publishing record." : "What the server is for, who should use it, anything they should check."}>
        <Textarea rows={3} maxLength={maxNote} value={note} onChange={(e) => setNote(e.target.value)} />
      </Field>
      <ErrorAlert error={publish.error} describe={describeChangedSinceReview} />
    </FormDialog>
  );
}

const unpublishText = {
  pending: {
    title: () => "Withdraw the publishing request?",
    description: "The review stops and the server stays private to your team. You can request it again later.",
    confirm: "Withdraw request",
    done: () => "Request withdrawn",
  },
  published: {
    title: (n: string) => `Remove ${n} from the catalog?`,
    description: "It becomes private to your team again: people in other teams no longer find it in the catalog. Publishing it again follows the team's policy.",
    confirm: "Remove from catalog",
    done: (n: string) => `${n} was removed from the catalog`,
  },
  rejected: {
    title: (n: string) => `Make ${n} private?`,
    description: "The rejection is set aside and the server is private to your team, as it was before the request. You can request a review again later.",
    confirm: "Make private",
    done: (n: string) => `${n} is private`,
  },
};

/** Withdraw a pending request, take a published server off the catalog, or make a rejected one private (owners and admins). */
export function UnpublishDialog({ server, open, onClose }: { server: McpServer; open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const text = unpublishText[server.publishState === "private" ? "published" : server.publishState];
  const unpublish = useMutation({
    mutationFn: async () => unwrap(await api.POST("/v1/teams/{team}/mcp-servers/{serverId}/unpublish", { params: { path: { team: server.teamSlug, serverId: server.id } } })),
    onSuccess: (s) => {
      storeServer(qc, s);
      toast.success(text.done(s.name));
      onClose();
    },
  });
  return (
    <ConfirmMutationDialog
      target={open ? server : null}
      onClose={onClose}
      mutation={unpublish}
      onConfirm={() => unpublish.mutate()}
      tone={server.publishState === "published" ? "danger" : "primary"}
      title={text.title(server.name)}
      description={text.description}
      confirmLabel={text.confirm}
    />
  );
}

export type ReviewDecision = "approve" | "reject" | "remove";

const reviewText: Record<ReviewDecision, { title: (n: string) => string; description: string; submit: string; done: (n: string) => string }> = {
  approve: {
    title: (n) => `Approve ${n} for the catalog?`,
    description: "It's published now, with its current capabilities approved as they are. Read them first on the Capabilities tab.",
    submit: "Approve and publish",
    done: (n) => `${n} is in the catalog`,
  },
  reject: {
    title: (n) => `Reject ${n}?`,
    description: "It stays private to its team, which sees your note and can fix what's needed and ask again.",
    submit: "Reject",
    done: (n) => `${n} was rejected`,
  },
  remove: {
    title: (n) => `Remove ${n} from the catalog?`,
    description: "People outside its team no longer find it in the catalog. The server is marked rejected, and its team sees your note.",
    submit: "Remove from catalog",
    done: (n) => `${n} was removed from the catalog`,
  },
};

/** A platform admin's review: approve a request, reject it, or remove a published server (both with a note). */
export function ReviewDialog({ server, decision, onClose }: { server: McpServer; decision: ReviewDecision; onClose: () => void }) {
  const qc = useQueryClient();
  const [note, setNote] = useState("");
  const [submitted, setSubmitted] = useState(false);
  // What the admin was shown when the dialog opened; an approval names it (a refetch must not replace it).
  const [seen] = useState(server.reviewDigest);
  const needsNote = decision !== "approve";
  const missing = needsNote && !note.trim();
  const text = reviewText[decision];
  const review = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.POST("/v1/admin/mcp-servers/{serverId}/review", {
          params: { path: { serverId: server.id } },
          body: {
            decision: decision === "approve" ? "approve" : "reject",
            ...(note.trim() ? { note: note.trim() } : {}),
            ...(decision === "approve" ? { expectedDigest: seen ?? "" } : {}),
          },
        }),
      ),
    onSuccess: (s) => {
      storeServer(qc, s);
      toast.success(text.done(s.name));
      onClose();
    },
    // The server may have changed under the reviewer (a new URL): load it again.
    onError: (err) => {
      if (err instanceof ApiError && err.status === 409) invalidateServer(qc, server);
    },
  });
  const blocked = decision === "approve" ? approveBlocked(server) : undefined;
  return (
    <FormDialog
      title={text.title(server.name)}
      description={text.description}
      onClose={onClose}
      formProps={{ noValidate: true }}
      onSubmit={() => {
        setSubmitted(true);
        if (!missing && !blocked) review.mutate();
      }}
      submitLabel={text.submit}
      submitDisabled={Boolean(blocked)}
      busy={review.isPending}
    >
      {decision === "approve" && <ApproveChecks server={server} />}
      {decision === "approve" && <ServerReceives server={server} scope={{ kind: "admin" }} />}
      {server.publishRequestNote && decision !== "remove" && (
        <p>
          <strong>The team's note:</strong> <span>{server.publishRequestNote}</span>
        </p>
      )}
      <Field
        label="Note for the team"
        labelHint={needsNote ? undefined : "Optional"}
        description={needsNote ? "Required: say why, so the team knows what to change." : "Shown to the team with the decision."}
        error={submitted && missing ? "Say why, so the team knows what to change." : undefined}
      >
        <Textarea aria-required={needsNote} rows={3} maxLength={maxNote} value={note} onChange={(e) => setNote(e.target.value)} />
      </Field>
      <ErrorAlert
        error={review.error}
        title={decision === "approve" ? "Couldn't approve the server" : undefined}
        describe={(e) =>
          e instanceof ApiError && e.code === "not_refreshed"
            ? { message: "Its capabilities haven't been read from its current URL, so there's nothing reviewed to approve. The team refreshes the server first; then approve it." }
            : describeChangedSinceReview(e)
        }
      />
    </FormDialog>
  );
}

/** What an approver should know first: the endpoint wasn't read from its current URL, or never checked. */
function ApproveChecks({ server }: { server: McpServer }) {
  const blocked = approveBlocked(server);
  if (blocked) {
    return (
      <Alert tone="warning" title="Not read from its current URL">
        {blocked} Approve becomes available once it has been.
      </Alert>
    );
  }
  if (server.health.status === "unknown") {
    return (
      <Alert tone="warning" title="Not checked yet">
        The portal hasn't checked this endpoint's health yet, so it's not known whether it answers.
      </Alert>
    );
  }
  if (server.health.status === "failing") {
    return <Alert tone="warning" title="The endpoint is failing">Its last health check failed. People in the catalog may not be able to use it.</Alert>;
  }
  return null;
}
