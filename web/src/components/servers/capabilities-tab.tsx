/*
 * A server's Capabilities tab: everything it listed at its last refresh
 * (gone ones too), filtered by kind and state (?kind=, ?state=), grouped by
 * kind, each with its definition. A published server's changed capability
 * can be approved here, after a confirmation, by whoever the policy allows:
 * the team's owners and admins under self_publish, platform admins always
 * (in Admin). Only they are told to read the text before approving.
 *
 * Each capability shows the account it needs ("Needs GitHub (repo)"), and
 * on a server that requires one, editors and above override it per
 * capability (override-dialog.tsx): the server's, none, or other scopes.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, KeyRound, ListTree, UserCheck } from "lucide-react";
import { useState } from "react";
import { ApiError, api, unwrap } from "../../api/client";
import { ConfirmMutationDialog } from "../confirm-dialog";
import { needsText, serviceAccountsCant } from "../providers/labels";
import { RequiresBadge } from "../providers/requires";
import { useListFilters } from "../templates/list-page";
import { Badge } from "@/components/ui/badge/badge";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { EmptyState } from "@/components/ui/empty-state/empty-state";
import { type Facet, FilterBar, facetCounts, filterRows } from "@/components/ui/filter-bar/filter-bar";
import { SkeletonText } from "@/components/ui/skeleton/skeleton";
import { Time } from "@/components/ui/time/time";
import { toast } from "@/components/ui/toast/toast";
import s from "../../pages/shared.module.css";
import { CapabilityStateBadge } from "./badges";
import { CapabilityItem } from "./capability-item";
import { ClassificationDialog } from "./classification";
import { changedSinceReviewText } from "./publish-dialogs";
import { kindOrder, kindTitle, type McpCapability, type McpServer, untrustedApproverText, untrustedText } from "./labels";
import { capabilitiesQuery, invalidateServer, type ServerAbilities, type ServerScope } from "./scope";
import { OverrideDialog } from "./override-dialog";
import { PresenceDialog, presenceLabels, presenceOf } from "./presence";
import { overrideLabels } from "./requirement";
import m from "./servers.module.css";

const stateOf = (c: McpCapability) => (c.goneAt ? "gone" : c.changed ? "changed" : c.approved ? "approved" : "listed");

const facets: Facet<McpCapability>[] = [
  { id: "kind", label: "Kind", type: "toggle", allLabel: "All", accessor: (c) => c.kind, options: kindOrder.map((k) => ({ value: k, label: kindTitle(k) })) },
  {
    id: "state",
    label: "State",
    type: "toggle",
    allLabel: "Any",
    accessor: stateOf,
    options: [
      { value: "changed", label: "Changed" },
      { value: "approved", label: "Approved" },
      { value: "gone", label: "Gone" },
    ],
  },
];

type Props = { server: McpServer; scope: ServerScope; abilities: ServerAbilities };

export function CapabilitiesTab({ server, scope, abilities }: Props) {
  const caps = useQuery(capabilitiesQuery(scope, server.id));
  const [classifying, setClassifying] = useState(false);
  const { values, setValues } = useListFilters(facets);
  const all = caps.data ?? [];
  const shown = filterRows(all, facets, values);
  const inCatalog = server.publishState !== "private";
  const changed = all.some((c) => c.changed && !c.goneAt);
  const waitsForAdmin = scope.kind === "team" && abilities.canManage && !abilities.canApproveChanges && changed;

  return (
    <>
      <Alert tone="warning" title="Untrusted text">
        {abilities.canApproveChanges || abilities.canReview ? untrustedApproverText : untrustedText}
      </Alert>
      {waitsForAdmin && <Alert tone="info">Your team needs approval to publish, so a platform admin approves changed capabilities.</Alert>}
      {server.requirement && (
        <Alert tone="info" title={`Calls carry the caller's ${server.requirement.providerName} token`}>
          {needsText(server.requirement)} unless a capability says otherwise (its badge shows what it receives). {serviceAccountsCant}
        </Alert>
      )}
      <Card title="Capabilities" description={server.refreshedAt ? <>As listed at the last refresh, <Time value={server.refreshedAt} />.</> : "Not read yet."}>
        <div className={m.stack}>
          {scope.kind === "team" && abilities.canManage && all.some((c) => c.kind === "tool" && !c.goneAt) && (
            <Button variant="secondary" onClick={() => setClassifying(true)}>Classify tools…</Button>
          )}
          {classifying && scope.kind === "team" && <ClassificationDialog caps={all} server={server} scope={scope} onClose={() => setClassifying(false)} />}
          {all.length > 0 && <FilterBar facets={facets} value={values} onValueChange={setValues} counts={facetCounts(all, facets, values)} />}
          {caps.isLoading ? (
            <div role="status" aria-label="Loading capabilities…">
              <SkeletonText lines={4} />
            </div>
          ) : caps.error ? (
            <ErrorAlert error={caps.error} title="Couldn't load the capabilities" onRetry={() => void caps.refetch()} />
          ) : all.length === 0 ? (
            <EmptyState
              size="compact"
              icon={<ListTree />}
              title={server.refreshedAt ? "The server lists nothing." : "Nothing read yet."}
              description={abilities.canEdit ? "Refresh the server on the Overview tab to read what it offers." : "An editor refreshes the server to read what it offers."}
            />
          ) : shown.length === 0 ? (
            <p className={s.muted}>No capabilities match the filters.</p>
          ) : (
            kindOrder
              .filter((k) => shown.some((c) => c.kind === k))
              .map((k) => (
                <section key={k} className={m.kindGroup} aria-labelledby={`kind-${k}`}>
                  <h3 id={`kind-${k}`} className={m.kindTitle}>
                    {kindTitle(k)}
                  </h3>
                  <ul className={m.capList}>
                    {shown
                      .filter((c) => c.kind === k)
                      .map((c) => (
                        <CapabilityRow key={c.id} cap={c} server={server} scope={scope} abilities={abilities} inCatalog={inCatalog} />
                      ))}
                  </ul>
                </section>
              ))
          )}
        </div>
      </Card>
    </>
  );
}

function CapabilityRow({ cap, server, scope, abilities, inCatalog }: { cap: McpCapability; inCatalog: boolean } & Props) {
  const qc = useQueryClient();
  const [confirming, setConfirming] = useState<McpCapability | null>(null);
  const [overriding, setOverriding] = useState(false);
  const [presence, setPresence] = useState(false);
  const [classifying, setClassifying] = useState(false);
  // The approval names the fingerprint of the definition the approver confirmed (the one in `confirming`), so a
  // refresh in between fails with 409 changed_since_review instead of approving text nobody read.
  const send = async (expectedFingerprint: string) =>
    scope.kind === "team"
      ? unwrap(
          await api.PUT("/v1/teams/{team}/mcp-servers/{serverId}/capabilities/{capabilityId}/approval", {
            params: { path: { team: scope.team, serverId: server.id, capabilityId: cap.id } },
            body: { expectedFingerprint },
          }),
        )
      : unwrap(
          await api.PUT("/v1/admin/mcp-servers/{serverId}/capabilities/{capabilityId}/approval", {
            params: { path: { serverId: server.id, capabilityId: cap.id } },
            body: { expectedFingerprint },
          }),
        );
  const approve = useMutation({
    mutationFn: async (expectedFingerprint: string) => {
      try {
        return await send(expectedFingerprint);
      } catch (err) {
        // The dialog shows the error's message: say plainly what to do.
        if (err instanceof ApiError && err.code === "changed_since_review") throw new ApiError(err.status, err.code, changedSinceReviewText, err.details);
        throw err;
      }
    },
    onSuccess: (updated) => {
      qc.setQueryData<McpCapability[]>(capabilitiesQuery(scope, server.id).queryKey, (list) => list?.map((c) => (c.id === updated.id ? updated : c)));
      invalidateServer(qc, server);
      setConfirming(null);
      toast.success(`The change to ${cap.name} was approved`, "The catalog shows its new definition.");
    },
    // Changed under the approver: show the new definition (the list reloads); the dialog says to review it again.
    onError: (err) => {
      if (err instanceof ApiError && err.status === 409) {
        void qc.invalidateQueries({ queryKey: capabilitiesQuery(scope, server.id).queryKey });
        invalidateServer(qc, server);
      }
    },
  });
  const canApprove = abilities.canApproveChanges && cap.changed && !cap.goneAt;
  const canOverride = scope.kind === "team" && abilities.canEdit && Boolean(server.requirement) && !cap.goneAt;
  const mode = cap.requirementOverride.mode;
  const canPresence = scope.kind === "team" && abilities.canEdit && !cap.goneAt;
  const canClassify = scope.kind === "team" && abilities.canManage && cap.kind === "tool" && !cap.goneAt;
  const present = presenceOf(cap);
  return (
    <CapabilityItem
      cap={cap}
      muted={Boolean(cap.goneAt)}
      badges={
        <>
          <CapabilityStateBadge cap={cap} inCatalog={inCatalog} />
          {cap.requires && <RequiresBadge req={cap.requires} note={serviceAccountsCant} />}
          {mode !== "inherit" && (
            <Badge size="sm" variant="outline" title="Set on this capability; the server's requirement doesn't apply.">
              {overrideLabels[mode]}
            </Badge>
          )}
          {present.effective && (
            <Badge size="sm" variant="outline" tone="info" title="A call through an agent platform's relay account is refused unless it is for a person who is present (not for scheduled or background work, and not when it names nobody).">
              Needs a present person
            </Badge>
          )}
        </>
      }
      meta={
        <p className={m.capMeta}>
          {cap.goneAt ? (
            <>
              No longer listed since <Time value={cap.goneAt} format="date" />.
            </>
          ) : cap.changed ? (
            "Its definition changed since it was approved. The catalog leaves it out until the change is approved."
          ) : cap.approved && cap.approvedAt ? (
            <>
              Approved <Time value={cap.approvedAt} format="date" />
              {cap.approvedByName ? ` by ${cap.approvedByName}` : ""}.
            </>
          ) : (
            <>
              First seen <Time value={cap.firstSeenAt} format="date" />.
            </>
          )}
        </p>
      }
      action={
        canApprove || canOverride || canPresence || canClassify ? (
          <div className={m.actions}>
            {canClassify && <Button size="sm" variant="secondary" onClick={() => setClassifying(true)} aria-label={`Classify ${cap.name}`}>Classify…</Button>}
            {classifying && scope.kind === "team" && <ClassificationDialog caps={[cap]} server={server} scope={scope} onClose={() => setClassifying(false)} />}
            {canOverride && (
              <Button size="sm" variant="secondary" onClick={() => setOverriding(true)} aria-label={`Change the account ${cap.name} needs`}>
                <KeyRound aria-hidden /> Account…
              </Button>
            )}
            {canPresence && (
              <Button size="sm" variant="secondary" onClick={() => setPresence(true)} aria-label={`Change whether ${cap.name} needs a present person (now: ${presenceLabels[present.mode].toLowerCase()})`}>
                <UserCheck aria-hidden /> Present person…
              </Button>
            )}
            {presence && scope.kind === "team" && <PresenceDialog cap={cap} server={server} scope={scope} onClose={() => setPresence(false)} />}
            {overriding && scope.kind === "team" && <OverrideDialog cap={cap} server={server} scope={scope} onClose={() => setOverriding(false)} />}
            {canApprove && (
              <>
                <Button size="sm" variant="secondary" onClick={() => setConfirming(cap)} aria-label={`Approve the change to ${cap.name}`}>
                  <Check aria-hidden /> Approve change
                </Button>
                <ConfirmMutationDialog
                  target={confirming}
                  onClose={() => setConfirming(null)}
                  mutation={approve}
                  onConfirm={(c) => approve.mutate(c.fingerprint)}
                  tone="primary"
                  title={`Approve the change to ${cap.name}?`}
                  description="The catalog shows its new definition from now on, and a model will read it. Read the definition before you approve."
                  confirmLabel="Approve change"
                />
              </>
            )}
          </div>
        ) : undefined
      }
    />
  );
}
