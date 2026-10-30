/*
 * Edit a server's governance (decision 88): owner, on-call contact,
 * sensitivity, lifecycle with its sunset date and replacement. The form keeps
 * the revision it opened with (a change made elsewhere is told, never
 * overwritten) and sends only what changed. Raising the sensitivity of a
 * published server sends it back to review under approval_required: the
 * dialog says so before it is saved. A label nobody confirmed is confirmed by
 * sending one: choosing another label does, and so does ticking the box for
 * the one it has (saving other changes alone never does).
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError, api, ifMatch, staleMessage, unwrap } from "../../api/client";
import { membersQuery } from "../../api/queries";
import { FormDialog } from "../form-dialog";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Checkbox } from "@/components/ui/checkbox/checkbox";
import { Field } from "@/components/ui/field/field";
import { Input, NativeSelect } from "@/components/ui/input/input";
import { toast } from "@/components/ui/toast/toast";
import { lifecycleLabels, raises, type Sensitivity, sensitivities, sensitivityLabels, type ServerLifecycle, unconfirmedTitle } from "./governance";
import type { McpServer } from "./labels";
import { reviewedAgain } from "./requirement";
import { type ServerScope, storeServer } from "./scope";
import m from "./servers.module.css";

type Props = { server: McpServer; scope: ServerScope & { kind: "team" }; onClose: () => void };

/** A datetime-local value for an ISO time, in the viewer's zone. */
const localValue = (iso?: string | null) => {
  if (!iso) return "";
  const d = new Date(iso);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
};

const errorTexts: Record<string, string> = {
  invalid_owner: "Choose an active editor, admin or owner of this team.",
  invalid_oncall_contact: "Use an email address, an http(s) or tel: link, or a channel such as #oncall (up to 200 characters).",
  sunset_in_past: "Choose a sunset date in the future.",
  invalid_replacement: "Choose another published server (or one of this team's) that isn't retired itself.",
  lifecycle_active: "Deprecate the server first: a sunset date or a replacement belongs to a retiring server.",
};

export function GovernanceDialog({ server, scope, onClose }: Props) {
  const qc = useQueryClient();
  const g = server.governance!;
  // What was reviewed, with its revision: a refetch never rebases this edit.
  const [seen] = useState(() => ({ revision: server.revision, g }));
  const [owner, setOwner] = useState(g.ownerUserId ?? "");
  const [oncall, setOncall] = useState(g.oncallContact ?? "");
  const [sensitivity, setSensitivity] = useState<Sensitivity>(g.sensitivity);
  const [lifecycle, setLifecycle] = useState<ServerLifecycle>(g.lifecycle);
  const [sunset, setSunset] = useState(localValue(g.sunsetAt));
  const [replacement, setReplacement] = useState(g.replacement?.id ?? "");
  const [confirmLabel, setConfirmLabel] = useState(false);
  const [stale, setStale] = useState(false);
  const members = useQuery(membersQuery(scope.team));
  const others = useQuery({
    queryKey: ["governance", "replacements", server.id],
    queryFn: async () => unwrap(await api.GET("/v1/catalog/servers", { params: { query: { limit: 100 } } })),
  });
  const owners = (members.data ?? []).filter((x) => x.role !== "member");
  const candidates = (others.data?.items ?? []).filter((x) => x.id !== server.id);
  const retiring = lifecycle !== "active";
  const leaves = reviewedAgain(server) && raises(seen.g.sensitivity, sensitivity);
  const governance: Record<string, unknown> = {};
  if (owner !== (seen.g.ownerUserId ?? "")) governance.ownerUserId = owner || null;
  if (oncall.trim() !== (seen.g.oncallContact ?? "")) governance.oncallContact = oncall.trim() || null;
  const unconfirmed = seen.g.sensitivityConfirmed === false;
  if (sensitivity !== seen.g.sensitivity || (unconfirmed && confirmLabel)) governance.sensitivity = sensitivity;
  if (lifecycle !== seen.g.lifecycle) governance.lifecycle = lifecycle;
  if (retiring && sunset !== localValue(seen.g.sunsetAt)) governance.sunsetAt = sunset ? new Date(sunset).toISOString() : null;
  if (retiring && replacement !== (seen.g.replacement?.id ?? "")) governance.replacementServerId = replacement || null;
  const save = useMutation({
    mutationFn: async () =>
      unwrap(await api.PATCH("/v1/teams/{team}/mcp-servers/{serverId}", { params: { path: { team: scope.team, serverId: server.id }, header: ifMatch(seen.revision) }, body: { governance } as never })),
    onSuccess: (updated) => {
      storeServer(qc, updated);
      toast.success("Governance saved", leaves ? "The server went back to review." : undefined);
      onClose();
    },
    onError: (err) => {
      if (err instanceof ApiError && (err.status === 412 || err.status === 409)) setStale(true);
    },
  });
  return (
    <FormDialog
      title="Edit governance"
      description={`Who is accountable for ${server.name}, whom to page and how sensitive it is. Only this team's owners and admins change it; automation tokens never do.`}
      onClose={onClose}
      onSubmit={() => {
        if (Object.keys(governance).length && !stale) save.mutate();
      }}
      submitLabel="Save governance"
      submitDisabled={!Object.keys(governance).length || stale}
      busy={save.isPending}
    >
      <div className={m.stack}>
        {stale && (
          <Alert tone="warning" title="Changed elsewhere">
            {staleMessage} Close this and open it again to start from what is saved now.
          </Alert>
        )}
        <Field label="Owner" description="The person accountable for the server: an active editor, admin or owner of this team. Leave empty and it shows in attention lists.">
          <NativeSelect value={owner} disabled={save.isPending} onChange={(e) => setOwner(e.target.value)}>
            <option value="">Nobody</option>
            {owners.map((x) => (
              <option key={x.user.id} value={x.user.id}>
                {x.user.displayName || x.user.email} ({x.role})
              </option>
            ))}
          </NativeSelect>
        </Field>
        <Field label="On-call contact" labelHint="Optional" description="Whom to page when it's unhealthy: an email address, a link or a channel such as #oncall.">
          <Input maxLength={200} value={oncall} disabled={save.isPending} onChange={(e) => setOncall(e.target.value)} />
        </Field>
        <Field label="Sensitivity" description="A gateway never serves a server above its own ceiling.">
          <NativeSelect value={sensitivity} disabled={save.isPending} onChange={(e) => setSensitivity(e.target.value as Sensitivity)}>
            {sensitivities.map((x) => (
              <option key={x} value={x}>
                {sensitivityLabels[x]}
              </option>
            ))}
          </NativeSelect>
        </Field>
        {unconfirmed && (
          <Checkbox
            label={`${sensitivityLabels[sensitivity]} is the right label for this server`}
            description={
              sensitivity === seen.g.sensitivity
                ? `${unconfirmedTitle}: ${sensitivity === "internal" ? "Internal is only a default until you confirm it." : `${sensitivityLabels[sensitivity]} has not been confirmed.`} Saving other changes doesn't confirm it.`
                : "Saving a different label confirms it."
            }
            checked={confirmLabel || sensitivity !== seen.g.sensitivity}
            disabled={save.isPending || sensitivity !== seen.g.sensitivity}
            onCheckedChange={setConfirmLabel}
          />
        )}
        {leaves && (
          <Alert tone="warning" title="It goes back to review">
            Raising the sensitivity of a published server sends it to a platform admin again, and it leaves the catalog until they approve. Lowering it never does.
          </Alert>
        )}
        <Field label="Lifecycle" description="Deprecated servers show a banner and tell the owners of gateways that select them. A sunset stops serving the server everywhere.">
          <NativeSelect value={lifecycle} disabled={save.isPending} onChange={(e) => setLifecycle(e.target.value as ServerLifecycle)}>
            {(Object.keys(lifecycleLabels) as ServerLifecycle[]).map((x) => (
              <option key={x} value={x}>
                {lifecycleLabels[x]}
              </option>
            ))}
          </NativeSelect>
        </Field>
        {retiring && (
          <>
            <Field label="Stops being served at" labelHint="Optional" description={lifecycle === "sunset" ? "A sunset server has a date; leave it to use now." : "At this moment no gateway serves the server any more."}>
              <Input type="datetime-local" value={sunset} disabled={save.isPending} onChange={(e) => setSunset(e.target.value)} />
            </Field>
            <Field label="Replacement" labelHint="Optional" description="Shown in the banner and in notices. A published server, or one of this team's.">
              <NativeSelect value={replacement} disabled={save.isPending} onChange={(e) => setReplacement(e.target.value)}>
                <option value="">None</option>
                {g.replacement && !candidates.some((x) => x.id === g.replacement!.id) && <option value={g.replacement.id}>{g.replacement.name}</option>}
                {candidates.map((x) => (
                  <option key={x.id} value={x.id}>
                    {x.name} ({x.teamName})
                  </option>
                ))}
              </NativeSelect>
            </Field>
          </>
        )}
        {save.error && <ErrorAlert error={save.error} title="Couldn't save" describe={(e) => (e instanceof ApiError && errorTexts[e.code] ? { message: errorTexts[e.code]!, tone: "warning" as const } : undefined)} />}
      </div>
    </FormDialog>
  );
}
