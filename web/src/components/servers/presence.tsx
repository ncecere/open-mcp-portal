/*
 * "Requires a present person" (decision 66): a server, and each of its capabilities, can refuse calls an agent
 * platform relays for a person when the platform says the person isn't present (scheduled or background work).
 * A call on a relay account that names nobody (a token without a person, or no token) is refused too (M-2).
 * The server's switch applies to every capability that doesn't override it; the override is required, not
 * required or the server's. Requiring never needs review; relaxing a requirement sends a published server back
 * to review under approval_required, like widening what a capability receives.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ifMatch, unwrap } from "../../api/client";
import { FormDialog } from "../form-dialog";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { RadioGroup } from "@/components/ui/radio-group/radio-group";
import { Switch } from "@/components/ui/switch/switch";
import { toast } from "@/components/ui/toast/toast";
import type { McpCapability, McpServer } from "./labels";
import { reviewedAgain } from "./requirement";
import { capabilitiesQuery, invalidateServer, type ServerScope } from "./scope";

export type PresenceMode = "inherit" | "required" | "not_required";

export const presenceHelp =
  "When on, a call that comes through an agent platform's relay account is refused with a tool error unless it is for a person who is present. That includes a person the platform says isn't present (scheduled or background work) and a call that names nobody (a team agent's shared thread, a background run, or no identity token). Recommended for tools that send mail, post or spend. Calls from people's own keys and apps, and from ordinary service accounts, are never affected.";

export const presenceLabels: Record<PresenceMode, string> = {
  inherit: "Same as the server",
  required: "Needs a present person",
  not_required: "Doesn't need a present person",
};

/** What a capability's present-person setting comes to (the server's switch unless it overrides). */
export const presenceOf = (c: McpCapability) => c.presentPerson ?? { mode: "inherit" as const, effective: false };

/** Whether turning the switch off (or an override off) relaxes a capability that required a present person. */
export function relaxesServerSwitch(wasOn: boolean, isOn: boolean, caps: McpCapability[] | undefined) {
  return wasOn && !isOn && (caps ?? []).some((c) => !c.goneAt && presenceOf(c).mode === "inherit");
}

export function PresentPersonSwitch({ checked, onChange, disabled, leaves, server }: { checked: boolean; onChange: (on: boolean) => void; disabled: boolean; leaves: boolean; server: McpServer }) {
  return (
    <>
      <Switch label="Require a present person for calls from agents" description={presenceHelp} disabled={disabled} checked={checked} onCheckedChange={onChange} />
      {leaves && reviewedAgain(server) && (
        <Alert tone="warning" title="The server will leave the catalog">
          Your team needs approval to publish, and turning this off lets agents call some capabilities when nobody is present, so it&apos;s reviewed again: once you save,{" "}
          {server.name} is out of the company catalog until a platform admin approves it. Turning it on never needs a review.
        </Alert>
      )}
    </>
  );
}

type Props = { cap: McpCapability; server: McpServer; scope: ServerScope & { kind: "team" }; onClose: () => void };

export function PresenceDialog({ cap, server, scope, onClose }: Props) {
  const qc = useQueryClient();
  const [mode, setMode] = useState<PresenceMode>(presenceOf(cap).mode);
  const after = mode === "inherit" ? (server.requiresPresentPerson ?? false) : mode === "required";
  const leaves = reviewedAgain(server) && presenceOf(cap).effective && !after;
  const save = useMutation({
    mutationFn: async () =>
      unwrap(
        await api.PUT("/v1/teams/{team}/mcp-servers/{serverId}/capabilities/{capabilityId}/present-person", {
          params: { path: { team: scope.team, serverId: server.id, capabilityId: cap.id }, header: ifMatch(server.revision) },
          body: { mode },
        }),
      ),
    onSuccess: (updated) => {
      qc.setQueryData<McpCapability[]>(capabilitiesQuery(scope, server.id).queryKey, (list) => list?.map((c) => (c.id === updated.id ? updated : c)));
      invalidateServer(qc, server);
      toast.success(`${cap.name}: ${presenceLabels[mode].toLowerCase()}`, leaves ? `${server.name} left the catalog until a platform admin reviews it.` : undefined);
      onClose();
    },
  });
  return (
    <FormDialog
      title={`Present person for ${cap.name}`}
      description={`Whether calls to ${cap.name} that come through an agent platform's relay account need a person who is present. A call that names nobody doesn't have one.`}
      onClose={onClose}
      onSubmit={() => save.mutate()}
      submitLabel="Save"
      busy={save.isPending}
    >
      <RadioGroup<PresenceMode>
        legend="Present person"
        value={mode}
        onValueChange={(m) => {
          if (save.error) save.reset();
          setMode(m);
        }}
        options={[
          { value: "inherit", label: presenceLabels.inherit, description: `${server.requiresPresentPerson ? "The server requires a present person" : "The server doesn't require one"}, so this capability ${server.requiresPresentPerson ? "does too" : "doesn't"}.` },
          { value: "required", label: presenceLabels.required, description: "Refused for an agent working when nobody is there: scheduled runs, webhooks and other background work." },
          { value: "not_required", label: presenceLabels.not_required, description: "Allowed in background work, even when the server requires a present person." },
        ]}
      />
      {leaves && (
        <Alert tone="warning" title="The server will leave the catalog">
          Your team needs approval to publish, and this lets agents call {cap.name} when nobody is present, so it&apos;s reviewed again: once you save, {server.name} is out of
          the company catalog until a platform admin approves it.
        </Alert>
      )}
      <ErrorAlert error={save.error} title="Couldn't save the setting" />
    </FormDialog>
  );
}
