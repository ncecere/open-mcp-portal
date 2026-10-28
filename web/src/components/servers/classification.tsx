/* Owner classification is separate from the upstream's untrusted annotations. */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError, api, ifMatch, unwrap, type Schemas } from "../../api/client";
import { FormDialog } from "../form-dialog";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Badge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { Field } from "@/components/ui/field/field";
import { NativeSelect } from "@/components/ui/input/input";
import { toast } from "@/components/ui/toast/toast";
import type { McpCapability, McpServer } from "./labels";
import { reviewedAgain } from "./requirement";
import { capabilitiesQuery, invalidateServer, type ServerScope } from "./scope";
import m from "./servers.module.css";

export type ToolClass = Schemas["ToolClass"];
export const classLabels: Record<ToolClass, string> = { read: "Read", write: "Write", destructive: "Destructive" };
const classRank = { read: 0, write: 1, destructive: 2 };

/** Null fails closed for future class-based policy, so assigning read/write is a lowering too. */
export function lowersClass(before: ToolClass | null | undefined, after: ToolClass | null) {
  return after !== null && classRank[after] < (before ? classRank[before] : classRank.destructive);
}

type Classified = { kind: string; toolClass?: ToolClass | null; suggestedClass?: ToolClass | null; classDrift?: boolean };

export function ClassificationBadges({ cap }: { cap: Classified }) {
  if (cap.kind !== "tool" || !("toolClass" in cap)) return null;
  return (
    <>
      <Badge size="sm" variant="outline" title="Set by the server team's owners or admins, not by the upstream server.">
        {cap.toolClass ? `Class: ${classLabels[cap.toolClass].toLowerCase()}` : "Unclassified"}
      </Badge>
      {cap.suggestedClass && (
        <Badge size="sm" variant="outline" title="An untrusted suggestion from the server's annotations. Never saved automatically.">
          Suggested: {classLabels[cap.suggestedClass].toLowerCase()}
        </Badge>
      )}
      {cap.classDrift && <Badge size="sm" variant="outline" tone="warning">Class differs from suggestion</Badge>}
    </>
  );
}

type Props = { caps: McpCapability[]; server: McpServer; scope: ServerScope & { kind: "team" }; onClose: () => void };
type Choice = { toolClass: ToolClass | null; viaSuggestion: boolean };

export function ClassificationDialog({ caps, server, scope, onClose }: Props) {
  const qc = useQueryClient();
  // Freeze what was reviewed, including the revision; a refetch never silently rebases this edit.
  const [seen] = useState(() => ({ caps: caps.filter((c) => c.kind === "tool" && !c.goneAt), revision: server.revision }));
  const [choices, setChoices] = useState<Record<string, Choice>>(() => Object.fromEntries(seen.caps.map((c) => [c.id, { toolClass: c.toolClass ?? null, viaSuggestion: false }])));
  const [stale, setStale] = useState(false);
  const items = seen.caps.filter((c) => choices[c.id]!.toolClass !== (c.toolClass ?? null)).map((c) => ({ capabilityId: c.id, ...choices[c.id]! }));
  const leaves = reviewedAgain(server) && items.some((item) => lowersClass(seen.caps.find((c) => c.id === item.capabilityId)!.toolClass, item.toolClass));
  const single = seen.caps.length === 1;
  const save = useMutation({
    mutationFn: async () => {
      const params = { path: { team: scope.team, serverId: server.id }, header: ifMatch(seen.revision) };
      if (single) {
        const item = items[0]!;
        const updated = unwrap(await api.PUT("/v1/teams/{team}/mcp-servers/{serverId}/capabilities/{capabilityId}/class", {
          params: { ...params, path: { ...params.path, capabilityId: item.capabilityId } },
          body: { toolClass: item.toolClass, viaSuggestion: item.viaSuggestion },
        }));
        return [updated];
      }
      return unwrap(await api.PUT("/v1/teams/{team}/mcp-servers/{serverId}/capabilities/classes", { params, body: { items } }));
    },
    onSuccess: (updated) => {
      qc.setQueryData<McpCapability[]>(capabilitiesQuery(scope, server.id).queryKey, (list) => list?.map((c) => updated.find((v) => v.id === c.id) ?? c));
      invalidateServer(qc, server);
      toast.success("Tool classes saved", leaves ? "The server left the catalog until a platform admin reviews it." : undefined);
      onClose();
    },
    onError: (err) => {
      if (err instanceof ApiError && (err.status === 412 || err.status === 409)) {
        setStale(true);
        invalidateServer(qc, server);
      }
    },
  });
  const choose = (id: string, toolClass: ToolClass | null, viaSuggestion = false) => {
    save.reset();
    setChoices((old) => ({ ...old, [id]: { toolClass, viaSuggestion } }));
  };
  return (
    <FormDialog
      title={single ? `Classify ${seen.caps[0]!.name}` : "Classify tools"}
      description="Read the tool definitions before classifying. Server hints are suggestions, not evidence of safety. Owners and admins are responsible for the saved class."
      onClose={onClose}
      onSubmit={() => { if (items.length && items.length <= 500 && !stale) save.mutate(); }}
      submitLabel="Save classes"
      submitDisabled={!items.length || items.length > 500 || stale}
      busy={save.isPending}
    >
      <div className={m.stack}>
        <p>Read only observes; write changes data; destructive deletes data or causes irreversible effects. Unclassified makes no assertion.</p>
        <Button variant="secondary" disabled={stale || save.isPending} onClick={() => {
          save.reset();
          setChoices((old) => Object.fromEntries(seen.caps.map((c) => [c.id, c.suggestedClass ? { toolClass: c.suggestedClass, viaSuggestion: true } : old[c.id]!])));
        }}>Use suggestions</Button>
        {seen.caps.map((cap) => (
          <Field key={cap.id} label={`Class for ${cap.name}`} description={cap.suggestedClass ? `Suggested: ${classLabels[cap.suggestedClass].toLowerCase()} (untrusted server hints).` : "No suggestion available."}>
            <NativeSelect value={choices[cap.id]!.toolClass ?? ""} disabled={stale || save.isPending} onChange={(e) => choose(cap.id, e.target.value ? e.target.value as ToolClass : null)}>
              <option value="">Unclassified</option>
              {Object.entries(classLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </NativeSelect>
          </Field>
        ))}
        {leaves && <Alert tone="warning" title="The server will leave the catalog">Lowering a class needs a new review under your team's publishing policy. Once saved, {server.name} leaves the catalog until a platform admin approves it. Raising or clearing a class does not need a review.</Alert>}
        {items.length > 500 && <Alert tone="warning">Save at most 500 changed tools at once. Reduce the number of changes before saving.</Alert>}
        {stale && <Alert tone="warning">The server changed. Close this dialog and review the refreshed tools before trying again.</Alert>}
        <ErrorAlert error={save.error} title="Couldn't save tool classes" />
      </div>
    </FormDialog>
  );
}
