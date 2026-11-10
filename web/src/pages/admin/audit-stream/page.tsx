import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ConfirmMutationDialog } from "@/components/confirm-dialog";
import { SecretDialog } from "@/components/notifications/destinations/secret-dialog";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { Inline, Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import { Table, Td, Tr } from "@/components/ui/table/table";
import { useIsPlatformAdmin } from "../hooks";
import { Time } from "@/components/ui/time/time";
import { getStatus, sinkAction, statusKey, verificationDocs, type Action, type Sink } from "./api";
import { SinkForm } from "./form";
import { StreamStatus } from "./status";
import { Consumers } from "./consumers";
import s from "../../shared.module.css";

const actionCopy = {
  "rotate-secret": ["Rotate secret", "The previous secret remains valid for 24 hours. Copy the new secret when it appears; you will not see it again."],
  resume: [
    "Resume sink",
    "Resume declares a signed gap for unavailable records. Preserve previous evidence. The receiver must locally approve the discontinuity and its trusted predecessor; resuming here does not approve a new trust anchor. Delivery continues after the receiver acknowledges the gap.",
  ],
  acknowledge: [
    "Acknowledge oversized sequence",
    "You must first retrieve and preserve the complete row using /v1/admin/audit/entries/{seq}/full (the entries API). Acknowledging releases this sink's retention hold for exactly this sequence; another person's fetch does not release it.",
  ],
  delete: ["Delete sink", "This stops delivery and releases this sink's retention hold. This cannot be undone."],
  test: ["Test sink", "Send a signed audit.test without audit records. This does not move the cursor."],
};
export function AdminAuditStreamPage() {
  const canEdit = useIsPlatformAdmin();
  const qc = useQueryClient();
  const status = useQuery({ queryKey: statusKey, queryFn: getStatus, refetchInterval: 60_000 });
  const [form, setForm] = useState<Sink | "new" | null>(null);
  const [secret, setSecret] = useState<{ value: string; rotated: boolean } | null>(null);
  const [target, setTarget] = useState<{ sink: Sink; action: Action } | null>(null);
  const [result, setResult] = useState<string | null>(null);
  const action = useMutation({ mutationFn: async ({ sink, action }: { sink: Sink; action: Action }) => {
    const out = await sinkAction(sink, action);
    if (typeof out.secret === "string") setSecret({ value: out.secret, rotated: true });
    return { error_class: out.error_class };
  }, onSuccess: (out, variables) => {
    if (variables.action === "test") setResult(`${variables.sink.name}: ${out.error_class ? `Test failed: ${out.error_class}` : "Test succeeded"}`);
    setTarget(null); action.reset(); void qc.invalidateQueries({ queryKey: statusKey });
  }, onError: () => { void qc.invalidateQueries({ queryKey: statusKey }); } });
  const choose = (sink: Sink, a: Action) => { action.reset(); setResult(null); setTarget({ sink, action: a }); };
  return <Stack gap={6} className={s.page}>
    <PageHeader title="Audit stream" description="Tamper-evident with pinned keys and stream id. Independently preserve and verify evidence at the receiver." />
    <a href={verificationDocs}>Receiver verification and key enrollment</a>
    {!canEdit && <Alert tone="info">Read only. Platform admins manage sinks and pull consumers.</Alert>}
    {status.isPending && <p role="status">Loading audit stream…</p>}
    <ErrorAlert error={status.error} onRetry={() => void status.refetch()} />
    {status.data && <>
      <StreamStatus data={status.data} />
      <Card title="Sinks" actions={canEdit ? <Button onClick={() => setForm("new")}>Create sink</Button> : undefined}>
        <Stack gap={4}>
          <p>Required sinks hold retention at their cursor even while disabled. Optional sinks do not hold retention and can expire.</p>
          {result && <p role="status">{result}</p>}
          <Table stack caption="Audit sinks"
            columns={[
              "Name", "Kind", "Profile", "Required", "Host hint", "State", "Lag (records)", "Last success", "Last error class", "Consecutive failures",
              "Retention effect", "Held oversized sequence", ...(canEdit ? ["Actions"] : []),
            ]}
            empty={!status.data.sinks.length ? "No sinks registered." : undefined}>
            {status.data.sinks.map(sink => <Tr key={sink.id}>
              <Td>{sink.name}</Td><Td>{sink.kind}</Td><Td>{sink.profile}</Td><Td>{sink.required ? "Yes" : "No"}</Td><Td>{sink.url_hint}</Td>
              <Td>{sink.state} · {sink.enabled ? "enabled" : "disabled"}</Td><Td>{sink.lag}</Td><Td>{sink.last_ok_at ? <Time value={sink.last_ok_at} /> : "Never"}</Td>
              <Td>{sink.last_error_class || "None"}</Td><Td>{sink.consecutive_failures}</Td>
              <Td>{!sink.required
                ? "Not holding — optional sinks do not cap retention."
                : sink.enabled
                  ? "Holding — retention waits for this cursor."
                  : "Holding while disabled — disabling delivery does not release retention."}</Td>
              <Td>{sink.held_oversized_seq ?? "None"}</Td>
              {canEdit && <Td><Inline gap={2}>
                <Button size="sm" onClick={() => setForm(sink)}>Edit</Button>
                <Button size="sm" onClick={() => choose(sink, "test")}>Test</Button>
                <Button size="sm" onClick={() => choose(sink, "rotate-secret")}>Rotate secret</Button>
                {sink.state === "range_expired" && <Button size="sm" onClick={() => choose(sink, "resume")}>Resume</Button>}
                {sink.held_oversized_seq != null && <Button size="sm" onClick={() => choose(sink, "acknowledge")}>Acknowledge oversized</Button>}
                <Button size="sm" variant="danger" onClick={() => choose(sink, "delete")}>Delete</Button>
              </Inline></Td>}
            </Tr>)}
          </Table>
        </Stack>
      </Card>
      <Consumers items={status.data.consumers} canEdit={canEdit} />
    </>}
    {form && <SinkForm sink={form === "new" ? undefined : status.data?.sinks.find(s => s.id === form.id) ?? form} onClose={() => setForm(null)} onSecret={value => { setForm(null); setSecret({ value, rotated: false }); }} />}
    {secret && <SecretDialog title="Audit sink signing secret" secret={secret.value} previousUntil={secret.rotated ? new Date(Date.now() + 24 * 3600_000).toISOString() : undefined} onClose={() => setSecret(null)} />}
    {target && <ConfirmMutationDialog target={target} onClose={() => setTarget(null)} mutation={action} onConfirm={v => action.mutate(v)}
      title={`${actionCopy[target.action][0]}: ${target.sink.name}`} description={actionCopy[target.action][1]} confirmLabel={actionCopy[target.action][0]} />}
  </Stack>;
}
