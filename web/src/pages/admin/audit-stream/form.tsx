import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ApiError, api, ifMatch, type Schemas } from "@/api/client";
import { FormDialog } from "@/components/form-dialog";
import { useRevisionForm } from "@/components/templates/revision-form";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Checkbox } from "@/components/ui/checkbox/checkbox";
import { Field } from "@/components/ui/field/field";
import { Input, NativeSelect } from "@/components/ui/input/input";
import { unwrapAudit, type Sink, statusKey } from "./api";

const formOf = (s?: Sink) => ({ name: s?.name ?? "", url: "", profile: s?.profile ?? "summary", required: s?.required ?? false, enabled: s?.enabled ?? true, batch_max_records: s?.batch_max_records ?? 100 });
export function SinkForm({ sink, onClose, onSecret }: { sink?: Sink; onClose: () => void; onSecret: (secret: string) => void }) {
  const qc = useQueryClient();
  const [form, setForm] = useRevisionForm(formOf(sink), sink?.revision ?? 0);
  const save = useMutation({ mutationFn: async () => {
    const body: Schemas["AuditSinkRequest"] = { ...form, name: form.name.trim(), url: form.url.trim() || undefined };
    const out = sink
      ? unwrapAudit(await api.PUT("/v1/admin/settings/audit-sinks/{id}", { params: { path: { id: sink.id }, header: ifMatch(sink.revision) }, body }))
      : unwrapAudit(await api.POST("/v1/admin/settings/audit-sinks", { body }));
    if (typeof out.secret === "string") onSecret(out.secret); else onClose();
  }, onSuccess: () => {
    // Never retain secret-bearing responses in the query or mutation cache.
    save.reset();
    void qc.invalidateQueries({ queryKey: statusKey });
  }, onError: (e) => { if (e instanceof ApiError && e.status === 409) void qc.invalidateQueries({ queryKey: statusKey }); } });
  return <FormDialog title={sink ? `Edit ${sink.name}` : "Create audit sink"} description="URLs are write-only. Leaving the URL empty on edit keeps the existing destination."
    onClose={onClose} onSubmit={() => save.mutate()} busy={save.isPending} closeDisabled={save.isPending} submitLabel="Save sink">
    {save.error instanceof ApiError && save.error.status === 409 && <Alert tone="warning">Your changes weren't saved. Your edits are still here. Review the latest revision before saving again.</Alert>}
    <ErrorAlert error={save.error} />
    <Field label="Name"><Input required maxLength={100} value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} /></Field>
    <Field label="URL" description={sink ? `Current host: ${sink.url_hint}` : "HTTPS receiver destination"}>
      <Input type="url" required={!sink} maxLength={2048} value={form.url} onChange={e => setForm({ ...form, url: e.target.value })} />
    </Field>
    <Field label="Profile">
      <NativeSelect value={form.profile} onChange={e => setForm({ ...form, profile: e.target.value as "summary" | "full" })}>
        <option value="summary">Summary</option>
        <option value="full">Full</option>
      </NativeSelect>
    </Field>
    <Checkbox label="Required" checked={form.required} onCheckedChange={v => setForm({ ...form, required: v })}
      description="A required sink holds audit retention, even while disabled. An outage can grow database usage without bound. Making it optional or deleting it releases the hold." />
    <Checkbox label="Enabled" checked={form.enabled} onCheckedChange={v => setForm({ ...form, enabled: v })} />
    <Field label="Batch size"><Input type="number" min={1} max={1000} required value={form.batch_max_records} onChange={e => setForm({ ...form, batch_max_records: Number(e.target.value) })} /></Field>
  </FormDialog>;
}
