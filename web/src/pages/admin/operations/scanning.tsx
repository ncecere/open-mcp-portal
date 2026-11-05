import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ApiError, api, ifMatch, unwrap, type Schemas } from "@/api/client";
import { useRevisionForm } from "@/components/templates/revision-form";
import { SettingsPage, SettingsSection } from "@/components/templates/settings-page";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Field } from "@/components/ui/field/field";
import { NativeSelect } from "@/components/ui/input/input";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import { toast } from "@/components/ui/toast/toast";
import { scanningDocs } from "@/components/servers/scan-findings";
import { useIsPlatformAdmin } from "../hooks";
import s from "../../shared.module.css";

const settingsKey = ["admin", "settings", "scanning"];
export function AdminScanningPage() {
  const settings = useQuery({ queryKey: settingsKey, queryFn: async () => unwrap(await api.GET("/v1/admin/settings/scanning")) });
  const catalog = useQuery({ queryKey: ["admin", "scanning", "rules"], queryFn: async () => unwrap(await api.GET("/v1/admin/scanning/rules")) });
  return <Stack gap={6} className={s.page}>
    <PageHeader title="Definition scanning" description="Local heuristics for stored capability definitions. Shadow mode only; nothing is blocked, redacted or rewritten." />
    <p><a href={scanningDocs}>What scanning will not catch</a></p>
    {settings.isPending && <p role="status">Loading scanning settings…</p>}
    <ErrorAlert error={settings.error} onRetry={() => void settings.refetch()} />
    {settings.data && <ScanningForm saved={settings.data} />}
    <SettingsSection title="Rule catalog" description={catalog.data ? `Read only · Ruleset ${catalog.data.rulesetVersion}` : "Read only"}>
      {catalog.isPending && <p role="status">Loading rule catalog…</p>}
      <ErrorAlert error={catalog.error} onRetry={() => void catalog.refetch()} />
      <ul>{catalog.data?.rules.map((rule) => <li key={rule.id}><strong>{rule.id}</strong> · Group: {rule.group} · Severity: {rule.severity}<p>{rule.description}</p></li>)}</ul>
    </SettingsSection>
  </Stack>;
}

function ScanningForm({ saved }: { saved: Schemas["ScanningSettings"] }) {
  const qc = useQueryClient();
  const canEdit = useIsPlatformAdmin();
  const [form, setForm, revision] = useRevisionForm({ definitionMode: saved.definitionMode }, saved.revision);
  const save = useMutation({ mutationFn: async () => unwrap(await api.PUT("/v1/admin/settings/scanning", { params: { header: ifMatch(saved.revision) }, body: form })),
    onSuccess: (data) => { qc.setQueryData(settingsKey, data); void qc.invalidateQueries({ queryKey: ["definition-findings"] }); toast.success("Scanning settings saved"); },
    onError: (error) => { if (error instanceof ApiError && (error.status === 409 || error.status === 412)) void qc.invalidateQueries({ queryKey: settingsKey }); } });
  const conflict = save.error instanceof ApiError && save.error.status === 409;
  return <SettingsPage dirty={form.definitionMode !== saved.definitionMode} canEdit={canEdit} revision={revision} saving={save.isPending} error={conflict ? undefined : save.error} onSave={() => save.mutate()} onDiscard={() => setForm({ definitionMode: saved.definitionMode })}>
    <SettingsSection title="Scanning mode" description="Off disables scanning. Shadow records findings for human review without changing definitions or calls.">
      {conflict && <Alert tone="warning">Scanning settings changed elsewhere. Your changes weren't saved. Review the latest settings before saving again.</Alert>}
      <Field label="Definition scanning mode"><NativeSelect disabled={!canEdit} value={form.definitionMode} onChange={(e) => setForm({ definitionMode: e.target.value as "off" | "shadow" })}><option value="off">Off</option><option value="shadow">Shadow</option></NativeSelect></Field>
    </SettingsSection>
  </SettingsPage>;
}
