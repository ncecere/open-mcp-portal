import { ArrowDown, ArrowUp, Plus, Trash2 } from "lucide-react";
import { Alert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Field } from "@/components/ui/field/field";
import { Input } from "@/components/ui/input/input";
import { Switch } from "@/components/ui/switch/switch";
import { SettingsSection } from "../templates/settings-page";
import { CredentialFields } from "./credential-fields";
import { endpointProblems, newEndpoint, type EndpointForm } from "./endpoints";
import type { McpServer } from "./labels";
import m from "./servers.module.css";

type Props = { value: EndpointForm[]; onChange: (next: EndpointForm[]) => void; server: McpServer; primaryUrl: string; mode: string; blocked: boolean; disabled: boolean; submitted: boolean; dev: boolean };

export function EndpointFields({ value, onChange, server, primaryUrl, mode, blocked, disabled, submitted, dev }: Props) {
  const errors = submitted ? endpointProblems(value, { ...server, url: primaryUrl }, mode, dev, blocked) : {};
  const change = (key: string, patch: Partial<EndpointForm>) => onChange(value.map((e) => e.key === key ? { ...e, ...patch } : e));
  const move = (index: number, offset: number) => { const next = [...value]; const a = next[index], b = next[index + offset]; if (!a || !b) return; next[index] = b; next[index + offset] = a; onChange(next); };
  return (
    <SettingsSection title="Additional endpoints" description="Only this team's owners and admins configure extra replicas. The primary URL above stays canonical. Endpoint changes need catalog review when published.">
      <Alert tone="info" title="A fallback is not another approval">
        Governed and NoReplay calls always use the primary, even if it cannot be reached. Ordinary calls share one original deadline and at most three forwarding iterations, not a retry budget per replica. Only matching trusted capability definitions may be used.
      </Alert>
      <p className={m.muted}>At most two ordered extras. Each static endpoint needs its own explicitly entered credential; primary values are never inherited. A changed origin requires every value again. Disabling retains the encrypted credential and still requires a supported mode.</p>
      {blocked && <Alert tone={value.length > 0 ? "danger" : "info"} title="This configuration cannot use extra endpoints">Only None or Static credential without a user-authorization requirement or TLS settings is supported. Remove all extras before choosing OAuth, per-person/provider credentials, the portal's OAuth client or TLS. Save removal of existing TLS before adding replicas.</Alert>}
      {value.length === 0 && <p className={m.muted}>No additional endpoints. Calls use the primary URL.</p>}
      {value.map((e, i) => (
        <fieldset key={e.key} className={m.part} aria-label={`Additional endpoint ${i + 1}`}>
          <div className={m.partHead}>
            <strong>Additional endpoint {i + 1}</strong>
            <Button variant="ghost" size="sm" disabled={disabled || i === 0} aria-label={`Move endpoint ${i + 1} up`} onClick={() => move(i, -1)}><ArrowUp aria-hidden /> Up</Button>
            <Button variant="ghost" size="sm" disabled={disabled || i === value.length - 1} aria-label={`Move endpoint ${i + 1} down`} onClick={() => move(i, 1)}><ArrowDown aria-hidden /> Down</Button>
            <Button variant="ghost" size="sm" disabled={disabled} aria-label={`Remove endpoint ${i + 1}`} onClick={() => onChange(value.filter((x) => x.key !== e.key))}><Trash2 aria-hidden /> Remove</Button>
          </div>
          <Field label={`Additional endpoint ${i + 1} URL`} error={errors[e.key]?.url} description="This actual URL is the outbound identity audience. Every destination must pass the same address policy.">
            <Input type="url" autoComplete="off" spellCheck={false} maxLength={500} disabled={disabled} value={e.url} onChange={(event) => change(e.key, { url: event.target.value })} />
          </Field>
          <Switch label={`Enable additional endpoint ${i + 1}`} checked={e.enabled} disabled={disabled} onCheckedChange={(enabled) => change(e.key, { enabled })} />
          {mode === "static_header" && <CredentialFields parts={e.parts} setParts={(parts) => change(e.key, { parts })} errors={errors[e.key]?.parts ?? {}} noParts={submitted && errors[e.key]?.noParts} disabled={disabled} />}
        </fieldset>
      ))}
      {!disabled && <div className={m.actions}>
        <Button variant="secondary" size="sm" disabled={blocked || value.length >= 2} onClick={() => onChange([...value, newEndpoint()])}><Plus aria-hidden /> Add endpoint</Button>
        {value.length > 0 && <Button variant="ghost" size="sm" onClick={() => onChange([])}>Remove all endpoints</Button>}
      </div>}
    </SettingsSection>
  );
}
