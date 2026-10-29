import { ApiError } from "../../api/client";
import { Field } from "@/components/ui/field/field";
import { Input } from "@/components/ui/input/input";
import { SettingsSection } from "../templates/settings-page";
import type { McpServer } from "./labels";

export type ProtectionForm = { rate: string; concurrent: string };
export const protectionFormOf = (server: McpServer): ProtectionForm => ({ rate: server.rateLimitPerMinute == null ? "" : String(server.rateLimitPerMinute), concurrent: server.maxConcurrent == null ? "" : String(server.maxConcurrent) });

function problem(text: string, max: number) {
  if (!text.trim()) return undefined;
  const n = Number(text);
  return !/^\d+$/.test(text.trim()) || !Number.isSafeInteger(n) || n < 1 || n > max ? `Use a whole number from 1 to ${max.toLocaleString("en-US")}, or leave blank.` : undefined;
}
export function protectionProblems(form: ProtectionForm) {
  const out: Partial<Record<keyof ProtectionForm, string>> = {};
  const rate = problem(form.rate, 1_000_000), concurrent = problem(form.concurrent, 10_000);
  if (rate) out.rate = rate;
  if (concurrent) out.concurrent = concurrent;
  return out;
}
export function protectionBody(form: ProtectionForm, saved: ProtectionForm) {
  return {
    ...(form.rate !== saved.rate ? { rateLimitPerMinute: form.rate.trim() ? Number(form.rate) : null } : {}),
    ...(form.concurrent !== saved.concurrent ? { maxConcurrent: form.concurrent.trim() ? Number(form.concurrent) : null } : {}),
  };
}

export function ServerProtectionFields({ value, onChange, disabled, submitted, error }: { value: ProtectionForm; onChange: (v: ProtectionForm) => void; disabled: boolean; submitted: boolean; error: unknown }) {
  const errors = submitted ? protectionProblems(value) : {};
  if (error instanceof ApiError && error.code === "invalid_limit" && error.details?.key === "server_per_minute") errors.rate = error.message;
  if (error instanceof ApiError && error.code === "invalid_concurrency") errors.concurrent = error.message;
  return (
    <SettingsSection title="Upstream protection" description="Only this team's owners and admins change these limits. They do not grant access or change credential scopes. Finish rolling out supported serving replicas before relying on them.">
      <Field label="Forwarded attempts per minute" labelHint="Optional" description="Blank inherits the owning team/platform default, capped by the platform ceiling. Automatic retries count again; other servers have separate counters." error={errors.rate}>
        <Input inputMode="numeric" disabled={disabled} value={value.rate} placeholder="Inherit" onChange={(e) => onChange({ ...value, rate: e.target.value })} />
      </Field>
      <Field label="Concurrent forwarded operations" labelHint="Optional" description="Fail-fast, per server and replica; blank is unlimited. The fleet cap grows with replicas. No queue or distributed lease." error={errors.concurrent}>
        <Input inputMode="numeric" disabled={disabled} value={value.concurrent} placeholder="Unlimited" onChange={(e) => onChange({ ...value, concurrent: e.target.value })} />
      </Field>
    </SettingsSection>
  );
}
