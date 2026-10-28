import { useState } from "react";
import type { Schemas } from "../api/client";
import { Badge } from "@/components/ui/badge/badge";
import { Checkbox } from "@/components/ui/checkbox/checkbox";
import { Field } from "@/components/ui/field/field";
import { Inline, Stack } from "@/components/ui/layout/layout";
import { RadioGroup } from "@/components/ui/radio-group/radio-group";
import { TagInput } from "@/components/ui/tag-input/tag-input";
import styles from "./tool-scope.module.css";

export type ToolScope = Schemas["ToolScope"] | null;
const classes = ["read", "write", "destructive"] as const;
const labels = { read: "Read", write: "Write", destructive: "Destructive" };
export const scopeInheritance = "Everything means no restriction at this layer, not extra access. Owner, gateway, account and key limits still apply together; a tool must pass every applicable layer. Prompts and resources are unaffected.";
/** A stable form value, including when an API response omits empty arrays. */
export function scopeFormValue(scope: ToolScope | undefined): ToolScope {
  return scope == null ? null : { classes: classes.filter((c) => scope.classes?.includes(c)), tools: [...new Set(scope.tools ?? [])].sort() };
}
export function scopeProblem(scope: ToolScope): string | undefined {
  if ((scope?.tools?.length ?? 0) > 500) return "Use at most 500 exact tool names.";
  if (scope?.tools?.some((t) => !t.length || new TextEncoder().encode(t).length > 1100 || /[\p{Cc}*?\[\]{}]/u.test(t))) return "Use exact exposed names: 1–1100 UTF-8 bytes, without control characters or wildcard operators. No wildcards.";
  return undefined;
}

export function ScopeBadges({ scope }: { scope?: ToolScope }) {
  const empty = scope != null && !scope.classes?.length && !scope.tools?.length;
  return <Inline gap={2}>
    {scope == null ? <Badge>Everything</Badge> : empty ? <Badge>No tools</Badge> : <>
      {classes.filter((c) => scope.classes?.includes(c)).map((c) => <Badge key={c}>{labels[c]}</Badge>)}
      {scope.tools?.map((t) => <Badge key={t} className={styles.name} title={t}><span className={styles.nameText}>{t}</span></Badge>)}
      <span>Unclassified tools: {scope.tools?.length ? "exact names only" : "excluded"}</span>
    </>}
  </Inline>;
}

type Props = {
  value: ToolScope;
  onChange: (scope: ToolScope) => void;
  disabled?: boolean;
  /** OAuth may only remove requested classes; exact names cannot be added. */
  ceiling?: ToolScope;
  allowNames?: boolean;
};
export function ScopeEditor({ value, onChange, disabled = false, ceiling = null, allowNames = true }: Props) {
  // Keep Custom visible even when its value happens to equal the Read only preset.
  const [custom, setCustom] = useState(false);
  const preset = value === null ? "everything" : !custom && value.classes?.length === 1 && value.classes[0] === "read" && !value.tools?.length ? "read" : "custom";
  const allowed = (c: typeof classes[number]) => ceiling === null || !!ceiling.classes?.includes(c);
  return <Stack gap={3}>
    <RadioGroup legend="Tool scope" value={preset} disabled={disabled} onValueChange={(p) => {
      setCustom(p === "custom");
      onChange(p === "everything" ? null : p === "read" ? { classes: ["read"], tools: [] } : value ?? { classes: [], tools: [] });
    }} options={[
      { value: "everything", label: "Everything", disabled: ceiling !== null, description: "No restriction at this layer, including unclassified tools." },
      { value: "read", label: "Read only", disabled: !allowed("read"), description: "Only tools classified as read; not write, destructive or unclassified tools." },
      { value: "custom", label: "Custom", description: allowNames ? "Choose independent classes or exact exposed names." : "Choose from the requested classes." },
    ]} />
    {preset === "custom" && <>
      {classes.map((c) => <Checkbox key={c} label={labels[c]} disabled={disabled || !allowed(c)} checked={!!value?.classes?.includes(c)} onCheckedChange={(checked) => {
        setCustom(true);
        onChange({ ...value, classes: classes.filter((candidate) => candidate === c ? checked : value?.classes?.includes(candidate)) });
      }} />)}
      {allowNames && <Field label="Exact tool names" description="Class OR exact exposed name. Names are case-sensitive, may refer to future tools, and cannot contain wildcards. Up to 500 names, each 1–1100 UTF-8 bytes; no control characters. Renamed and future tools are allowed; no server prefix is required." error={scopeProblem(value)}>
        <TagInput value={value?.tools ?? []} onValueChange={(tools) => onChange({ ...value, tools })} normalize={(t) => t} maxTags={500} maxTagLength={1101} disabled={disabled} noun={{ one: "tool name", other: "tool names" }} />
      </Field>}
    </>}
    <ScopeBadges scope={value} />
    {value !== null && !value.classes?.length && !value.tools?.length && <p>No tools. Prompts and resources are unaffected.</p>}
    {value !== null && <p>Classes are independent, not a hierarchy. Even all three classes exclude unclassified tools unless an exact name matches.</p>}
    <p>{scopeInheritance}</p>
  </Stack>;
}
