import { useState } from "react";
import type { Schemas } from "../api/client";
import { Badge } from "@/components/ui/badge/badge";
import { Checkbox } from "@/components/ui/checkbox/checkbox";
import { Inline, Stack } from "@/components/ui/layout/layout";
import { RadioGroup } from "@/components/ui/radio-group/radio-group";
import { literalNameProblem, ScopeNames } from "./scope-names";
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
  for (const name of scope?.tools ?? []) {
    const problem = literalNameProblem(name);
    if (problem) return problem;
  }
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
  /** Parent submissions must also refuse a pending or rejected literal-name draft. */
  onProblemChange?: (problem: string | undefined) => void;
};
export function ScopeEditor({ value, onChange, disabled = false, ceiling = null, allowNames = true, onProblemChange }: Props) {
  // Keep Custom visible even when its value happens to equal the Read only preset.
  const [custom, setCustom] = useState(false);
  const preset = value === null ? "everything" : !custom && value.classes?.length === 1 && value.classes[0] === "read" && !value.tools?.length ? "read" : "custom";
  const allowed = (c: typeof classes[number]) => ceiling === null || !!ceiling.classes?.includes(c);
  return <Stack gap={3}>
    <RadioGroup legend="Tool scope" value={preset} disabled={disabled} onValueChange={(p) => {
      onProblemChange?.(undefined);
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
      {allowNames && <ScopeNames names={value?.tools ?? []} onChange={(tools) => { setCustom(true); onChange({ ...value, tools }); }} onProblemChange={(problem) => { if (problem) setCustom(true); onProblemChange?.(problem); }} disabled={disabled} error={scopeProblem(value)} />}
    </>}
    <ScopeBadges scope={value} />
    {value !== null && !value.classes?.length && !value.tools?.length && <p>No tools. Prompts and resources are unaffected.</p>}
    {value !== null && <p>Classes are independent, not a hierarchy. Even all three classes exclude unclassified tools unless an exact name matches.</p>}
    <p>{scopeInheritance}</p>
  </Stack>;
}
