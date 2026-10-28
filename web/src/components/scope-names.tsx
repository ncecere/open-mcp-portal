import { useState } from "react";
import { Button } from "@/components/ui/button/button";
import { Field } from "@/components/ui/field/field";
import { Input } from "@/components/ui/input/input";
import { Inline, Stack } from "@/components/ui/layout/layout";
import styles from "./tool-scope.module.css";

export const literalNameProblem = (name: string): string | undefined =>
  !name.length || new TextEncoder().encode(name).length > 1100 || /[\p{Cc}*?\[\]{}]/u.test(name)
    ? "Use exact exposed names: 1–1100 UTF-8 bytes, without control characters or wildcard operators. No wildcards."
    : undefined;

/** Unlike a tag input, one draft is one literal permission, never a delimited list. */
export function ScopeNames({ names, onChange, onProblemChange, disabled, error }: {
  names: string[];
  onChange: (names: string[]) => void;
  onProblemChange?: (problem: string | undefined) => void;
  disabled: boolean;
  error?: string;
}) {
  const [draft, setDraft] = useState("");
  const [rejected, setRejected] = useState<string>();
  const problem = (text: string, refusal?: string) => refusal ?? (text.length ? literalNameProblem(text) ?? "Add the tool name or clear the draft before saving." : undefined);
  function update(text: string, refusal?: string) {
    setDraft(text);
    setRejected(refusal);
    onProblemChange?.(problem(text, refusal));
  }
  function add() {
    if (disabled || (!draft.length && !rejected)) return;
    const refusal = rejected ?? literalNameProblem(draft) ?? (names.length >= 500 && !names.includes(draft) ? "Use at most 500 exact tool names." : undefined);
    if (refusal) { update(draft, refusal); return; }
    if (!names.includes(draft)) onChange([...names, draft]);
    update("");
  }
  return <Stack gap={2}>
    <Field label="Exact tool names" description="Add one literal name at a time. Commas, spaces and case are preserved, not separators. Up to 500 names, each 1–1100 UTF-8 bytes; no control characters or wildcards. Renamed and future tools are allowed; no server prefix is required. Class OR exact exposed name." error={error ?? problem(draft, rejected)}>
      <Input value={draft} disabled={disabled} autoComplete="off" spellCheck={false}
        onChange={(e) => update(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && !e.nativeEvent.isComposing) { e.preventDefault(); add(); }
        }}
        onPaste={(e) => {
          e.preventDefault();
          const raw = e.clipboardData.getData("text");
          // Read raw clipboard data before a text input can silently strip newlines or controls.
          if (/[\p{Cc}]/u.test(raw)) { update(draft, "Pasted names cannot contain control characters, including tabs or newlines. Nothing was added."); return; }
          const start = e.currentTarget.selectionStart ?? draft.length;
          const end = e.currentTarget.selectionEnd ?? start;
          update(draft.slice(0, start) + raw + draft.slice(end));
        }} />
    </Field>
    <Inline gap={2}>
      <Button type="button" variant="secondary" disabled={disabled || !draft.length || !!rejected || !!literalNameProblem(draft)} onClick={add}>Add tool name</Button>
      {(draft.length > 0 || rejected) && <Button type="button" variant="ghost" disabled={disabled} onClick={() => update("")}>Clear name draft</Button>}
    </Inline>
    {names.length > 0 && <ul aria-label="Exact tool names">
      {names.map((name) => <li key={name}>
        <Inline gap={2}>
          <span className={styles.literalName}>{name}</span>
          <Button type="button" variant="ghost" disabled={disabled} aria-label={`Remove tool name ${name}`} onClick={() => onChange(names.filter((n) => n !== name))}>Remove</Button>
        </Inline>
      </li>)}
    </ul>}
  </Stack>;
}
