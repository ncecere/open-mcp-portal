/*
 * The parts of a server's own credential (decision 70), a repeatable editor
 * under Authentication > Static credential: each part is a header, a bearer
 * token, Basic user and password or a query parameter. A stored part shows
 * its kind, name and the end of its value and keeps the value unless a new
 * one is typed; a new part picks its kind. Values are never shown again.
 */
import { Plus, Trash2 } from "lucide-react";
import { Alert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Field } from "@/components/ui/field/field";
import { Input, NativeSelect } from "@/components/ui/input/input";
import { kindLabels, maxParts, newPart, type PartErrors, type PartForm, type PartKind, partKinds } from "./credentials";
import m from "./servers.module.css";

type Props = {
  parts: PartForm[];
  setParts: (next: PartForm[]) => void;
  errors: Record<string, PartErrors>;
  disabled?: boolean;
  /** Shown after a save was tried with no part at all. */
  noParts?: boolean;
};

const valueLabels: Record<PartKind, string> = { header: "Value", bearer: "Token", basic: "User name", query: "Value" };
const nameLabels: Partial<Record<PartKind, string>> = { header: "Header name", query: "Parameter name" };

export function CredentialFields({ parts, setParts, errors, disabled, noParts }: Props) {
  const change = (key: string, patch: Partial<PartForm>) => setParts(parts.map((p) => (p.key === key ? { ...p, ...patch } : p)));
  return (
    <div className={m.stack}>
      <p className={m.muted}>
        Sent with every request to the server. Values are stored encrypted and never shown again. At most one part can set the Authorization header (a header named
        Authorization, a bearer token or Basic).
      </p>
      {parts.map((p, i) => (
        <Part key={p.key} index={i} part={p} errors={errors[p.key] ?? {}} disabled={disabled} change={(patch) => change(p.key, patch)} remove={() => setParts(parts.filter((x) => x.key !== p.key))} />
      ))}
      {noParts && <Alert tone="danger" title="Add a part">Add at least one part, or choose None.</Alert>}
      {parts.some((p) => p.kind === "query") && (
        <Alert tone="warning" title="A query value is part of the address">
          The value goes in the URL&apos;s query (?name=value) on every request. Servers, proxies and their logs often record addresses, so use a header when the server
          accepts one. The portal never logs it and never saves it in the server&apos;s URL, and it is sent only to the address you entered it for.
        </Alert>
      )}
      {!disabled && (
        <div>
          <Button variant="secondary" size="sm" disabled={parts.length >= maxParts} onClick={() => setParts([...parts, newPart()])}>
            <Plus aria-hidden /> Add part
          </Button>
          {parts.length >= maxParts && <span className={m.muted}> At most {maxParts} parts.</span>}
        </div>
      )}
    </div>
  );
}

function Part({ index, part, errors, disabled, change, remove }: { index: number; part: PartForm; errors: PartErrors; disabled?: boolean; change: (p: Partial<PartForm>) => void; remove: () => void }) {
  const stored = part.stored;
  const nameLabel = nameLabels[part.kind];
  return (
    <fieldset className={m.part} aria-label={`Credential part ${index + 1}`} disabled={disabled}>
      <div className={m.partHead}>
        {stored ? (
          <strong>
            {kindLabels[part.kind]}
            {part.name ? `: ${part.name}` : ""}
            {part.hint ? ` (value ends in ${part.hint})` : ""}
          </strong>
        ) : (
          <Field label="Kind" className={m.partKind}>
            <NativeSelect value={part.kind} onChange={(e) => change({ kind: e.target.value as PartKind, name: "", value: "", secondary: "" })}>
              {partKinds.map((k) => (
                <option key={k} value={k}>
                  {kindLabels[k]}
                </option>
              ))}
            </NativeSelect>
          </Field>
        )}
        <Button variant="ghost" size="sm" aria-label={`Remove part ${index + 1}`} onClick={remove}>
          <Trash2 aria-hidden /> Remove
        </Button>
      </div>
      {nameLabel && !stored && (
        <Field label={nameLabel} error={errors.name}>
          <Input autoComplete="off" spellCheck={false} value={part.name} onChange={(e) => change({ name: e.target.value })} />
        </Field>
      )}
      {stored && errors.name && <p role="alert">{errors.name}</p>}
      <Field label={stored ? `Replace ${valueLabels[part.kind].toLowerCase()}` : valueLabels[part.kind]} description={stored ? "Leave empty to keep the stored value." : undefined} error={errors.value}>
        <Input type={part.kind === "basic" ? "text" : "password"} autoComplete="off" spellCheck={false} value={part.value} onChange={(e) => change({ value: e.target.value })} />
      </Field>
      {part.kind === "basic" && (
        <Field label={stored ? "Replace password" : "Password"} error={errors.secondary}>
          <Input type="password" autoComplete="new-password" value={part.secondary} onChange={(e) => change({ secondary: e.target.value })} />
        </Field>
      )}
    </fieldset>
  );
}
