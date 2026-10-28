import { Field } from "@/components/ui/field/field";
import { Input, NativeSelect, Textarea } from "@/components/ui/input/input";
import type { Schemas } from "../../api/client";
import g from "./gateways.module.css";

export type Policy = Schemas["GatewayToolCuration"];
export type Definition = Record<string, unknown>;
export type Choice = { mode: "" | "fixed" | "allowed"; text: string };
export type Choices = Record<string, Choice>;
export const object = (v: unknown): Definition => v && typeof v === "object" && !Array.isArray(v) ? v as Definition : {};
const annotations = ["title", "description", "default", "examples", "$comment", "deprecated", "readOnly", "writeOnly", "x-mcp-header"];
const rootKeys = ["type", "properties", "required", "additionalProperties", "$schema", ...annotations];
export const canConstrain = (schema: Definition) => schema.type === "object" && Object.keys(schema).every((k) => rootKeys.includes(k)) && !!schema.properties && (!Object.hasOwn(schema, "additionalProperties") || typeof schema.additionalProperties === "boolean") && Object.values(object(schema.properties)).every((p) => supported(object(p)));
const keywords = ["type", "enum", "const", "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "multipleOf", "minLength", "maxLength", "pattern", "minItems", "maxItems", "uniqueItems", "items", "minProperties", "maxProperties", "properties", "required", "additionalProperties", ...annotations];
const supported = (s: Definition, depth = 0): boolean => depth <= 16 && Object.entries(s).every(([k, v]) => keywords.includes(k) && (k === "properties" ? Object.values(object(v)).every((p) => supported(object(p), depth + 1)) : ["items", "additionalProperties"].includes(k) && typeof v === "object" ? supported(object(v), depth + 1) : true));

export function choicesOf(policy: Policy | null | undefined, properties: Definition): Choices {
  return Object.fromEntries(Object.entries(policy?.constraints ?? {}).map(([name, c]) => {
    const fixed = Object.hasOwn(c, "fixed");
    return [name, { mode: fixed ? "fixed" : "allowed", text: fixed && object(properties[name]).type === "string" && typeof c.fixed === "string" ? c.fixed : JSON.stringify(fixed ? c.fixed : c.allowed) }];
  }));
}
function parse(text: string, prop: Definition, mode: Choice["mode"]): unknown {
  if (mode === "fixed" && prop.type === "string") return text;
  const v: unknown = JSON.parse(text);
  const safe = (v: unknown): boolean => typeof v === "number" ? Number.isFinite(v) && (!Number.isInteger(v) || Number.isSafeInteger(v)) : Array.isArray(v) ? v.every(safe) : v && typeof v === "object" ? Object.values(v).every(safe) : true;
  if (!safe(v)) throw new Error("Use the API for numbers outside JavaScript's exact integer range.");
  return v;
}
export function policyOf(name: string, description: string, choices: Choices, properties: Definition): Policy {
  const constraints: NonNullable<Policy["constraints"]> = {};
  for (const [arg, choice] of Object.entries(choices)) {
    if (!choice.mode) continue;
    let v: unknown;
    try { v = parse(choice.text, object(properties[arg]), choice.mode); } catch { throw new Error(`Enter valid JSON for ${arg} (large integers require the API).`); }
    if (choice.mode === "allowed") {
      if (!Array.isArray(v) || !v.length || v.length > 100) throw new Error(`Allow for ${arg} needs a JSON array of 1–100 values.`);
      constraints[arg] = { allowed: v };
    } else constraints[arg] = { fixed: v };
  }
  return { nameOverride: name.trim() || null, descriptionOverride: description, constraints };
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => [k, canonical(v)]));
  return value;
}

export function previewOf(original: Definition, policy: Policy, fallbackName: string): Definition {
  const schema = { ...object(original.inputSchema) };
  const properties = { ...object(schema.properties) };
  let required = Array.isArray(schema.required) ? [...schema.required] : undefined;
  for (const [arg, c] of Object.entries(policy.constraints ?? {})) {
    if (Object.hasOwn(c, "fixed")) { delete properties[arg]; required = required?.filter((v) => v !== arg); }
    else {
      const prop = object(properties[arg]);
      const originalEnum = Array.isArray(prop.enum) ? prop.enum : undefined;
      const values = c.allowed?.filter((v) => !originalEnum || originalEnum.some((x) => JSON.stringify(canonical(x)) === JSON.stringify(canonical(v))));
      properties[arg] = { ...prop, enum: values };
    }
  }
  return { ...original, name: policy.nameOverride || fallbackName, description: policy.descriptionOverride ?? original.description, inputSchema: { ...schema, properties, ...(required ? { required } : {}) } };
}

export function ArgumentFields({ schema, choices, onChange, disabled }: { schema: Definition; choices: Choices; onChange: (next: Choices) => void; disabled: boolean }) {
  if (!canConstrain(schema)) return <p className={g.note}>This schema cannot safely be narrowed. You can still rename or re-describe this tool.</p>;
  return <div className={g.stack}>
    {Object.entries({ ...Object.fromEntries(Object.keys(choices).map((name) => [name, {}])), ...object(schema.properties) }).map(([name, raw]) => {
      const prop = object(raw);
      const missing = !Object.hasOwn(object(schema.properties), name);
      const choice = choices[name] ?? { mode: "", text: "" };
      const set = (next: Partial<Choice>) => onChange({ ...choices, [name]: { ...choice, ...next } });
      const json = choice.mode === "allowed" || !["string", "number", "integer", "boolean"].includes(String(prop.type));
      return <div key={name} className={g.tight}>
        <Field label={`Policy for ${name}`} description={missing ? "This argument was removed. Choose Unrestricted to remove its old constraint before resaving." : !supported(prop) ? "Unsupported property schema; constraints are unavailable." : String(prop.description ?? prop.type ?? "JSON value")}>
          <NativeSelect disabled={disabled || !supported(prop)} value={choice.mode} onChange={(e) => set({ mode: e.target.value as Choice["mode"], text: e.target.value === "allowed" ? "[]" : prop.type === "boolean" ? "true" : "" })}>
            <option value="">Unrestricted</option><option disabled={missing} value="fixed">Fix</option><option disabled={missing} value="allowed">Allow</option>
          </NativeSelect>
        </Field>
        {choice.mode && <Field label={`${choice.mode === "fixed" ? "Fixed value" : "Allowed values"} for ${name}`} description={json ? "JSON value; Allow needs a JSON array. The server checks the original schema." : undefined}>
          {json ? <Textarea disabled={disabled} value={choice.text} onChange={(e) => set({ text: e.target.value })} /> : prop.type === "boolean" ? <NativeSelect disabled={disabled} value={choice.text} onChange={(e) => set({ text: e.target.value })}><option value="true">true</option><option value="false">false</option></NativeSelect> : <Input disabled={disabled} type={prop.type === "number" || prop.type === "integer" ? "number" : "text"} step={prop.type === "integer" ? "1" : "any"} value={choice.text} onChange={(e) => set({ text: e.target.value })} />}
        </Field>}
      </div>;
    })}
  </div>;
}
