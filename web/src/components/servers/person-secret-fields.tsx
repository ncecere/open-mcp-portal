/*
 * The Authentication fields of a server where each person enters their own
 * key (decision 72): how it travels (a header, a bearer token or a query
 * parameter), the header or parameter's name, an optional prefix, and the
 * words the page where people paste it uses (what the key is called, where to
 * find it). Nobody's key is ever shown here; the card on the Overview counts
 * who has entered one.
 */
import { Alert } from "@/components/ui/alert/alert";
import { Field } from "@/components/ui/field/field";
import { Input, Textarea } from "@/components/ui/input/input";
import { RadioGroup, type RadioOption } from "@/components/ui/radio-group/radio-group";
import { type Placement, placementHelp, placementLabels, type SecretErrors, type SecretForm } from "./person-secret";
import m from "./servers.module.css";

type Props = {
  value: SecretForm;
  onChange: (next: SecretForm) => void;
  errors: SecretErrors;
  disabled?: boolean;
};

const placements: Placement[] = ["header", "bearer", "query"];

export function PersonSecretFields({ value, onChange, errors, disabled }: Props) {
  const options: RadioOption<Placement>[] = placements.map((p) => ({ value: p, label: placementLabels[p], description: placementHelp[p] }));
  const named = value.placement !== "bearer";
  return (
    <div className={m.stack}>
      <RadioGroup<Placement>
        legend="How the key is sent"
        options={options}
        value={value.placement}
        onValueChange={(placement) => onChange({ ...value, placement, ...(placement === "bearer" ? { name: "", prefix: "" } : {}) })}
        disabled={disabled}
      />
      {value.placement === "query" && (
        <Alert tone="warning" title="A query value is part of the address">
          Servers, proxies and their logs often record addresses, and people&apos;s keys would be in them. Use a header when the server accepts one. The portal never logs
          the key and never saves it in the server&apos;s URL.
        </Alert>
      )}
      {named && (
        <>
          <Field label={value.placement === "header" ? "Header name" : "Parameter name"} error={errors.name} description={value.placement === "header" ? "For example X-API-Key, or Authorization with a prefix." : undefined}>
            <Input autoComplete="off" spellCheck={false} disabled={disabled} value={value.name} onChange={(e) => onChange({ ...value, name: e.target.value })} />
          </Field>
          <Field label="Prefix" labelHint="Optional" error={errors.prefix} description={'Sent before the key, for example "Token " (with its space).'}>
            <Input autoComplete="off" spellCheck={false} disabled={disabled} maxLength={64} value={value.prefix} onChange={(e) => onChange({ ...value, prefix: e.target.value })} />
          </Field>
        </>
      )}
      <Field label="What the key is called" labelHint="Optional" error={errors.label} description='Shown where people enter it, for example "Acme API key".'>
        <Input maxLength={100} disabled={disabled} value={value.label} onChange={(e) => onChange({ ...value, label: e.target.value })} />
      </Field>
      <Field label="Where to find it" labelHint="Optional" error={errors.help} description="Plain text on that page, for example: Acme › Settings › API keys.">
        <Textarea maxLength={2000} disabled={disabled} value={value.help} onChange={(e) => onChange({ ...value, help: e.target.value })} />
      </Field>
      <p className={m.muted}>
        Each person enters their own key under Account › My connections, and calls carry it only to this server&apos;s address. A new address, another way of sending it or
        leaving this mode deletes everyone&apos;s keys; a new name, prefix or text does not.
      </p>
    </div>
  );
}
