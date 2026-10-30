/*
 * A gateway's sensitivity ceiling (decision 88): the highest label of server
 * it serves. A server above it is listed as unavailable on the gateway's
 * Capabilities tab, with the reason, and is never served. The default,
 * restricted, is no ceiling.
 */
import { SettingsSection } from "../templates/settings-page";
import { Alert } from "@/components/ui/alert/alert";
import { Field } from "@/components/ui/field/field";
import { NativeSelect } from "@/components/ui/input/input";
import { ceilingText, type Sensitivity, sensitivities, sensitivityLabels } from "../servers/governance";

type Props = { value: Sensitivity; saved: Sensitivity; disabled: boolean; unavailable: number; onChange: (v: Sensitivity) => void };

export function CeilingSection({ value, saved, disabled, unavailable, onChange }: Props) {
  const lowering = sensitivities.indexOf(value) < sensitivities.indexOf(saved);
  return (
    <SettingsSection title="Sensitivity ceiling" description="The most sensitive servers this gateway may serve. Each server's team labels it; a server above the ceiling is never served here.">
      <Field label="Highest label served" description={ceilingText(value)}>
        <NativeSelect value={value} disabled={disabled} onChange={(e) => onChange(e.target.value as Sensitivity)}>
          {sensitivities.map((s) => (
            <option key={s} value={s}>
              {sensitivityLabels[s]}
              {s === "restricted" ? " (no ceiling)" : ""}
            </option>
          ))}
        </NativeSelect>
      </Field>
      {lowering && (
        <Alert tone="warning" title="Tools may disappear for everyone who uses this gateway">
          Servers above {sensitivityLabels[value].toLowerCase()} stop being served as soon as you save. They stay selected and show as unavailable, with the reason.
        </Alert>
      )}
      {!lowering && unavailable > 0 && value !== "restricted" && (
        <Alert tone="info">Some selected capabilities are unavailable. Open the Capabilities tab to see why: a server above this ceiling says so.</Alert>
      )}
    </SettingsSection>
  );
}
