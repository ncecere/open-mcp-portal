/*
 * A server's "User authorization" settings (decision 26): whether its
 * capabilities need each caller's own account with an auth provider, which
 * provider (from GET /v1/auth-providers for this team and server: enabled
 * ones that are open to the team, or restricted ones that list the team or
 * the server, decision 69; one already chosen that was turned off, or that
 * stopped being open to the server, can be kept but not newly chosen) and
 * which scopes (none: the provider's defaults). Part of the server's settings form, saved with it.
 */
import { useQuery } from "@tanstack/react-query";
import { authProvidersQuery } from "../../api/queries";
import { normalizeScope, requirementHelp, scopesText } from "../providers/labels";
import { Alert } from "@/components/ui/alert/alert";
import { Field } from "@/components/ui/field/field";
import { NativeSelect } from "@/components/ui/input/input";
import { Switch } from "@/components/ui/switch/switch";
import { TagInput } from "@/components/ui/tag-input/tag-input";
import s from "../../pages/shared.module.css";
import type { McpServer } from "./labels";
import type { RequirementForm } from "./requirement";

type Props = {
  server: McpServer;
  value: RequirementForm;
  onChange: (next: RequirementForm) => void;
  errors: { provider?: string; scopes?: string };
  disabled?: boolean;
  /** Saving resets capabilities' own scopes to the server's (the provider changes or goes). */
  resetsOverrides: number;
};

export function RequirementFields({ server, value, onChange, errors, disabled, resetsOverrides }: Props) {
  const providers = useQuery(authProvidersQuery({ team: server.teamSlug, serverId: server.id }));
  const list = providers.data ?? [];
  const current = server.requirement;
  // A provider the server already names that was turned off, or that is no longer open to it, stays choosable (it can be kept, not newly chosen).
  const keptOff = current && !list.some((p) => p.id === current.providerId) ? current : null;
  const chosen = list.find((p) => p.id === value.providerId);
  const defaults = chosen ? scopesText(chosen.defaultScopes, "none") : undefined;
  return (
    <>
      <p className={s.muted}>{requirementHelp}</p>
      <Switch
        label="Requires a connection"
        description="Callers connect their own account with a provider before these capabilities run. Without it, calls carry only the portal's identity token."
        disabled={disabled}
        checked={value.on}
        onCheckedChange={(on) => onChange({ ...value, on, providerId: on && !value.providerId ? (list[0]?.id ?? "") : value.providerId })}
      />
      {value.on && (
        <>
          {providers.data && list.length === 0 && !keptOff && (
            <Alert tone="info">No auth provider is open to this team yet. Platform admins add providers, and the teams that may use them, in Admin › Auth providers.</Alert>
          )}
          {keptOff?.providerEnabled && keptOff.providerId === value.providerId && (
            <Alert tone="warning" title={`${keptOff.providerName} isn't open to this team`}>
              Calls to this server that need it are refused until a platform admin adds the team or this server to the provider&apos;s access list. Choose another provider to change it.
            </Alert>
          )}
          <Field label="Provider" description="The service the token is for. Platform admins configure the providers." error={errors.provider}>
            <NativeSelect disabled={disabled} value={value.providerId} onChange={(e) => onChange({ ...value, providerId: e.target.value })}>
              {!value.providerId && <option value="">Choose a provider</option>}
              {keptOff && <option value={keptOff.providerId}>{`${keptOff.providerName} (${keptOff.providerEnabled ? "not open to this team" : "turned off"})`}</option>}
              {list.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </NativeSelect>
          </Field>
          <Field
            label="Scopes"
            labelHint="Optional"
            description={`What the token may do, in the provider's own names; press Enter after each. Leave empty for the provider's default scopes${defaults ? ` (${defaults})` : ""}. Ask for as little as the tools need.`}
            error={errors.scopes}
          >
            <TagInput
              value={value.scopes}
              onValueChange={(scopes) => onChange({ ...value, scopes })}
              normalize={normalizeScope}
              maxTags={50}
              maxTagLength={200}
              noun={{ one: "scope", other: "scopes" }}
              disabled={disabled}
            />
          </Field>
        </>
      )}
      {current && !current.providerEnabled && (
        <Alert tone="warning" title={`${current.providerName} is turned off`}>
          A platform admin turned this provider off, so calls that need it are refused until it&apos;s on again.
        </Alert>
      )}
      {resetsOverrides > 0 && (
        <Alert tone="info">
          {resetsOverrides === 1 ? "1 capability has" : `${resetsOverrides} capabilities have`} its own scopes. Saving with {value.on ? "another provider" : "no requirement"} sets{" "}
          {resetsOverrides === 1 ? "it" : "them"} back to the server&apos;s requirement.
        </Alert>
      )}
    </>
  );
}
