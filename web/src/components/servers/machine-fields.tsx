/*
 * The machine OAuth client of a server in machine_oauth mode (Add and
 * Settings; machine-auth.ts): the authorization server's token endpoint, the
 * client the portal was given (ID and a replace-only secret), how it
 * authenticates at the token endpoint, the scopes, and optionally an audience or
 * resource. Detect sign-in fills the token endpoint and resource when the
 * authorization server offers the client credentials grant.
 */
import { normalizeScope } from "../providers/labels";
import { Alert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Disclosure } from "@/components/ui/disclosure/disclosure";
import { Field } from "@/components/ui/field/field";
import { Input, NativeSelect } from "@/components/ui/input/input";
import { TagInput } from "@/components/ui/tag-input/tag-input";
import type { McpServer } from "./labels";
import { type MachineErrors, type MachineForm, machineMethodLabels, machineMethods, secretWhy } from "./machine-auth";
import { sameOrigin } from "./origin";
import type { DetectResult } from "./upstream-auth";
import m from "./servers.module.css";

type Props = {
  value: MachineForm;
  onChange: (next: MachineForm) => void;
  detected?: DetectResult;
  /** The server as saved (Settings) and the URL as edited: another host asks for the secret again. */
  server?: McpServer;
  url: string;
  secret: string;
  setSecret: (secret: string) => void;
  errors: MachineErrors;
  disabled?: boolean;
};

export function MachineFields({ value, onChange, detected, server, url, secret, setSecret, errors, disabled }: Props) {
  const set = (patch: Partial<MachineForm>) => onChange({ ...value, ...patch });
  const stored = server?.machineOAuth;
  const found = detected?.machineOAuth;
  const why = secretWhy(value, stored, { originMoved: Boolean(server) && !sameOrigin(server?.url ?? "", url.trim()) });
  return (
    <>
      {found && (
        <Alert
          tone={found.clientCredentials ? "info" : "warning"}
          title={found.clientCredentials ? "The authorization server offers client credentials" : "The authorization server doesn't list client credentials"}
          actions={
            !disabled &&
            found.tokenEndpoint && (
              <Button size="sm" variant="secondary" onClick={() => set({ tokenUrl: found.tokenEndpoint, resource: value.resource || found.resource })}>
                Use its token endpoint
              </Button>
            )
          }
        >
          {found.clientCredentials
            ? `Token endpoint ${found.tokenEndpoint}.`
            : `Its metadata ${found.grantTypesListed ? "lists other grant types" : "doesn't say which grants it supports"}. Ask whoever runs it whether a client can use the client_credentials grant.`}
        </Alert>
      )}
      <Field label="Token endpoint" description="Where the portal asks for its token, at the server's authorization server. Checked against the address rules when you save." error={errors.tokenUrl}>
        <Input autoComplete="off" spellCheck={false} maxLength={1000} disabled={disabled} value={value.tokenUrl} onChange={(e) => set({ tokenUrl: e.target.value })} />
      </Field>
      <Field
        label={stored ? "Replace client ID" : "Client ID"}
        description={stored ? `The stored one ends in ${stored.clientIdHint}. Leave empty to keep it; a new one needs the secret again.` : "The client the authorization server created for the portal."}
        error={errors.machineClientId}
      >
        <Input autoComplete="off" spellCheck={false} maxLength={500} disabled={disabled} value={value.clientId} onChange={(e) => set({ clientId: e.target.value })} />
      </Field>
      <Field
        label={stored ? "Replace client secret" : "Client secret"}
        description={
          stored && !why
            ? `Stored encrypted${stored.clientSecretHint ? `, ending in ${stored.clientSecretHint}` : ""}. Leave empty to keep it. It's never shown again.`
            : `Stored encrypted and never shown again. ${why ? `Enter it again: the ${why} changed, and the stored secret was entered for the old one.` : ""}`
        }
        error={errors.machineSecret}
      >
        <Input type="password" autoComplete="new-password" maxLength={2000} disabled={disabled} value={secret} onChange={(e) => setSecret(e.target.value)} />
      </Field>
      <Field label="Token method" description="How the portal proves it's the client at the token endpoint.">
        <NativeSelect disabled={disabled} value={value.tokenAuthMethod} onChange={(e) => set({ tokenAuthMethod: e.target.value as MachineForm["tokenAuthMethod"] })}>
          {machineMethods.map((x) => (
            <option key={x} value={x}>
              {machineMethodLabels[x]}
            </option>
          ))}
        </NativeSelect>
      </Field>
      <Field label="Scopes" labelHint="Optional" description="What the portal's token may do. Ask for as little as the tools need; adding a scope later sends a published server back to review. Press Enter after each." error={errors.machineScopes}>
        <TagInput value={value.scopes} onValueChange={(scopes) => set({ scopes })} normalize={normalizeScope} maxTags={50} maxTagLength={200} noun={{ one: "scope", other: "scopes" }} disabled={disabled} />
      </Field>
      <Disclosure title="Advanced" summary={value.resource || value.audience ? "Audience or resource set" : "No audience or resource"}>
        <Field label="Resource" labelHint="Optional" description="Sent as the resource parameter (RFC 8707) so the token is for this server only. Some authorization servers ignore it, and then the token works elsewhere too." error={errors.machineResource}>
          <Input autoComplete="off" spellCheck={false} maxLength={500} disabled={disabled} value={value.resource} onChange={(e) => set({ resource: e.target.value })} />
        </Field>
        <Field label="Audience" labelHint="Optional" description="Sent as the audience parameter, which some authorization servers (Auth0, for example) want instead of a resource.">
          <Input autoComplete="off" spellCheck={false} maxLength={500} disabled={disabled} value={value.audience} onChange={(e) => set({ audience: e.target.value })} />
        </Field>
      </Disclosure>
      <p className={m.capMeta}>Everyone who calls this server shares the portal&apos;s token: the call log and the identity token are the only record of who called.</p>
    </>
  );
}
