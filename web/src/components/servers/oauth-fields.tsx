/*
 * The OAuth settings of a server in oauth mode (Add and Settings): how the
 * gateway gets its client (automatic registration, a matching platform
 * provider's client, or a client the team creates and enters: client ID,
 * replace-only secret, token method, with the callback to register), the
 * scopes each person allows (from what the server supports), the
 * authorization server when it lists several, and the resource parameter.
 */
import { callbackPath, normalizeScope, type TokenAuthMethod, tokenAuthMethodLabels } from "../providers/labels";
import { Checkbox, CheckboxGroup } from "@/components/ui/checkbox/checkbox";
import { CopyField } from "@/components/ui/copy-field/copy-field";
import { Disclosure } from "@/components/ui/disclosure/disclosure";
import { Field } from "@/components/ui/field/field";
import { Input, NativeSelect } from "@/components/ui/input/input";
import { type RadioOption, RadioGroup } from "@/components/ui/radio-group/radio-group";
import { Switch } from "@/components/ui/switch/switch";
import { TagInput } from "@/components/ui/tag-input/tag-input";
import { type McpServer, urlHost } from "./labels";
import {
  choiceOf,
  type DetectResult,
  gitHubScopes,
  type OAuthErrors,
  type OAuthForm,
  oauthUsable,
  type RegistrationChoice,
  registrationLabels,
  splitChoice,
  supportedScopes,
} from "./upstream-auth";
import m from "./servers.module.css";

type Props = {
  value: OAuthForm;
  onChange: (next: OAuthForm) => void;
  detected?: DetectResult;
  /** The server as saved (Settings). */
  server?: McpServer;
  secret: string;
  setSecret: (secret: string) => void;
  errors: OAuthErrors;
  disabled?: boolean;
};

const methods: TokenAuthMethod[] = ["client_secret_post", "client_secret_basic", "none"];

/** The registrations to choose from: what the detection offers (each matching provider on its own), else the stored one; always a client entered by hand. */
function registrationOptions(detected: DetectResult | undefined, server: McpServer | undefined): RadioOption<RegistrationChoice>[] {
  const reg = oauthUsable(detected) ? detected?.registration : undefined;
  const host = urlHost(detected?.authorizationServer?.issuer ?? server?.oauth?.authorizationServer ?? "");
  const out: RadioOption<RegistrationChoice>[] = [];
  const offered = reg ? reg.options : server?.oauth ? [server.oauth.registration] : [];
  if (offered.includes("cimd"))
    out.push({ value: "cimd", label: "Automatic: the portal's client metadata document", description: "A public client whose ID is the portal's own address. Nothing to create." });
  if (offered.includes("dcr")) out.push({ value: "dcr", label: "Automatic: register a client", description: `The portal registers its own client at ${host} when you save.` });
  const providers = reg ? reg.matchingProviders : server?.oauth?.platformProvider ? [server.oauth.platformProvider] : [];
  for (const p of providers) {
    out.push({
      value: choiceOf("platform_provider", p.id),
      label: `Use platform provider ${p.name}`,
      description: `The client a platform admin set up for ${p.name}. Sign-ins to this server stay separate from people's ${p.name} connections.`,
    });
  }
  out.push({ value: "manual", label: "Enter a client ID and secret", description: `Create an OAuth app at ${host || "the authorization server"} with the callback below.` });
  return out;
}

export function OAuthFields({ value, onChange, detected, server, secret, setSecret, errors, disabled }: Props) {
  const set = (patch: Partial<OAuthForm>) => onChange({ ...value, ...patch });
  const stored = server?.oauth;
  const { registration } = splitChoice(value.registration);
  const keepsManual = stored?.registration === "manual" && registration === "manual";
  const listed = detected?.authorizationServer?.tokenEndpointAuthMethodsSupported ?? [];
  const methodChoices = methods.filter((x) => listed.length === 0 || listed.includes(x) || x === value.tokenAuthMethod);
  const supported = detected ? supportedScopes(detected) : (stored?.scopesSupported ?? []);
  const scopeChoices = [...supported, ...value.scopes.filter((x) => !supported.includes(x))];
  const servers = detected?.resourceMetadata?.authorizationServers ?? [];
  const github = gitHubScopes.every((x) => supported.includes(x)) && urlHost(detected?.authorizationServer?.issuer ?? stored?.issuer ?? "") === "github.com";
  const redirectUri = detected?.registration?.redirectUri ?? `${globalThis.location?.origin ?? ""}${callbackPath}`;
  const scopeHelp =
    `What each person allows the server to do. Ask for as little as its tools need${github ? ` (for GitHub, usually ${gitHubScopes.join(", ")})` : ""}.` +
    " Adding a scope later sends a published server back to review.";
  return (
    <>
      <RadioGroup<RegistrationChoice>
        legend="Client"
        description="How the portal gets its OAuth client at the authorization server."
        options={registrationOptions(detected, server)}
        value={value.registration}
        onValueChange={(registration) => set({ registration })}
        error={errors.registration}
        disabled={disabled}
      />
      {stored && !detected && <p className={m.capMeta}>Now: {registrationLabels[stored.registration]}. Press Detect sign-in to see every option the server offers.</p>}
      {registration === "manual" && (
        <>
          <CopyField label="Callback URL" name="callback URL" value={redirectUri} description="Register this exact URL as the OAuth app's callback (redirect) URL." />
          <Field
            label={keepsManual ? "Replace client ID" : "Client ID"}
            description={keepsManual ? `The stored one ends in ${stored?.clientIdHint}. Leave empty to keep it; a new one signs everyone out of this server.` : "From the OAuth app you created."}
            error={errors.clientId}
          >
            <Input autoComplete="off" spellCheck={false} maxLength={500} disabled={disabled} value={value.clientId} onChange={(e) => set({ clientId: e.target.value })} />
          </Field>
          <Field
            label={keepsManual && stored?.hasClientSecret ? "Replace client secret" : "Client secret"}
            description={keepsManual && stored?.hasClientSecret ? "Stored encrypted. Leave empty to keep it. It's never shown again." : "Stored encrypted and never shown again."}
            error={errors.clientSecret}
          >
            <Input type="password" autoComplete="new-password" maxLength={2000} disabled={disabled} value={secret} onChange={(e) => setSecret(e.target.value)} />
          </Field>
          <Field label="Token method" description="How the portal proves it's the client when it asks for tokens.">
            <NativeSelect disabled={disabled} value={value.tokenAuthMethod} onChange={(e) => set({ tokenAuthMethod: e.target.value as TokenAuthMethod })}>
              {methodChoices.map((x) => (
                <option key={x} value={x}>
                  {tokenAuthMethodLabels[x]}
                </option>
              ))}
            </NativeSelect>
          </Field>
        </>
      )}
      {scopeChoices.length > 0 ? (
        <CheckboxGroup legend="Scopes" description={scopeHelp} orientation="horizontal" value={value.scopes} onValueChange={(scopes) => set({ scopes: scopeChoices.filter((x) => scopes.includes(x)) })} error={errors.scopes}>
          {scopeChoices.map((x) => (
            <Checkbox key={x} value={x} label={<code>{x}</code>} disabled={disabled} />
          ))}
        </CheckboxGroup>
      ) : (
        <Field label="Scopes" labelHint="Optional" description={`The server lists none. ${scopeHelp} Press Enter after each.`} error={errors.scopes}>
          <TagInput value={value.scopes} onValueChange={(scopes) => set({ scopes })} normalize={normalizeScope} maxTags={50} maxTagLength={200} noun={{ one: "scope", other: "scopes" }} disabled={disabled} />
        </Field>
      )}
      {servers.length > 1 && (
        <Field label="Authorization server" description="The server lists several. The detection read the first; the portal checks the one you choose when you save.">
          <NativeSelect disabled={disabled} value={value.authorizationServer || servers[0]} onChange={(e) => set({ authorizationServer: e.target.value })}>
            {servers.map((x) => (
              <option key={x} value={x}>
                {x}
              </option>
            ))}
          </NativeSelect>
        </Field>
      )}
      <Disclosure title="Advanced" summary={value.sendResource ? "Resource indicator sent" : "Resource indicator off"}>
        <Switch
          label="Send resource indicator"
          description="Sends the server's URL as the resource parameter (RFC 8707) when people sign in, as the MCP spec requires, so their tokens work only for this server. Turn it off only if the authorization server refuses it."
          disabled={disabled}
          checked={value.sendResource}
          onCheckedChange={(sendResource) => set({ sendResource })}
        />
      </Disclosure>
      {value.scopes.length === 0 && scopeChoices.length > 0 && <p className={m.capMeta}>No scope ticked: people sign in with the authorization server&apos;s default access.</p>}
    </>
  );
}
