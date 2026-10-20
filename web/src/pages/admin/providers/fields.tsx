/*
 * An auth provider's fields, in groups that Create (FormSection) and
 * Settings (SettingsSection) each wrap their own way: the provider, its
 * OAuth app (the redirect URI to register, the client ID, the replace-only
 * secret, how the token endpoint authenticates, PKCE), the endpoints, and
 * the authorization request (default scopes, the scope parameter and
 * separator, the token response format and extra parameters, for
 * providers such as Slack and Google).
 */
import { normalizeScope, tokenAuthMethodLabels, tokenResponseFormatLabels, type TokenAuthMethod, type TokenResponseFormat } from "@/components/providers/labels";
import { CopyField } from "@/components/ui/copy-field/copy-field";
import { Field } from "@/components/ui/field/field";
import { Input, NativeSelect, Textarea } from "@/components/ui/input/input";
import { Switch } from "@/components/ui/switch/switch";
import { TagInput } from "@/components/ui/tag-input/tag-input";
import m from "@/components/servers/servers.module.css";
import s from "../../shared.module.css";
import type { ProviderForm, ProviderProblems } from "./form";

export type FieldsProps = {
  form: ProviderForm;
  set: (patch: Partial<ProviderForm>) => void;
  errors: ProviderProblems;
  disabled?: boolean;
};

/** Name, slug (typed on Create, fixed afterwards), logo and the switch. */
export function IdentityFields({ form, set, errors, disabled, creating }: FieldsProps & { creating: boolean }) {
  return (
    <>
      <Field label="Name" description="What people see when they connect, such as GitHub or Google Workspace." error={errors.name}>
        <Input maxLength={100} disabled={disabled} value={form.name} onChange={(e) => set({ name: e.target.value })} />
      </Field>
      {creating ? (
        <Field
          label="Slug"
          description="Lower-case letters, digits and dashes. Servers receive it in MCP-Gateway-Provider and the identity token's provider claim, and consent links use it. It can't be changed later."
          error={errors.slug}
        >
          <Input spellCheck={false} autoComplete="off" maxLength={48} disabled={disabled} value={form.slug} onChange={(e) => set({ slug: e.target.value })} />
        </Field>
      ) : (
        <CopyField label="Slug" name="provider slug" value={form.slug} description="Can't be changed. Servers receive it in MCP-Gateway-Provider and the identity token's provider claim." />
      )}
      <Field label="Logo URL" labelHint="Optional" description="An https address or a path on this site, shown next to the name." error={errors.logoUrl}>
        <Input type="url" inputMode="url" spellCheck={false} maxLength={500} disabled={disabled} value={form.logoUrl} onChange={(e) => set({ logoUrl: e.target.value })} />
      </Field>
      <Switch
        label="Enabled"
        description="Turned off, calls that need it are refused and nobody can connect it. Existing connections are kept."
        disabled={disabled}
        checked={form.enabled}
        onCheckedChange={(v) => set({ enabled: v })}
      />
    </>
  );
}

type AppProps = FieldsProps & {
  redirectUri: string;
  /** The typed secret (replace-only: never loaded, sent only when typed). */
  secret: string;
  setSecret: (v: string) => void;
  hasSecret: boolean;
  hint?: string;
};

/** The redirect URI to register, the client ID and secret, the token endpoint's authentication and PKCE. */
export function AppFields({ form, set, errors, disabled, redirectUri, secret, setSecret, hasSecret, hint }: AppProps) {
  const isPublic = form.tokenAuthMethod === "none";
  return (
    <>
      <CopyField
        label="Redirect URI"
        name="redirect URI"
        value={redirectUri}
        className={m.wide}
        description="Register this exact address as the callback (redirect) URL of the OAuth app you create at the provider."
      />
      <Field label="Client ID" description="From the OAuth app you registered. Changing it later disconnects everyone: their tokens belong to the old app." error={errors.clientId}>
        <Input spellCheck={false} autoComplete="off" maxLength={500} disabled={disabled} value={form.clientId} onChange={(e) => set({ clientId: e.target.value })} />
      </Field>
      <Field
        label={hasSecret ? "Replace client secret" : "Client secret"}
        labelHint={isPublic ? "Not used" : undefined}
        description={
          isPublic
            ? "A public client has no secret."
            : hasSecret
              ? `The stored secret ends in ${hint || "…"}. Leave empty to keep it. It's never shown again.`
              : "Stored encrypted and never shown again, not even to platform admins."
        }
        error={errors.clientSecret}
      >
        <Input type="password" autoComplete="new-password" maxLength={2000} disabled={disabled || isPublic} value={secret} onChange={(e) => setSecret(e.target.value)} />
      </Field>
      <Field label="Token endpoint authentication" description="How the portal proves it's the app when it exchanges a code or refreshes a token.">
        <NativeSelect disabled={disabled} value={form.tokenAuthMethod} onChange={(e) => set({ tokenAuthMethod: e.target.value as TokenAuthMethod })}>
          {(Object.keys(tokenAuthMethodLabels) as TokenAuthMethod[]).map((m) => (
            <option key={m} value={m}>
              {tokenAuthMethodLabels[m]}
            </option>
          ))}
        </NativeSelect>
      </Field>
      <div>
        <Switch
          label="Use PKCE (S256)"
          description="Protects the code exchange. Keep it on unless the provider rejects it; a public client needs it."
          disabled={disabled}
          checked={form.pkce}
          onCheckedChange={(v) => set({ pkce: v })}
        />
        {errors.pkce && <p className={s.dangerText}>{errors.pkce}</p>}
      </div>
    </>
  );
}

const endpointFields = [
  ["authorizationUrl", "Authorization URL", "Where people's browsers go to approve, such as https://github.com/login/oauth/authorize.", false],
  ["tokenUrl", "Token URL", "Where the portal exchanges codes and refreshes tokens, through the same address guard as MCP servers.", false],
  ["revocationUrl", "Revocation URL", "RFC 7009. Used when someone disconnects; without it, tokens are only erased here.", true],
  ["userinfoUrl", "Userinfo URL", "Read once after connecting, to label the account (such as octocat). Informational only.", true],
] as const;

export function EndpointFields({ form, set, errors, disabled }: FieldsProps) {
  return (
    <>
      {endpointFields.map(([key, label, description, optional]) => (
        <Field key={key} label={label} labelHint={optional ? "Optional" : undefined} description={description} error={errors[key]}>
          <Input type="url" inputMode="url" spellCheck={false} autoComplete="off" maxLength={500} disabled={disabled} value={form[key]} onChange={(e) => set({ [key]: e.target.value })} />
        </Field>
      ))}
    </>
  );
}

/** Default scopes and how the authorization request and token response are shaped. */
export function RequestFields({ form, set, errors, disabled }: FieldsProps) {
  return (
    <>
      <Field
        label="Default scopes"
        labelHint="Optional"
        className={m.wide}
        description="Asked for when a server's requirement names none, and when someone connects from My connections. Use the provider's exact names; press Enter after each."
        error={errors.defaultScopes}
      >
        <TagInput
          value={form.defaultScopes}
          onValueChange={(v) => set({ defaultScopes: v })}
          normalize={normalizeScope}
          maxTags={50}
          maxTagLength={200}
          noun={{ one: "scope", other: "scopes" }}
          disabled={disabled}
        />
      </Field>
      <Field label="Scope parameter" description="The authorization request's parameter that carries the scopes: scope, or user_scope for Slack user tokens." error={errors.scopeParam}>
        <Input spellCheck={false} autoComplete="off" maxLength={64} disabled={disabled} value={form.scopeParam} onChange={(e) => set({ scopeParam: e.target.value })} />
      </Field>
      <Field label="Scope separator" description="How scopes are joined in the request: a space (the standard), or a comma (Slack).">
        <NativeSelect disabled={disabled} value={form.scopeSeparator === "," ? "comma" : "space"} onChange={(e) => set({ scopeSeparator: e.target.value === "comma" ? "," : " " })}>
          <option value="space">Space</option>
          <option value="comma">Comma</option>
        </NativeSelect>
      </Field>
      <Field label="Token response format" description="Where the token response puts the tokens: at the top level (standard), or under authed_user (Slack user tokens).">
        <NativeSelect disabled={disabled} value={form.tokenResponseFormat} onChange={(e) => set({ tokenResponseFormat: e.target.value as TokenResponseFormat })}>
          {(Object.keys(tokenResponseFormatLabels) as TokenResponseFormat[]).map((f) => (
            <option key={f} value={f}>
              {tokenResponseFormatLabels[f]}
            </option>
          ))}
        </NativeSelect>
      </Field>
      <Field
        label="Extra authorization parameters"
        labelHint="Optional"
        className={m.wide}
        description="Added to every authorization request, one key=value per line, such as access_type=offline for Google. At most 10; the portal sets client_id, redirect_uri, state, the scope parameter and PKCE itself."
        error={errors.extraParams}
      >
        <Textarea rows={3} spellCheck={false} disabled={disabled} value={form.extraParams} onChange={(e) => set({ extraParams: e.target.value })} />
      </Field>
    </>
  );
}

/** Whether a call gets a token narrowed to the scopes it needs (decision 69). */
export function NarrowingFields({ form, set, disabled }: FieldsProps) {
  return (
    <Switch
      label="Narrow tokens per call"
      description="A call carries a token refreshed with only the scopes it needs, kept in memory for its lifetime, instead of the stored token that holds every scope a person ever granted. Turn it on only if the provider honours a scope on refresh: the Microsoft preset documents it, while GitHub, Google, Atlassian, Slack and GitLab don't, and a provider that ignores it sends its full token anyway. It needs a refresh token: a connection without one keeps sending the stored token, and My connections says so."
      disabled={disabled}
      checked={form.narrowOnRefresh}
      onCheckedChange={(v) => set({ narrowOnRefresh: v })}
    />
  );
}
