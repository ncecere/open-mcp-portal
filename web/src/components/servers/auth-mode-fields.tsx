/*
 * The Authentication section of Add and Settings: Detect sign-in, the mode
 * (None, Static header, Sign-in with OAuth per person; OAuth only once a
 * detection found it usable, or when the server uses it already), the
 * mode's fields, and whether the server receives the identity token
 * (decision 45, recommended off for servers run outside the company).
 */
import type { ReactNode } from "react";
import { Alert } from "@/components/ui/alert/alert";
import { type RadioOption, RadioGroup } from "@/components/ui/radio-group/radio-group";
import { Switch } from "@/components/ui/switch/switch";
import { DetectSignIn } from "./detect-auth";
import type { McpServer } from "./labels";
import { OAuthFields } from "./oauth-fields";
import { type AuthMode, authModeHelp, authModeLabels, type DetectResult, type OAuthErrors, oauthUsable, otherHost, type UpstreamForm } from "./upstream-auth";
import m from "./servers.module.css";

type Props = {
  team: string;
  url: string;
  urlError?: string;
  value: UpstreamForm;
  onChange: (next: UpstreamForm) => void;
  detected?: DetectResult;
  onDetected: (r: DetectResult) => void;
  onUseUrl: (url: string) => void;
  server?: McpServer;
  secret: string;
  setSecret: (secret: string) => void;
  errors: OAuthErrors;
  disabled?: boolean;
  /** The static header's fields. */
  headerFields: ReactNode;
  /** Warnings about what saving the change does (review, sign-ins). */
  notes?: ReactNode;
  /** Why the identity switch starts where it does (Add: it follows the address). */
  identityNote?: ReactNode;
};

export const identityHelp =
  "Every call carries a signed token (Authorization: Bearer …) with the caller's name, email and teams, so the server knows who's calling; Test connection sends one for you too. Turn it off for servers run outside the company, such as GitHub's hosted MCP server, so that personal data isn't sent to a third party. Some public servers refuse any Authorization header, so it should be off for them: a server like that fails on its first call while this is on. A new server with no sign-in on a public address starts with this off.";

export function AuthModeFields({ team, url, urlError, value, onChange, detected, onDetected, onUseUrl, server, secret, setSecret, errors, disabled, headerFields, notes, identityNote }: Props) {
  const canOAuth = oauthUsable(detected) || server?.authMode === "oauth";
  const options: RadioOption<AuthMode>[] = (["none", "static_header", "oauth"] as AuthMode[]).map((mode) => ({
    value: mode,
    label: authModeLabels[mode],
    description: mode === "oauth" && !canOAuth ? `${authModeHelp.oauth} Press Detect sign-in first.` : authModeHelp[mode],
    disabled: mode === "oauth" && !canOAuth && value.mode !== "oauth",
  }));
  const asHost = value.mode === "oauth" ? otherHost(detected?.authorizationServer?.issuer ?? server?.oauth?.authorizationServer ?? "", url) : undefined;
  return (
    <div className={`${m.wide} ${m.stack}`}>
      {!disabled && <DetectSignIn team={team} url={url} urlError={urlError} result={detected} onResult={onDetected} onUseUrl={onUseUrl} />}
      <RadioGroup<AuthMode>
        legend="How the portal authenticates"
        options={options}
        value={value.mode}
        onValueChange={(mode) => onChange({ ...value, mode })}
        error={errors.mode}
        disabled={disabled}
      />
      {value.mode === "static_header" && headerFields}
      {value.mode === "oauth" && (
        <OAuthFields
          value={value.oauth}
          onChange={(oauth) => onChange({ ...value, oauth })}
          detected={detected}
          server={server}
          secret={secret}
          setSecret={setSecret}
          errors={errors}
          disabled={disabled}
        />
      )}
      {notes}
      <Switch label="Send identity token" description={identityHelp} disabled={disabled} checked={value.sendIdentity} onCheckedChange={(sendIdentity) => onChange({ ...value, sendIdentity })} />
      {identityNote && <p className={m.identityNote}>{identityNote}</p>}
      {value.sendIdentity && asHost && !disabled && (
        <Alert tone="info" title="Run outside the company?">
          People sign in to this server at {asHost}. If a third party runs it, turn off Send identity token: the server still gets each person&apos;s own token, but not their
          name, email and teams.
        </Alert>
      )}
    </div>
  );
}
