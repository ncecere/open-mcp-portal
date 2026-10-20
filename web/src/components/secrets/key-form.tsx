/*
 * Entering a person's own key for a server (decision 72): the fields shared by
 * the dialog on Account › My connections and the page a call's link opens
 * (/connect/secret/{request}). It names the server, its team, the address the
 * key will go to (and only there), how it is sent and what the team calls it;
 * the key goes in a password field and is never shown again (not here, not in
 * a list: only its last four characters). Saving sends the origin the person
 * was shown, so a server that moved meanwhile is refused (409 server_changed).
 * Editors can also choose to read the server's capabilities with their key;
 * everyone chooses whether agents acting for them may use it.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ApiError, type Schemas, unwrap } from "../../api/client";
import { keyLabel, placementText, type ServerSecret } from "../servers/person-secret";
import { Alert } from "@/components/ui/alert/alert";
import { Field } from "@/components/ui/field/field";
import { Input } from "@/components/ui/input/input";
import { Switch } from "@/components/ui/switch/switch";
import { toast } from "@/components/ui/toast/toast";
import m from "../servers/servers.module.css";

export const myServerSecretsKey = ["my", "server-secrets"];

/** 8 to 4096 characters on one line (the server decides; this saves a round trip). */
export function keyProblem(v: string): string | undefined {
  const t = v.trim();
  if (t.length < 8) return "Enter the key: at least 8 characters.";
  if (t.length > 4096 || /[\r\n]/.test(t)) return "The key must be on one line, at most 4096 characters.";
  return undefined;
}

/** The words for this save's refusals; undefined for any other error. */
export function describeKeyError(err: unknown): { title?: string; message: string } | undefined {
  if (!(err instanceof ApiError)) return undefined;
  switch (err.code) {
    case "server_changed":
      return { title: "The server's address changed", message: "Nothing was saved. It is on another host than the one this page showed: close this and open it again to review where your key would go." };
    case "server_not_found":
      return { title: "You can't use this server", message: "It doesn't exist, or none of your gateways offers it, so no key can be entered for it." };
    case "not_person_secret":
      return { title: "This server doesn't ask for keys any more", message: "Reload the page." };
    case "invalid_secret_value":
      return { title: "Check the key", message: err.message };
    default:
      return undefined;
  }
}

export type KeyFormState = ReturnType<typeof useKeyForm>;

/** The form's state and its save. `onSaved` runs after a successful save (the key field is cleared first). */
export function useKeyForm(entry: ServerSecret, onSaved?: (saved: ServerSecret) => void) {
  const qc = useQueryClient();
  const [value, setValue] = useState("");
  const [allowAgents, setAllowAgents] = useState(entry.allowAgents);
  const [useForSetup, setUseForSetup] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const save = useMutation({
    mutationFn: async (): Promise<ServerSecret> => {
      const body: Schemas["SetServerSecret"] = { origin: entry.origin, value: value.trim(), allowAgents, ...(useForSetup ? { useForSetup } : {}) };
      return unwrap(await api.PUT("/v1/me/server-secrets/{serverId}", { params: { path: { serverId: entry.server.id } }, body }));
    },
    onSuccess: (saved) => {
      setValue("");
      toast.success(`Your ${keyLabel(entry.config)} for ${entry.server.name} was saved`, "It is stored encrypted and won't be shown again.");
      void qc.invalidateQueries({ queryKey: myServerSecretsKey });
      void qc.invalidateQueries({ queryKey: ["team", entry.server.teamSlug, "servers"] });
      onSaved?.(saved);
    },
  });
  const problem = keyProblem(value);
  return {
    value,
    setValue: (v: string) => {
      if (save.isError) save.reset();
      setValue(v);
    },
    allowAgents,
    setAllowAgents,
    useForSetup,
    setUseForSetup,
    submitted,
    save,
    problem,
    submit: () => {
      setSubmitted(true);
      if (!problem) save.mutate();
    },
  };
}

type Props = { entry: ServerSecret; form: KeyFormState };

/** The fields: where the key goes, the key itself and the two switches. */
export function KeyFields({ entry, form }: Props) {
  const label = keyLabel(entry.config);
  const query = entry.config.placement === "query";
  return (
    <div className={m.stack}>
      <dl>
        <dt>Server</dt>
        <dd>
          <strong>{entry.server.name}</strong> · team {entry.server.teamName}
        </dd>
        <dt>Your key goes only to</dt>
        <dd>
          <code>{entry.origin}</code>
        </dd>
        <dt>Sent as</dt>
        <dd>{placementText(entry.config)}</dd>
      </dl>
      {entry.config.help && <p className={m.muted}>{entry.config.help}</p>}
      {query && (
        <Alert tone="warning" title="This server takes the key in the address">
          Servers and proxies often log addresses, so your key may be written to their logs. The portal never logs it.
        </Alert>
      )}
      <Field
        label={entry.hasSecret ? `Replace your ${label}` : `Your ${label}`}
        description={entry.hasSecret ? `Stored now: ${entry.hint ? `ends in ${entry.hint}` : "entered"}. Typing a new one replaces it.` : "Paste it here. It is stored encrypted and never shown again, not even to you."}
        error={form.submitted ? form.problem : undefined}
      >
        <Input type="password" name="server-key" autoComplete="off" spellCheck={false} autoCapitalize="off" value={form.value} onChange={(e) => form.setValue(e.target.value)} />
      </Field>
      <Switch
        label="Let my agents use this key"
        description="An agent acting for you can't open a link to enter one, so it uses this key only when you allow it. Off, it is told to ask you here."
        checked={form.allowAgents}
        onCheckedChange={form.setAllowAgents}
      />
      {entry.canSetup && (
        <Switch
          label="Use my key to read this server's capabilities"
          description="The portal reads the server's tools, resources and prompts with one editor's key. Scheduled health checks send nobody's key."
          checked={form.useForSetup}
          onCheckedChange={form.setUseForSetup}
        />
      )}
    </div>
  );
}
