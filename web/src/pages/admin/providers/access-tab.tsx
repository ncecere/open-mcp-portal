/*
 * An auth provider's Access tab (decision 69, H-5): who may use it. Open: any
 * team's server may require it (every provider that existed before the list
 * stays open, and says so). Restricted: only a server of a listed team, or a
 * listed server, may require it, and only they receive people's tokens; a new
 * provider starts restricted with nobody listed. Saved as a whole (If-Match on
 * the provider's revision; edits survive a change made elsewhere); a team
 * taken off the list stops delivery on the next call. Servers that require
 * the provider though the list excludes them are listed, since their calls
 * are refused. Platform admins change it; auditors read.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { api, ifMatch, unwrap } from "@/api/client";
import { adminAuthProviderAccessQuery, adminAuthProviderQuery, adminAuthProvidersKey } from "@/api/queries";
import { type AccessMode, type AuthProvider, type AuthProviderAccess } from "@/components/providers/labels";
import { useRevisionForm } from "@/components/templates/revision-form";
import { SettingsPage, SettingsSection } from "@/components/templates/settings-page";
import { Alert } from "@/components/ui/alert/alert";
import { Combobox, type ComboboxOption } from "@/components/ui/combobox/combobox";
import { Field } from "@/components/ui/field/field";
import { RadioGroup } from "@/components/ui/radio-group/radio-group";
import { TextLink } from "@/components/ui/text-link/text-link";
import { toast } from "@/components/ui/toast/toast";
import { plural } from "@/lib/format";
import { adminOnly } from "@/lib/terms";
import { useDebounced, useIsPlatformAdmin } from "../hooks";

type AccessForm = { accessMode: AccessMode; teamIds: string[]; serverIds: string[] };

const labels = { accessMode: "Access", teamIds: "Teams", serverIds: "Servers" };

const formOf = (a: AuthProviderAccess): AccessForm => ({ accessMode: a.accessMode, teamIds: a.teams.map((t) => t.id), serverIds: a.servers.map((x) => x.id) });

const modeOptions: { value: AccessMode; label: string; description: string }[] = [
  { value: "restricted", label: "Restricted", description: "Only a server of a listed team, or a listed server, may require this provider and receive people's tokens." },
  { value: "open", label: "Open to every team", description: "Any editor of any team may require this provider on their servers. The teams and servers below are kept but not used." },
];

/** What taking away from the list does to the servers that use it now, in words. */
const effectText = "A team or server taken off the list stops receiving tokens on the next call: its calls are refused until it is listed again. People's own allowances and connections are kept.";

export function ProviderAccessTab({ provider }: { provider: AuthProvider }) {
  const access = useQuery(adminAuthProviderAccessQuery(provider.id));
  if (!access.data) return <Alert tone={access.error ? "danger" : "info"}>{access.error ? "Couldn't load the access list." : "Loading the access list…"}</Alert>;
  return <AccessEditor provider={provider} access={access.data} />;
}

function useTeamOptions(): ComboboxOption[] {
  const teams = useQuery({
    queryKey: ["admin", "teams", "access-options"],
    queryFn: async () => unwrap(await api.GET("/v1/admin/teams", { params: { query: { limit: 200 } } })),
  });
  return (teams.data?.items ?? []).map((t) => ({ value: t.team.id, label: t.team.name, hint: t.team.slug }));
}

function useServerOptions(text: string): ComboboxOption[] {
  const q = useDebounced(text.trim(), 250);
  const servers = useQuery({
    queryKey: ["admin", "servers", "access-options", q],
    queryFn: async () => unwrap(await api.GET("/v1/admin/mcp-servers", { params: { query: { q: q || undefined, limit: 20 } } })),
  });
  return (servers.data?.items ?? []).map((x) => ({ value: x.id, label: x.name, hint: x.teamSlug }));
}

/** The options plus the chosen values the options don't hold (named from what's saved), so chips always have a label. */
function withChosen(options: ComboboxOption[], chosen: string[], known: Map<string, ComboboxOption>): ComboboxOption[] {
  const out = [...options];
  for (const id of chosen) if (!out.some((o) => o.value === id)) out.push(known.get(id) ?? { value: id, label: id });
  return out;
}

function AccessEditor({ provider, access }: { provider: AuthProvider; access: AuthProviderAccess }) {
  const qc = useQueryClient();
  const isAdmin = useIsPlatformAdmin();
  const saved = formOf(access);
  const [form, setForm, revision] = useRevisionForm(saved, access.revision, { labels, choices: { accessMode: { open: "Open to every team", restricted: "Restricted" } } });
  const [serverText, setServerText] = useState("");
  const teamOptions = useTeamOptions();
  const serverOptions = useServerOptions(serverText);
  const known = new Map<string, ComboboxOption>([
    ...access.teams.map((t): [string, ComboboxOption] => [t.id, { value: t.id, label: t.name, hint: t.slug }]),
    ...access.servers.map((x): [string, ComboboxOption] => [x.id, { value: x.id, label: x.name, hint: x.teamSlug }]),
  ]);
  const save = useMutation({
    mutationFn: async () =>
      unwrap(await api.PUT("/v1/admin/auth-providers/{providerId}/access", { params: { path: { providerId: provider.id }, header: ifMatch(access.revision) }, body: form })),
    onSuccess: (updated) => {
      qc.setQueryData(adminAuthProviderAccessQuery(provider.id).queryKey, updated);
      void qc.invalidateQueries({ queryKey: adminAuthProviderQuery(provider.id).queryKey });
      void qc.invalidateQueries({ queryKey: adminAuthProvidersKey });
      void qc.invalidateQueries({ queryKey: ["auth-providers"] });
      toast.success("Access saved", updated.accessMode === "open" ? `${provider.name} is open to every team.` : `${provider.name} is restricted to the listed teams and servers.`);
    },
  });
  const dirty = JSON.stringify(form) !== JSON.stringify(saved);
  const empty = form.accessMode === "restricted" && form.teamIds.length === 0 && form.serverIds.length === 0;
  const restrict = form.accessMode === "restricted";
  return (
    <SettingsPage
      revision={revision}
      canEdit={isAdmin}
      readOnlyNote={adminOnly}
      dirty={dirty}
      saving={save.isPending}
      error={save.error}
      saveLabel="Save access"
      onSave={() => save.mutate()}
      onDiscard={() => {
        setForm(saved);
        save.reset();
      }}
    >
      {access.accessMode === "open" && (
        <Alert tone="warning" title="Open to every team">
          Any editor of any team can require {provider.name} on their servers, and those servers then receive the tokens of everyone who connected it and allowed them. Restrict it to the teams that need it.
        </Alert>
      )}
      {access.blockedCount > 0 && (
        <Alert tone="warning" title={`${plural(access.blockedCount, "server")} can't use ${provider.name}`}>
          <p>They require it, but the list leaves them out, so their calls are refused until their team or the server is listed.</p>
          <ul>
            {access.blocked.map((x) => (
              <li key={x.id}>
                <TextLink render={<Link to="/admin/servers/$serverId" params={{ serverId: x.id }} />}>{`${x.teamSlug} / ${x.slug}`}</TextLink>
              </li>
            ))}
          </ul>
          {access.blockedCount > access.blocked.length && <p>{`and ${access.blockedCount - access.blocked.length} more.`}</p>}
        </Alert>
      )}
      <SettingsSection title="Who may use it" description="Checked when a team saves a requirement, when a person allows a server to use their account, and on every call, including an agent's.">
        <RadioGroup<AccessMode> legend="Access" value={form.accessMode} onValueChange={(v) => setForm((f) => ({ ...f, accessMode: v }))} options={modeOptions} disabled={!isAdmin} />
        {empty && (
          <Alert tone="info">
            Nobody is listed, so no team or server can require {provider.name} yet. Add the teams or servers that should.
          </Alert>
        )}
      </SettingsSection>
      <SettingsSection title="Teams" description="Every server of a listed team, now and later.">
        <Field label="Teams" description={restrict ? effectText : "Used again when the provider is restricted."}>
          <Combobox
            multiple
            items={withChosen(teamOptions, form.teamIds, known)}
            value={form.teamIds}
            onValueChange={(v) => setForm((f) => ({ ...f, teamIds: v }))}
            placeholder="Search teams"
            chipsLabel="Listed teams"
            listLabel="Teams"
            disabled={!isAdmin}
          />
        </Field>
      </SettingsSection>
      <SettingsSection title="Servers" description="Single servers, whatever their team. Use it for one server instead of its whole team.">
        <Field label="Servers" description="Search by name.">
          <Combobox
            multiple
            filter={null}
            items={withChosen(serverOptions, form.serverIds, known)}
            value={form.serverIds}
            onValueChange={(v) => setForm((f) => ({ ...f, serverIds: v }))}
            onInputValueChange={setServerText}
            placeholder="Search servers"
            chipsLabel="Listed servers"
            listLabel="Servers"
            disabled={!isAdmin}
          />
        </Field>
      </SettingsSection>
    </SettingsPage>
  );
}
