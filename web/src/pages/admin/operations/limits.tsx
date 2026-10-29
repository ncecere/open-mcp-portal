/*
 * Admin → Limits: requests per minute on /mcp/{slug} per person, per API key
 * or connected app, per service account and per gateway (decision 31). Each
 * has a platform default; the two teams can override also have a ceiling,
 * the most a team or gateway may be given (lowering it caps existing values,
 * counted under it). Staged edits, one Save with If-Match after a
 * confirmation; edits survive a change made elsewhere. Auditors read.
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { api, ifMatch, unwrap } from "@/api/client";
import { PageSkeleton } from "@/components/page-skeleton";
import { isRevisionConflict, useRevisionForm } from "@/components/templates/revision-form";
import { SettingsPage, SettingsSection } from "@/components/templates/settings-page";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { AlertDialog } from "@/components/ui/dialog/dialog";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import { Table, Td, Tr } from "@/components/ui/table/table";
import { TextLink } from "@/components/ui/text-link/text-link";
import { toast } from "@/components/ui/toast/toast";
import { plural } from "@/lib/format";
import { limitSettingsKey, limitSettingsQuery, parseRate, rateInput, rateKeyLabels, rateText } from "@/lib/limits";
import { adminOnly, terms } from "@/lib/terms";
import s from "../../shared.module.css";
import { useIsPlatformAdmin } from "../hooks";
import { LimitName, RateInput } from "./limit-fields";
import { formInvalid, type LimitRow, type LimitsForm, limitChanges, limitProblem, limitsFormOf, type PlatformLimit, rowErrors, stricter } from "./limits-form";
import o from "./operations.module.css";

export function AdminLimitsPage() {
  const settings = useQuery(limitSettingsQuery());
  return (
    <Stack gap={6} className={s.page}>
      <PageHeader
        title={terms.limits}
        description="How many requests per minute callers may send to gateways, counted across every replica. Over a limit, the client is told to try again shortly (HTTP 429) and the call is recorded as rate limited."
      />
      {settings.isLoading ? (
        <PageSkeleton />
      ) : settings.data ? (
        <LimitsSettings items={settings.data.items} revision={settings.data.revision} />
      ) : (
        <ErrorAlert error={settings.error} title="Couldn't load the limits" onRetry={() => void settings.refetch()} />
      )}
    </Stack>
  );
}

const rowText = (r: unknown) => {
  const row = r as LimitRow | undefined;
  return row ? `default ${row.def.trim() ? Number(row.def).toLocaleString() : "unlimited"}${row.ceil.trim() ? `, ceiling ${Number(row.ceil).toLocaleString()}` : ""}` : "";
};

function LimitsSettings({ items, revision: saved }: { items: PlatformLimit[]; revision: number }) {
  const qc = useQueryClient();
  const isAdmin = useIsPlatformAdmin();
  const [confirming, setConfirming] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const base = limitsFormOf(items);
  const labels = Object.fromEntries(items.map((it) => [it.key, it.label]));
  const [form, setForm, revision] = useRevisionForm<LimitsForm>(base, saved, { labels, format: (_k, v) => rowText(v) });
  const changes = limitChanges(items, form);
  const invalid = formInvalid(items, form);
  const save = useMutation({
    mutationFn: async () => unwrap(await api.PUT("/v1/admin/settings/limits", { params: { header: ifMatch(saved) }, body: { items: changes } })),
    onSettled: () => setConfirming(false),
    onError: (err) => {
      if (isRevisionConflict(err)) void qc.invalidateQueries({ queryKey: limitSettingsKey });
    },
    onSuccess: (st) => {
      setSubmitted(false);
      qc.setQueryData(limitSettingsKey, st);
      // Teams' and gateways' effective limits follow.
      void qc.invalidateQueries({ queryKey: ["admin"] });
      void qc.invalidateQueries({ queryKey: ["team"] });
      const capped = st.items.filter((it) => it.cappedTeams + it.cappedGateways + (it.cappedServers ?? 0) > 0);
      toast.success("Limits saved", capped.length ? `Capped by a ceiling: ${capped.map((it) => cappedText(it)).join("; ")}.` : "Every replica applies them within 30 seconds.");
    },
  });
  const problem = limitProblem(save.error);
  const set = (key: PlatformLimit["key"], row: LimitRow) => {
    if (save.error) save.reset();
    setForm((f) => ({ ...f, [key]: row }));
  };
  const tight = stricter(items, changes);
  return (
    <>
      <SettingsPage
        revision={revision}
        canEdit={isAdmin}
        readOnlyNote={adminOnly}
        dirty={JSON.stringify(form) !== JSON.stringify(base)}
        saving={save.isPending}
        error={problem ? undefined : save.error}
        saveDisabled={submitted && invalid}
        message={invalid ? "Not saved: fix the highlighted limits" : undefined}
        onSave={() => {
          setSubmitted(true);
          if (!invalid && changes.length > 0) setConfirming(true);
        }}
        onDiscard={() => {
          setForm(base);
          setSubmitted(false);
        }}
      >
        <SettingsSection
          title="Requests per minute"
          description={
            <>
              Empty means unlimited (or, for a ceiling, none). A team&apos;s own values are set on its page in <TextLink render={<Link to="/admin/teams" />}>Teams</TextLink>; a
              gateway&apos;s or upstream server&apos;s in its settings. Windows are whole minutes, so a burst across a minute&apos;s end can briefly reach twice a limit.
            </>
          }
        >
          <Table caption="Rate limits: defaults and ceilings" stack columns={["Limit", { label: "Default", width: "14rem" }, { label: "Ceiling", width: "14rem" }]}>
            {items.map((it) => (
              <LimitRowView
                key={it.key}
                it={it}
                f={form[it.key] ?? { def: "", ceil: "" }}
                isAdmin={isAdmin}
                shown={submitted}
                refused={problem?.key === it.key ? problem.message : undefined}
                onChange={(row) => set(it.key, row)}
              />
            ))}
          </Table>
        </SettingsSection>
      </SettingsPage>
      <AlertDialog
        open={confirming}
        onOpenChange={(open) => {
          if (!open) setConfirming(false);
        }}
        tone="primary"
        title="Save the rate limits?"
        description={`${plural(changes.length, "limit")} changed. Every replica applies them within 30 seconds; callers over a limit are refused until the next minute.`}
        confirmLabel="Save limits"
        busy={save.isPending}
        onConfirm={() => save.mutate()}
      >
        {tight.length > 0 && (
          <>
            <p>Stricter than before:</p>
            <ul className={o.list}>
              {tight.map((c) => (
                <li key={c.key}>{`${rateKeyLabels[c.key]}: default ${rateText(c.default)}${c.ceiling !== null ? `, ceiling ${rateText(c.ceiling)}` : ""}`}</li>
              ))}
            </ul>
          </>
        )}
      </AlertDialog>
    </>
  );
}

/** "2 teams and 1 gateway above Per gateway's ceiling". */
const cappedText = (it: PlatformLimit) =>
  `${[it.cappedTeams ? plural(it.cappedTeams, "team") : "", it.cappedGateways ? plural(it.cappedGateways, "gateway") : "", it.cappedServers ? plural(it.cappedServers, "server") : ""].filter(Boolean).join(" and ")} for ${it.label}`;

/** A ceiling typed lower than the saved one (or a first ceiling). */
const lowered = (next: number | null, prev: number | null) => next !== null && Number.isInteger(next) && (prev === null || next < prev);

type RowProps = { it: PlatformLimit; f: LimitRow; isAdmin: boolean; shown: boolean; refused?: string; onChange: (row: LimitRow) => void };

function LimitRowView({ it, f, isAdmin, shown, refused, onChange }: RowProps) {
  // A typed value is checked as it's typed; the default-above-ceiling rule once both are there or on Save.
  const errs = shown || f.def.trim() || f.ceil.trim() ? rowErrors(it, f) : {};
  const builtIn = rateInput(it.builtInDefault);
  const differs = isAdmin ? f.def.trim() !== builtIn : it.default !== it.builtInDefault;
  const capped = it.cappedTeams + it.cappedGateways + (it.cappedServers ?? 0) > 0;
  return (
    <Tr>
      <Td>
        <LimitName label={it.label} description={it.description}>
          {differs && (
            <span className={s.secondary}>
              Built-in default: {rateText(it.builtInDefault)}
              {isAdmin && (
                <>
                  {" "}
                  <Button size="sm" variant="ghost" aria-label={`Use the built-in default for ${it.label}`} onClick={() => onChange({ ...f, def: builtIn })}>
                    Use it
                  </Button>
                </>
              )}
            </span>
          )}
        </LimitName>
      </Td>
      <Td>
        {isAdmin ? (
          <RateInput label={`Default for ${it.label}`} value={f.def} placeholder="Unlimited" error={refused ?? errs.def} onChange={(v) => onChange({ ...f, def: v })} />
        ) : (
          rateText(it.default)
        )}
      </Td>
      <Td>
        {!it.teamOverridable ? (
          <span className={s.muted} title="Teams can't override this limit">
            Not overridable
          </span>
        ) : isAdmin ? (
          <RateInput label={`Ceiling for ${it.label}`} value={f.ceil} placeholder="No ceiling" error={errs.ceil} onChange={(v) => onChange({ ...f, ceil: v })} />
        ) : (
          rateText(it.ceiling, "No ceiling")
        )}
        {capped && <span className={s.secondary}>{`Caps ${cappedText(it).replace(/ for .*$/, "")}`}</span>}
        {it.teamOverridable && lowered(parseRate(f.ceil), it.ceiling) && <span className={s.secondary}>Teams and gateways above the new ceiling keep their values, capped to it.</span>}
      </Td>
    </Tr>
  );
}
