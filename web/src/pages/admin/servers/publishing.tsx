/*
 * Admin → Publishing: the platform's default publishing policy, one
 * explicit save (If-Match; edits survive a change made elsewhere) after a
 * confirmation, like a team's override. A team's own override is set on its
 * admin page (Teams › a team › Settings).
 */
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { api, ifMatch, type Schemas, unwrap } from "@/api/client";
import { GovernanceSettingsCard, governanceSettingsKey } from "@/components/servers/governance-settings";
import { type PublishPolicy, policyHelp, policyLabels } from "@/components/servers/labels";
import { PageSkeleton } from "@/components/page-skeleton";
import { useRevisionForm } from "@/components/templates/revision-form";
import { SettingsPage, SettingsSection } from "@/components/templates/settings-page";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { AlertDialog } from "@/components/ui/dialog/dialog";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import { RadioGroup } from "@/components/ui/radio-group/radio-group";
import { TextLink } from "@/components/ui/text-link/text-link";
import { toast } from "@/components/ui/toast/toast";
import { adminOnly, terms } from "@/lib/terms";
import s from "../../shared.module.css";
import { useIsPlatformAdmin } from "../hooks";

export const publishingKey = ["admin", "publishing"];

/** The policies as radio options, each with what it means. */
export const policyOptions = (who = "the team's") =>
  (["approval_required", "self_publish"] as PublishPolicy[]).map((p) => ({ value: p, label: policyLabels[p], description: policyHelp(p, who) }));

export function AdminPublishingPage() {
  const settings = useQuery({ queryKey: publishingKey, queryFn: async () => unwrap(await api.GET("/v1/admin/settings/publishing")) });
  const governance = useQuery({ queryKey: governanceSettingsKey, queryFn: async () => unwrap(await api.GET("/v1/admin/settings/governance")) });
  const isAdmin = useIsPlatformAdmin();
  return (
    <Stack gap={6} className={s.page}>
      <PageHeader title={terms.publishing} description="How teams' MCP servers reach the company catalog. Team-private servers never need approval for the team's own use." />
      {settings.isLoading ? (
        <PageSkeleton />
      ) : settings.data ? (
        <PublishingForm saved={settings.data} />
      ) : (
        <ErrorAlert error={settings.error} title="Couldn't load the publishing settings" onRetry={() => void settings.refetch()} />
      )}
      {governance.data ? (
        <GovernanceSettingsCard key={governance.data.revision} saved={governance.data} canEdit={isAdmin} />
      ) : (
        governance.error && <ErrorAlert error={governance.error} title="Couldn't load the review settings" onRetry={() => void governance.refetch()} />
      )}
    </Stack>
  );
}

function PublishingForm({ saved }: { saved: Schemas["PublishingSettings"] }) {
  const qc = useQueryClient();
  const isAdmin = useIsPlatformAdmin();
  const [confirming, setConfirming] = useState(false);
  const base = { defaultPolicy: saved.defaultPolicy };
  const [form, setForm, revision] = useRevisionForm(base, saved.revision, { labels: { defaultPolicy: "Default policy" }, choices: { defaultPolicy: policyLabels } });
  const save = useMutation({
    mutationFn: async () => unwrap(await api.PUT("/v1/admin/settings/publishing", { params: { header: ifMatch(saved.revision) }, body: form })),
    // A failure shows on the save bar, which also handles a change made elsewhere (412).
    onSettled: () => setConfirming(false),
    onSuccess: (st) => {
      qc.setQueryData(publishingKey, st);
      // Teams that follow the default have a new effective policy.
      void qc.invalidateQueries({ queryKey: ["admin"] });
      toast.success("Publishing settings saved", `The default is now ${policyLabels[st.defaultPolicy].toLowerCase()}.`);
    },
  });
  return (
    <SettingsPage
      revision={revision}
      canEdit={isAdmin}
      readOnlyNote={adminOnly}
      dirty={form.defaultPolicy !== saved.defaultPolicy}
      saving={save.isPending}
      error={save.error}
      onSave={() => setConfirming(true)}
      onDiscard={() => setForm(base)}
    >
      <AlertDialog
        open={confirming}
        onOpenChange={(o) => {
          if (!o) setConfirming(false);
        }}
        tone="primary"
        title={`Make ${policyLabels[form.defaultPolicy].toLowerCase()} the default?`}
        description={`${policyHelp(form.defaultPolicy)} It applies to every team without its own policy. Servers already published or waiting for review stay as they are.`}
        confirmLabel="Save policy"
        busy={save.isPending}
        onConfirm={() => save.mutate()}
      />
      <SettingsSection
        title="Default policy"
        description={
          <>
            For every team without its own policy. Set a team's own on its page in{" "}
            <TextLink render={<Link to="/admin/teams" />}>Teams</TextLink> (Settings tab).
          </>
        }
      >
        <RadioGroup<PublishPolicy>
          legend="Default publishing policy"
          options={policyOptions()}
          value={form.defaultPolicy}
          disabled={!isAdmin}
          onValueChange={(v) => setForm({ defaultPolicy: v })}
          variant="card"
        />
      </SettingsSection>
    </SettingsPage>
  );
}
