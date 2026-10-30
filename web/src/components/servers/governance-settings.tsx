/*
 * Admin › Publishing › Server reviews (decision 88): the days between
 * re-reviews of a published server for each sensitivity label (0: never), and
 * whether an overdue review also sends the server back to review. Off by
 * default: an overdue review then only notifies the team and shows in
 * attention lists, and nothing is ever unpublished. Own revision and own
 * Save, apart from the publishing policy's. Platform admins change it;
 * auditors read.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, ifMatch, type Schemas, staleMessage, unwrap } from "../../api/client";
import { Alert, ErrorAlert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { Field } from "@/components/ui/field/field";
import { NumberInput } from "@/components/ui/number-input/number-input";
import { Switch } from "@/components/ui/switch/switch";
import { toast } from "@/components/ui/toast/toast";
import { ApiError } from "../../api/client";
import { type Sensitivity, sensitivities, sensitivityLabels } from "./governance";
import m from "./servers.module.css";

export const governanceSettingsKey = ["admin", "governance-settings"];

type Settings = Schemas["GovernanceSettings"];

export function GovernanceSettingsCard({ saved, canEdit }: { saved: Settings; canEdit: boolean }) {
  const qc = useQueryClient();
  const [days, setDays] = useState<Record<Sensitivity, string>>(() => ({ ...saved.reviewIntervalDays }) as unknown as Record<Sensitivity, string>);
  const [ret, setRet] = useState(saved.returnOverdueToReview);
  const [revision] = useState(saved.revision);
  const parsed = Object.fromEntries(sensitivities.map((s) => [s, Number(days[s])])) as Record<Sensitivity, number>;
  const bad = sensitivities.find((s) => !/^\d+$/.test(String(days[s])) || parsed[s] > 3650);
  const dirty = ret !== saved.returnOverdueToReview || sensitivities.some((s) => String(days[s]) !== String(saved.reviewIntervalDays[s]));
  const save = useMutation({
    mutationFn: async () => unwrap(await api.PUT("/v1/admin/settings/governance", { params: { header: ifMatch(revision) }, body: { reviewIntervalDays: parsed, returnOverdueToReview: ret } })),
    onSuccess: (st) => {
      qc.setQueryData(governanceSettingsKey, st);
      void qc.invalidateQueries({ queryKey: ["admin"] });
      toast.success("Review settings saved", "Every published server's next review is counted again from its last approval.");
    },
  });
  const stale = save.error instanceof ApiError && save.error.status === 412;
  return (
    <Card title="Server reviews" description="How often a published server is reviewed again, by sensitivity. A server's next review is counted from its last approval; 0 means never.">
      <form
        className={m.stack}
        onSubmit={(e) => {
          e.preventDefault();
          if (!bad && dirty && canEdit) save.mutate();
        }}
      >
        <div className={m.fieldGrid}>
          {sensitivities.map((s) => (
            <Field key={s} label={`${sensitivityLabels[s]} servers`} description="Days between reviews" error={bad === s ? "Use a whole number of days from 0 to 3650." : undefined}>
              <NumberInput value={String(days[s])} maximumFractionDigits={0} disabled={!canEdit} onValueChange={(v) => setDays((d) => ({ ...d, [s]: v }))} />
            </Field>
          ))}
        </div>
        <Switch
          label="Send overdue servers back to review"
          description="Under approval_required a published server whose review is overdue goes back to a platform admin. Off: the team is told and the server shows in attention lists, and stays published. It is never unpublished."
          disabled={!canEdit}
          checked={ret}
          onCheckedChange={setRet}
        />
        {stale && (
          <Alert tone="warning" title="Changed elsewhere">
            {staleMessage} Reload the page to start from what is saved.
          </Alert>
        )}
        {save.error && !stale && <ErrorAlert error={save.error} title="Couldn't save the review settings" />}
        {canEdit ? (
          <div className={m.actions}>
            <Button type="submit" loading={save.isPending} disabled={!dirty || Boolean(bad) || stale}>
              Save review settings
            </Button>
          </div>
        ) : (
          <p>Platform admins change these settings.</p>
        )}
      </form>
    </Card>
  );
}
