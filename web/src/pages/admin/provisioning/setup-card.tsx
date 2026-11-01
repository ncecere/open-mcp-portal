/*
 * Provisioning setup: bind a directory to the configured OIDC issuer, switch it on or off and choose the enrollment
 * policy. Platform admins change it; auditors read. Shows the SCIM base URL to give the identity provider.
 */
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { V02ErrorAlert } from "../../../components/errors";
import { Alert } from "@/components/ui/alert/alert";
import { Button } from "@/components/ui/button/button";
import { Card } from "@/components/ui/card/card";
import { CopyField } from "@/components/ui/copy-field/copy-field";
import { DescriptionList } from "@/components/ui/description-list/description-list";
import { Stack } from "@/components/ui/layout/layout";
import { RadioGroup } from "@/components/ui/radio-group/radio-group";
import { Switch } from "@/components/ui/switch/switch";
import { toast } from "@/components/ui/toast/toast";
import { type Directory, type Enrollment, createDirectory, provisioningKey, updateDirectory } from "./api";

const enrollmentOptions: { value: Enrollment; label: string; description: string }[] = [
  {
    value: "optional",
    label: "Optional",
    description: "Someone new without a provisioned account can still sign in, unmanaged. A later directory push doesn't take them over.",
  },
  {
    value: "required",
    label: "Required",
    description: "Someone new can sign in only with an active provisioned account. People who already signed in keep signing in.",
  },
];

export function SetupCard({ directory, canEdit }: { directory: Directory | null; canEdit: boolean }) {
  const qc = useQueryClient();
  const [enabled, setEnabled] = useState(directory?.enabled ?? false);
  const [enrollment, setEnrollment] = useState<Enrollment>(directory?.enrollment ?? "optional");
  const save = useMutation({
    mutationFn: () => (directory ? updateDirectory({ enabled, enrollment }, directory.revision) : createDirectory({ enabled, enrollment })),
    onSuccess: () => toast.success(directory ? "Provisioning saved" : "Provisioning set up"),
    onSettled: () => void qc.invalidateQueries({ queryKey: provisioningKey }),
  });
  const changed = !directory || enabled !== directory.enabled || enrollment !== directory.enrollment;
  return (
    <Card
      title="Directory"
      description="An identity provider creates, updates, deactivates and deletes people and groups through SCIM 2.0. Sign-in stays single sign-on."
      actions={
        canEdit ? (
          <Button size="sm" disabled={!changed} loading={save.isPending} onClick={() => save.mutate()}>
            {directory ? "Save" : "Set up provisioning"}
          </Button>
        ) : undefined
      }
    >
      <Stack gap={4}>
        {directory && !directory.issuerMatches && (
          <Alert tone="warning" title="Single sign-on uses another issuer now">
            This directory is bound to {directory.issuer}. It can&apos;t be enabled while sign-in uses a different issuer.
          </Alert>
        )}
        {directory && (
          <DescriptionList
            items={[
              { label: "Bound to issuer", value: <span>{directory.issuer}</span> },
              { label: "Status", value: directory.enabled ? "Enabled" : "Off" },
            ]}
          />
        )}
        {directory && <CopyField label="SCIM base URL" name="SCIM base URL" value={directory.scimBaseUrl} description="Give this to the identity provider with a provisioning token." />}
        <Switch label="Enabled" description="While off, the directory can't push changes and sign-in isn't gated." checked={enabled} disabled={!canEdit} onCheckedChange={setEnabled} />
        <RadioGroup<Enrollment> legend="Enrollment of new people" value={enrollment} onValueChange={setEnrollment} disabled={!canEdit} options={enrollmentOptions} />
        <Alert tone="info" title="How people are linked">
          A provisioned account links to someone only when its externalId equals the subject single sign-on issues for them. Configure the identity provider to send that subject as externalId.
          Email addresses never link accounts. Platform admins and team owners are never directory managed: keep an unmanaged admin for break-glass access.
        </Alert>
        <V02ErrorAlert error={save.error} title="Couldn't save provisioning" />
      </Stack>
    </Card>
  );
}
