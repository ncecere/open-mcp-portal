/*
 * Admin › Provisioning (/admin/provisioning): SCIM 2.0 directory provisioning (docs/scim.md). Platform admins set it
 * up, create the identity provider's token, adopt or unlink people and map groups to team roles; auditors read.
 */
import { useQuery } from "@tanstack/react-query";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import { Loading } from "@/components/ui/spinner/spinner";
import { adminOnly } from "@/lib/terms";
import s from "../../shared.module.css";
import { useIsPlatformAdmin } from "../hooks";
import { directoryQuery } from "./api";
import { MappingsCard } from "./mappings-card";
import { PeopleCard } from "./people-card";
import { SetupCard } from "./setup-card";
import { TokensCard } from "./tokens-card";

export function AdminProvisioningPage() {
  const isAdmin = useIsPlatformAdmin();
  const dir = useQuery(directoryQuery);
  return (
    <Stack gap={6} className={s.page}>
      <PageHeader title="Provisioning" description={`Let an identity provider manage who has access, through SCIM 2.0. ${isAdmin ? "" : adminOnly}`.trim()} />
      {dir.isLoading ? (
        <Loading label="Loading provisioning…" />
      ) : dir.error ? (
        <ErrorAlert error={dir.error} title="Couldn't load provisioning" onRetry={() => void dir.refetch()} />
      ) : (
        <>
          <SetupCard key={dir.data?.revision ?? 0} directory={dir.data ?? null} canEdit={isAdmin} />
          {dir.data && (
            <>
              <TokensCard canEdit={isAdmin} />
              <PeopleCard canEdit={isAdmin} />
              <MappingsCard canEdit={isAdmin} />
            </>
          )}
        </>
      )}
    </Stack>
  );
}
