/*
 * One call record (/teams/$team/calls/$callId and /admin/calls/$callId): its
 * metadata, and when its contents were recorded (and the viewer may open
 * them), the Contents card that loads them only on request. Rows of every
 * call list link here. A refusal (403: a team member below admin) is
 * explained, with nothing to retry.
 */
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";
import { ApiError, api, unwrap } from "../../api/client";
import { isNotFound, NotFoundState } from "../not-found";
import { PageSkeleton } from "../page-skeleton";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Badge } from "@/components/ui/badge/badge";
import { Card } from "@/components/ui/card/card";
import { DescriptionList } from "@/components/ui/description-list/description-list";
import { EmptyState } from "@/components/ui/empty-state/empty-state";
import { Stack } from "@/components/ui/layout/layout";
import { PageHeader } from "@/components/ui/page-header/page-header";
import { TextLink } from "@/components/ui/text-link/text-link";
import { Time } from "@/components/ui/time/time";
import s from "../../pages/shared.module.css";
import { OutcomeBadge } from "./badges";
import { CallPayloadCard, PayloadElsewhere, type PayloadScope } from "./call-payload";
import g from "./call.module.css";
import { CallError, principalDetail, principalName, useProviderName } from "./calls-table";
import { identitySentHelp, identitySentLabel, type McpCall } from "./labels";

/** The query of one call, by scope (also the breadcrumb's). */
export const callQuery = (scope: PayloadScope, callId: number) => ({
  queryKey: scope.kind === "team" ? ["team", scope.team, "calls", callId] : ["admin", "calls", "one", callId],
  queryFn: async () =>
    scope.kind === "team"
      ? unwrap(await api.GET("/v1/teams/{team}/calls/{callId}", { params: { path: { team: scope.team, callId } } }))
      : unwrap(await api.GET("/v1/admin/calls/{callId}", { params: { path: { callId } } })),
  enabled: Number.isSafeInteger(callId) && callId > 0,
});

const bytes = (n: number) => `${n.toLocaleString()} bytes`;

function Ref({ refd, link }: { refd: McpCall["gateway"] | undefined; link?: ReactNode }) {
  if (!refd) return <span className={s.muted}>—</span>;
  if (!refd.exists) return <span>{`${refd.name} (deleted)`}</span>;
  return link ?? <span>{refd.name}</span>;
}

function Provider({ slug, serverName }: { slug: string; serverName?: string }) {
  return <>{useProviderName(slug, serverName)}</>;
}

type Props = {
  scope: PayloadScope;
  callId: string;
  /** May open recorded contents here (team owners and admins; platform staff in Admin). */
  canViewPayload: boolean;
  /**
   * Where to open the contents instead (platform staff on a team's page, whose team record never says "captured":
   * the caller decides when to show it). Shown in place of the Contents card when canViewPayload is false.
   */
  elsewhere?: ReactNode;
};

/** Who reads call records, for a refusal. */
const refusedText = {
  team: { title: "Call records are for the team's owners and admins.", description: "Ask one of them if you need the details of this call." },
  admin: { title: "Call records in Admin are for platform admins and auditors.", description: "Ask a platform admin if you need access." },
};

function Refused({ scope }: { scope: PayloadScope }) {
  const t = refusedText[scope.kind];
  return (
    <Stack gap={6} className={s.page}>
      <PageHeader title="No access to this call" />
      <Card>
        <EmptyState icon={<ShieldAlert />} title={t.title} description={t.description} />
      </Card>
    </Stack>
  );
}

export function CallPage({ scope, callId, canViewPayload, elsewhere }: Props) {
  const id = Number(callId);
  const call = useQuery(callQuery(scope, id));
  if (call.isLoading) return <PageSkeleton />;
  if (isNotFound(call.error) || !(Number.isSafeInteger(id) && id > 0)) return <NotFoundState what="object" />;
  if (call.error instanceof ApiError && call.error.status === 403) return <Refused scope={scope} />;
  if (!call.data) return <ErrorAlert error={call.error} title="Couldn't load this call" onRetry={() => void call.refetch()} />;
  const c = call.data;
  const gatewayLink =
    scope.kind === "admin" && c.gateway.exists ? <TextLink render={<Link to="/admin/gateways/$gatewayId" params={{ gatewayId: c.gateway.id }} />}>{c.gateway.name}</TextLink> : undefined;
  return (
    <Stack gap={6} className={s.page}>
      <PageHeader
        title={<span className={g.title}>{c.exposedName ?? c.method}</span>}
        meta={
          <span className={s.badges}>
            <OutcomeBadge outcome={c.outcome} />
            {c.captured && (
              <Badge tone="info" size="sm">
                Contents recorded
              </Badge>
            )}
          </span>
        }
        description={`A ${c.method} call through ${c.gateway.name}, by ${principalName(c.principal)}.`}
      />
      <Card title="Details">
        <DescriptionList
          dividers
          items={[
            { label: "When", value: <Time value={c.occurredAt} format="datetime" /> },
            { label: "Who", value: [principalName(c.principal), c.principal.email, principalDetail(c.principal)].filter(Boolean).join(" · ") },
            { label: "Method", value: <code className={s.mono}>{c.method}</code> },
            ...(c.exposedName ? [{ label: "Called", value: <code className={s.mono}>{c.exposedName}</code> }] : []),
            { label: "Gateway", value: <Ref refd={c.gateway} link={gatewayLink} /> },
            { label: "Server", value: <Ref refd={c.server} /> },
            {
              label: "Outcome",
              value: (
                <span>
                  <OutcomeBadge outcome={c.outcome} />
                  {c.errorClass && <CallError code={c.errorClass} />}
                </span>
              ),
            },
            ...(c.providerSlug ? [{ label: "Account", value: <Provider slug={c.providerSlug} serverName={c.server?.name} /> }] : []),
            {
              label: "Identity token",
              value: (
                <span>
                  {identitySentLabel(c)} <span className={s.muted}>{identitySentHelp[identitySentLabel(c)]}</span>
                </span>
              ),
            },
            { label: "Time", value: `${c.latencyMs.toLocaleString()} ms` },
            { label: "Size", value: `${bytes(c.requestBytes)} in · ${bytes(c.responseBytes)} out` },
            ...(c.clientName ? [{ label: "Client", value: c.clientName }] : []),
            { label: "Request ID", value: <code className={s.mono}>{c.requestId}</code> },
          ]}
        />
      </Card>
      {canViewPayload ? c.captured && <CallPayloadCard scope={scope} callId={c.id} /> : elsewhere && <PayloadElsewhere>{elsewhere}</PayloadElsewhere>}
    </Stack>
  );
}
