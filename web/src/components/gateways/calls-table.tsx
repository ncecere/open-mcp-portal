/*
 * Call records (metadata; contents only where a gateway or server records them) as a list: when,
 * who (a person with the key they used or "via" the connected app, or a
 * team's service account), what was called, through which gateway to which
 * server, the outcome (with why it failed, in words, and the auth provider
 * whose account the capability needed) and how long it took.
 * A gateway's Activity tab and Admin › Calls share the columns and the
 * outcome facet. On a phone, who and when (and the gateway) move under what
 * was called, so the outcome stays in view. What was called links to the
 * call's own page (`detail`), and a Contents column marks recorded calls.
 */
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Activity } from "lucide-react";
import type { ReactElement } from "react";
import { api, unwrap } from "../../api/client";
import { authProvidersQuery, serviceAccountsQuery } from "../../api/queries";
import { RelativeTime, timeColumn } from "../templates/list-page";
import { Badge } from "@/components/ui/badge/badge";
import { CellText, type DataTableColumn } from "@/components/ui/data-table/data-table";
import { EmptyState } from "@/components/ui/empty-state/empty-state";
import type { Facet, FacetOption } from "@/components/ui/filter-bar/filter-bar";
import { TextLink } from "@/components/ui/text-link/text-link";
import s from "../../pages/shared.module.css";
import { OutcomeBadge } from "./badges";
import { callErrorLabel, callOutcomes, identitySentHelp, identitySentLabel, type McpCall, outcomeLabels } from "./labels";

/** The Outcome facet (one value: the API takes one). */
export const outcomeFacet: Facet<McpCall> = {
  id: "outcome",
  label: "Outcome",
  type: "select",
  placeholder: "Any outcome",
  options: callOutcomes.map((o) => ({ value: o, label: outcomeLabels[o] })),
};

/** A team's service accounts as filter options (none without a team: service accounts belong to one). */
export function useServiceAccountOptions(team: string | undefined): FacetOption[] {
  const accounts = useQuery({ ...serviceAccountsQuery(team ?? ""), enabled: Boolean(team), staleTime: 60_000 });
  return (accounts.data ?? []).map((a) => ({ value: a.id, label: a.name }));
}

/**
 * Every team's service accounts as filter options for platform staff (the first 200 by name, of the chosen
 * team when there is one), named with their team: the facet's list is searchable.
 */
export function useAdminServiceAccountOptions(team: string | undefined): FacetOption[] {
  const accounts = useQuery({
    queryKey: ["admin", "service-accounts", "options", team ?? ""],
    queryFn: async () => unwrap(await api.GET("/v1/admin/service-accounts", { params: { query: { limit: 200, ...(team ? { team } : {}) } } })),
    staleTime: 60_000,
  });
  return (accounts.data?.items ?? []).map((a) => ({ value: a.id, label: `${a.name} (${a.teamSlug})` }));
}

/** The Service account facet (the API's serviceAccount filter). */
export function serviceAccountFacet(options: FacetOption[], placeholder = "Any service account"): Facet<McpCall> {
  return { id: "serviceAccount", label: "Service account", type: "select", placeholder, options };
}

const bytes = (n: number) => (n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KiB` : `${(n / 1024 / 1024).toFixed(1)} MiB`);

/** What was called: the exposed tool or prompt name, or the method for a list call. */
const what = (c: McpCall) => c.exposedName ?? c.method;

type Principal = McpCall["principal"];

/** Who made a call, in words: the person's or the service account's name. */
export const principalName = (p: Principal) => p.displayName || p.email || (p.kind === "service_account" ? "Service account" : "Unknown");

/**
 * How they called: "API key: Laptop", "via Claude Code" ("via Helper (unverified)" for an app that
 * registered itself: its name is its own claim), "Service account · platform-tools · Key: GitHub Actions"
 * ("Deleted service account · …" once the account is gone).
 */
export function principalDetail(p: Principal): string | undefined {
  switch (p.kind) {
    case "api_key":
      return p.apiKeyName ? `API key: ${p.apiKeyName}` : "API key";
    case "oauth":
      if (!p.oauthClientName) return "via a connected app";
      return p.oauthClientVerified === false ? `via ${p.oauthClientName} (unverified)` : `via ${p.oauthClientName}`;
    case "service_account":
      return [
        p.serviceAccountExists === false ? "Deleted service account" : "Service account",
        p.serviceAccountTeamSlug,
        p.apiKeyName ? `Key: ${p.apiKeyName}` : undefined,
      ]
        .filter(Boolean)
        .join(" · ");
    default:
      return undefined;
  }
}

const who = (c: McpCall) => principalName(c.principal);

/**
 * The agent behind a call an agent platform relayed: "Mail assistant via Pi Durable Platform · for Ada Lovelace",
 * with "(not present)" when the platform said the person wasn't there, or "no person named" for a call that is the
 * relay account's own.
 */
export function agentLine(c: Pick<McpCall, "agent">): string | undefined {
  const a = c.agent;
  if (!a) return undefined;
  const person = a.person ? a.person.displayName || a.person.email : undefined;
  const who = person ? `for ${person}${a.personPresent === false ? " (not present)" : ""}` : "no person named";
  return `${a.agentName || a.agentId} via ${a.platformName} · ${who}`;
}

/** A call's row name for screen readers: "service-status__get_status by Una User". */
export const callLabel = (c: McpCall) => `${c.exposedName ?? c.method} by ${who(c)}`;

/**
 * Who made the call: a person (title: their email), or a service account linked to its record (members and
 * staff read it); a deleted account is plain text, like a deleted gateway or server.
 */
function PrincipalCell({ c }: { c: McpCall }) {
  const p = c.principal;
  const detail = principalDetail(p);
  const agent = agentLine(c);
  const secondary = agent ? (
    <>
      {detail}
      <span className={s.secondary}>{agent}</span>
    </>
  ) : (
    detail
  );
  if (p.kind === "service_account" && p.serviceAccountId && p.serviceAccountTeamSlug && p.serviceAccountExists !== false) {
    const link = <Link to="/teams/$team/service-accounts/$serviceAccountId" params={{ team: p.serviceAccountTeamSlug, serviceAccountId: p.serviceAccountId }} />;
    return <CellText primary={<TextLink render={link}>{principalName(p)}</TextLink>} secondary={secondary} />;
  }
  return <CellText primary={<span title={p.email}>{principalName(p)}</span>} secondary={secondary} />;
}

/** On a phone: who, when (and through which gateway), under what was called. */
function NarrowLine({ call, gateway }: { call: McpCall; gateway: boolean }) {
  return (
    <span>
      {gateway && `${call.gateway.name} · `}
      {who(call)} · <RelativeTime value={call.occurredAt} />
    </span>
  );
}

/** Why a call failed, in words; the recorded code as its tooltip. */
export function CallError({ code }: { code: string }) {
  return (
    <span className={s.secondary} title={`Recorded as ${code}`}>
      {callErrorLabel(code)}
    </span>
  );
}

/** The prefix of a server-bound provider's slug (a server in oauth mode: people sign in to the server itself). */
const SERVER_PROVIDER_PREFIX = "mcp-";

/**
 * A recorded provider slug as the provider's name, from the providers people can connect (GET /v1/auth-providers).
 * A server-bound provider (slug mcp-…, never in that list) is named after the call's server; the slug itself is
 * shown for a platform provider that's turned off or gone.
 */
export function useProviderName(slug: string, serverName?: string) {
  const providers = useQuery({ ...authProvidersQuery(), enabled: Boolean(slug) });
  const known = providers.data?.find((p) => p.slug === slug)?.name;
  if (known) return known;
  if (serverName && slug.startsWith(SERVER_PROVIDER_PREFIX)) return serverName;
  return slug;
}

/** The provider's name in the Account column, with its slug as the tooltip. */
function ProviderName({ slug, serverName }: { slug: string; serverName?: string }) {
  return <span title={slug}>{useProviderName(slug, serverName)}</span>;
}

/** The auth provider whose account the capability needed (named when it's known, else its slug as recorded). */
function ProviderBadge({ slug, serverName }: { slug: string; serverName?: string }) {
  const name = useProviderName(slug, serverName);
  return (
    <span className={s.secondary}>
      <Badge size="sm" variant="outline" title="The account the capability needed">
        {`Account: ${name}`}
      </Badge>
    </span>
  );
}

type Opts = {
  gateway?: boolean;
  adminLinks?: boolean;
  /** The call's own page, as a link element (team: /teams/$team/calls/$callId; admin: /admin/calls/$callId). */
  detail?: (c: McpCall) => ReactElement;
  /** A phone-width window (NARROW_QUERY): When, Who and Gateway start hidden and show under Called instead. */
  narrow?: boolean;
};

export function callColumns({ gateway = false, adminLinks = false, detail, narrow = false }: Opts = {}): DataTableColumn<McpCall>[] {
  return [
    { ...timeColumn<McpCall>("occurredAt", "When", (c) => c.occurredAt), sortable: false, defaultHiddenNarrow: true },
    {
      id: "who",
      header: "Who",
      defaultHiddenNarrow: true,
      accessor: who,
      cell: (c) => <PrincipalCell c={c} />,
    },
    {
      id: "what",
      header: "Called",
      accessor: what,
      rowHeader: true,
      cell: (c) => (
        <CellText
          className={s.compactCell}
          wrap="anywhere"
          primary={detail ? <TextLink render={detail(c)} className={s.mono}>{what(c)}</TextLink> : <span className={s.mono}>{what(c)}</span>}
          secondary={narrow ? <NarrowLine call={c} gateway={gateway} /> : c.exposedName ? c.method : undefined}
        />
      ),
    },
    ...(gateway
      ? [
          {
            id: "gateway",
            header: "Gateway",
            accessor: (c: McpCall) => c.gateway.name,
            defaultHiddenNarrow: true,
            cell: (c: McpCall) =>
              adminLinks && c.gateway.exists ? (
                <TextLink render={<Link to="/admin/gateways/$gatewayId" params={{ gatewayId: c.gateway.id }} />}>{c.gateway.name}</TextLink>
              ) : (
                <span>
                  {c.gateway.name}
                  {!c.gateway.exists && <span className={s.secondary}>Deleted</span>}
                </span>
              ),
          },
        ]
      : []),
    {
      id: "server",
      header: "Server",
      accessor: (c) => c.server?.name ?? "",
      defaultHiddenNarrow: true,
      cell: (c) =>
        c.server ? (
          <span>
            {c.server.name}
            {!c.server.exists && <span className={s.secondary}>Deleted</span>}
          </span>
        ) : (
          <span className={s.muted}>—</span>
        ),
    },
    {
      id: "outcome",
      header: "Outcome",
      accessor: (c) => (c.errorClass ? `${outcomeLabels[c.outcome]}: ${callErrorLabel(c.errorClass)}` : outcomeLabels[c.outcome]),
      cell: (c) => (
        <span>
          <OutcomeBadge outcome={c.outcome} />
          {c.errorClass && <CallError code={c.errorClass} />}
          {c.providerSlug && <ProviderBadge slug={c.providerSlug} serverName={c.server?.name} />}
        </span>
      ),
    },
    {
      id: "provider",
      header: "Account",
      accessor: (c) => c.providerSlug ?? "",
      defaultHidden: true,
      cell: (c) => (c.providerSlug ? <ProviderName slug={c.providerSlug} serverName={c.server?.name} /> : <span className={s.muted}>—</span>),
    },
    {
      id: "identity",
      header: "Identity token",
      accessor: (c) => identitySentLabel(c),
      defaultHidden: true,
      cell: (c) => <span title={identitySentHelp[identitySentLabel(c)]}>{identitySentLabel(c)}</span>,
    },
    {
      id: "captured",
      header: "Contents",
      accessor: (c) => (c.captured ? "Recorded" : ""),
      defaultHiddenNarrow: true,
      cell: (c) =>
        c.captured ? (
          <Badge size="sm" tone="info" title="Its arguments and result were recorded; open the call to view them">
            Recorded
          </Badge>
        ) : (
          <span className={s.muted}>—</span>
        ),
    },
    { id: "latency", header: "Time", accessor: (c) => c.latencyMs, cell: (c) => <span className={s.nowrap}>{c.latencyMs.toLocaleString()} ms</span>, defaultHiddenNarrow: true },
    { id: "size", header: "Size", accessor: (c) => c.requestBytes + c.responseBytes, defaultHidden: true, cell: (c) => <span className={s.nowrap}>{`${bytes(c.requestBytes)} in · ${bytes(c.responseBytes)} out`}</span> },
    { id: "client", header: "Client", accessor: (c) => c.clientName ?? "", defaultHidden: true, cell: (c) => c.clientName ?? <span className={s.muted}>—</span> },
    { id: "request", header: "Request ID", accessor: "requestId", muted: true, defaultHidden: true, cell: (c) => <span className={s.mono}>{c.requestId}</span> },
  ];
}

export const noCalls = <EmptyState size="compact" icon={<Activity />} title="No calls match these filters." description="Clear a filter to see more." />;

/** What a call record holds: said once above every call list. */
export const callsPrivacy =
  "Each call is recorded as metadata: who called what, when, and how it went. Arguments and results are kept only for gateways and servers that record call contents (marked Recorded), and opening them is audited.";
