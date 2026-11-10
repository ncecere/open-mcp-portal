/*
 * Team settings › Audit log: the team's audit log on a ListPage, filtered on
 * the server by area or action, person (or "System") and a date range (all
 * in the URL), with Load more. The action's label, with a simple change
 * under it ("Role Member → Editor"); its code is on the record page. Each
 * entry opens in a RecordPage (?record=<id>, fetched by id so links from the
 * overview work) with the before/after field by field. Sign-ins aren't team
 * entries, so there is no "Hide sign-ins" here.
 */
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Eye, FileClock } from "lucide-react";
import { api, unwrap, type Schemas } from "../../../api/client";
import { membersQuery } from "../../../api/queries";
import { changeSummary } from "../../../components/audit/changes";
import { TokenKindBadge } from "../../../components/audit/actor";
import { actionLabel, actorName, areaOptions, auditKey, personFilter, systemPersonOption, tokenPersonOption, tokenKindLabel, viaLabel } from "../../../components/audit/labels";
import { auditSections } from "../../../components/audit/record";
import { AuditTarget } from "../../../components/audit/target";
import { ListPage, useListFilters } from "../../../components/templates/list-page";
import { RelativeTime } from "../../../components/templates/relative-time";
import { RecordPage, useRecordParam } from "../../../components/templates/record-page";
import { terms } from "../../../lib/terms";
import { CellText, type DataTableColumn } from "@/components/ui/data-table/data-table";
import type { Facet, FilterValue } from "@/components/ui/filter-bar/filter-bar";
import { Time } from "@/components/ui/time/time";
import { rangeWindow } from "../../../lib/date-window";
import s from "../../shared.module.css";
import { useTeam } from "../common";

type Entry = Schemas["AuditEntry"];

function who(e: Entry) {
  const { actor } = e;
  if (actor.kind === "api_key") return `API key${actor.apiKeyName ? `: ${actor.apiKeyName}` : ""}`;
  if (actor.kind === "automation_token") return tokenKindLabel(actor);
  return actor.kind === "user" && actor.displayName ? actor.email : undefined;
}

/** A select facet's value (one option). */
const first = (v: FilterValue | undefined) => (Array.isArray(v) ? v[0] : undefined);

function useFacets(team: string): Facet<Entry>[] {
  const members = useQuery(membersQuery(team));
  return [
    { id: "action", label: "Area", type: "select", placeholder: "All areas, or type an action", options: areaOptions(false) },
    {
      id: "person",
      label: "Person",
      type: "select",
      placeholder: "Anyone",
      options: [systemPersonOption, tokenPersonOption, ...(members.data ?? []).map((m) => ({ value: m.user.id, label: m.user.displayName || m.user.email }))],
    },
    { id: "range", label: "Date", type: "date-range" },
  ];
}

export function TeamAuditLog() {
  const { slug: team, role } = useTeam();
  const scope = { kind: "team" as const, team };
  const facets = useFacets(team);
  const filters = useListFilters(facets);
  const record = useRecordParam();
  const query = {
    action: first(filters.values.action),
    ...personFilter(first(filters.values.person)),
    ...rangeWindow(filters.values),
  };
  const log = useInfiniteQuery({
    queryKey: [...auditKey(scope), "list", query],
    queryFn: async ({ pageParam }) => unwrap(await api.GET("/v1/teams/{team}/audit", { params: { path: { team }, query: { ...query, cursor: pageParam, limit: 50 } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
  });
  const items = log.data?.pages.flatMap((p) => p.items) ?? [];
  const filtered = Object.values(query).some(Boolean);

  const columns: DataTableColumn<Entry>[] = [
    { id: "when", header: "When", accessor: (e) => new Date(e.occurredAt), cell: (e) => (
        <span className={s.nowrap}>
          <RelativeTime value={e.occurredAt} />
        </span>
      ) },
    { id: "who", header: "Who", accessor: (e) => actorName(e.actor, e), cell: (e) => <CellText primary={actorName(e.actor, e)} secondary={e.actor.kind === "automation_token" ? <TokenKindBadge actor={e.actor} /> : who(e)} /> },
    {
      id: "action",
      header: "Action",
      accessor: (e) => actionLabel(e.action, e),
      rowHeader: true,
      cell: (e) => <CellText primary={actionLabel(e.action, e)} secondary={changeSummary(e) ?? undefined} />,
    },
    { id: "target", header: "Target", accessor: (e) => e.targetLabel ?? e.targetType, cell: (e) => <AuditTarget entry={e} scope={{ ...scope, member: Boolean(role) }} /> },
  ];

  return (
    <>
      <ListPage<Entry>
        id="team-audit"
        caption={terms.auditLog}
        columns={columns}
        data={items}
        getRowId={(e) => String(e.id)}
        rowLabel={(e) => `${actionLabel(e.action, e)}, ${new Date(e.occurredAt).toLocaleString()}`}
        facets={facets}
        manual
        onRowClick={(e) => record.open(String(e.id))}
        rowActions={(e) => [{ label: "View details", icon: <Eye aria-hidden />, onSelect: () => record.open(String(e.id)) }]}
        loading={log.isLoading}
        error={log.error}
        onRetry={() => void log.refetch()}
        empty={{ icon: <FileClock />, title: filtered ? "No entries match these filters." : "No audit entries yet." }}
        tableProps={{
          loadMore: { hasMore: Boolean(log.hasNextPage), loading: log.isFetchingNextPage, onLoadMore: () => void log.fetchNextPage() },
        }}
      />
      <AuditEntryPage id={record.id} loaded={items.find((e) => String(e.id) === record.id)} onClose={record.close} />
    </>
  );
}

function AuditEntryPage({ id, loaded, onClose }: { id?: string; loaded?: Entry; onClose: () => void }) {
  const { slug: team, role } = useTeam();
  const entry = useQuery({
    queryKey: [...auditKey({ kind: "team", team }), "entry", id],
    queryFn: async () => unwrap(await api.GET("/v1/teams/{team}/audit/{entryId}", { params: { path: { team, entryId: Number(id) } } })),
    enabled: Boolean(id) && !loaded && /^\d+$/.test(id ?? ""),
    initialData: loaded,
  });
  const e = entry.data;
  const badId = Boolean(id) && !loaded && !/^\d+$/.test(id ?? "");
  return (
    <RecordPage
      open={Boolean(id)}
      onClose={onClose}
      title={e ? actionLabel(e.action, e) : "Audit entry"}
      description="An entry of this team's audit log."
      loading={entry.isLoading && !badId}
      error={badId ? new Error("This audit entry doesn't exist, or the link is wrong.") : entry.error}
      facts={
        e
          ? [
              { label: "When", value: <Time value={e.occurredAt} format="datetime" /> },
              { label: "Who", value: [actorName(e.actor, e), who(e)].filter(Boolean).join(" · ") },
              ...(e.via ? [{ label: "How", value: viaLabel(e.via) }] : []),
              { label: "Action", value: <code className={s.mono}>{e.action}</code> },
              { label: "Target", value: <AuditTarget entry={e} scope={{ kind: "team", team, member: Boolean(role) }} /> },
              { label: "Request", value: e.requestId ? <code className={s.mono}>{e.requestId}</code> : undefined },
            ]
          : []
      }
      sections={e ? auditSections(e) : []}
    />
  );
}
