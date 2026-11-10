/*
 * Admin → Audit log: the platform audit log as a ListPage with server
 * filters in the URL (area or action, target type, person or "System", date
 * range), a simple change in one line under its action, sign-ins hidden by
 * default (?signins=show shows them), CSV export, and each entry in a
 * RecordPage with a before/after diff.
 */
import { useInfiniteQuery } from "@tanstack/react-query";
import { FileClock } from "lucide-react";
import { api, unwrap, type Schemas } from "@/api/client";
import { changeSummary } from "@/components/audit/changes";
import { AuditTeam } from "@/components/audit/record";
import { TokenKindBadge } from "@/components/audit/actor";
import { actionLabel, areaOptions, targetTypeLabel, targetTypeLabels } from "@/components/audit/labels";
import { actedVia, actorName, personFilter, systemPersonOption, tokenPersonOption } from "@/components/audit/actors";
import { AuditTarget } from "@/components/audit/target";
import { ListPage, timeColumn, useListFilters } from "@/components/templates/list-page";
import { useRecordParam } from "@/components/templates/record-page";
import { CellText, type DataTableColumn } from "@/components/ui/data-table/data-table";
import type { Facet } from "@/components/ui/filter-bar/filter-bar";
import { Switch } from "@/components/ui/switch/switch";
import { terms } from "@/lib/terms";
import { useSearchParams } from "@/lib/url-search";
import s from "../../shared.module.css";
import { AuditEntryPage } from "./audit-record";
import { dateFacet, ExportButton, noMatches, one, rangeWindow, usePeopleOptions } from "./common";
import l from "./audit.module.css";

type Entry = Schemas["AuditEntry"];

/** ?signins=show turns off the default "Hide sign-ins". */
export const SIGNINS_PARAM = "signins";

function useFacets(): Facet<Entry>[] {
  const people = usePeopleOptions();
  return [
    { id: "action", label: "Area", type: "select", placeholder: "All areas, or type an action", options: areaOptions(true) },
    {
      id: "target",
      label: "Target type",
      type: "select",
      placeholder: "Any target",
      options: Object.entries(targetTypeLabels)
        .sort((a, b) => a[1].localeCompare(b[1]))
        .map(([value, label]) => ({ value, label })),
    },
    { id: "person", label: "Person", type: "select", placeholder: "Anyone", options: [systemPersonOption, tokenPersonOption, ...people] },
    dateFacet<Entry>(),
  ];
}

/** The action, and a simple change in one line under it ("Role Member → Editor"), else its code. */
export function ActionCell({ entry }: { entry: Entry }) {
  const summary = changeSummary(entry);
  return <CellText primary={actionLabel(entry.action, entry)} secondary={summary ?? <span className={s.mono}>{entry.action}</span>} />;
}

const columns: DataTableColumn<Entry>[] = [
  { ...timeColumn<Entry>("occurredAt", "When", (e) => e.occurredAt), sortable: false },
  {
    id: "who",
    header: "Who",
    accessor: (e) => actorName(e.actor, e),
    cell: (e) => (
      <span className={e.actor.kind === "system" ? s.muted : s.primary} title={e.actor.email ?? undefined}>
        {actorName(e.actor, e)}
        {e.actor.kind === "automation_token" ? (
          <span className={s.secondary}>
            <TokenKindBadge actor={e.actor} />
          </span>
        ) : (
          actedVia(e) && <span className={s.secondary}>{actedVia(e)}</span>
        )}
      </span>
    ),
  },
  { id: "action", header: "Action", accessor: (e) => actionLabel(e.action, e), rowHeader: true, cell: (e) => <ActionCell entry={e} /> },
  {
    id: "target",
    header: "Target",
    accessor: (e) => e.targetLabel ?? targetTypeLabel(e.targetType),
    // A sign-in's target is the person who signed in: say nothing twice.
    cell: (e) =>
      e.action.startsWith("auth.") ? (
        <span className={s.muted}>—</span>
      ) : (
        <span className={l.target}>
          <AuditTarget entry={e} scope={{ kind: "platform" }} />
        </span>
      ),
  },
  { id: "team", header: "Team", accessor: (e) => e.teamName ?? "", cell: (e) => (e.teamId ? <AuditTeam entry={e} /> : <span className={s.muted}>—</span>) },
  { id: "request", header: "Request ID", accessor: "requestId", muted: true, defaultHidden: true, cell: (e) => <span className={s.mono}>{e.requestId}</span> },
];

const pageSize = 50;

export function AdminAuditPage() {
  const facets = useFacets();
  const { values } = useListFilters(facets);
  const [params, setParams] = useSearchParams();
  const showSignIns = params.get(SIGNINS_PARAM) === "show";
  const record = useRecordParam();
  const action = one(values, "action");
  const query = {
    action: action || undefined,
    // Hiding sign-ins doesn't fight an explicit "Sign-in" action filter.
    excludeAction: !showSignIns && action !== "auth." ? "auth." : undefined,
    targetType: one(values, "target") || undefined,
    ...personFilter(one(values, "person")),
    ...rangeWindow(values),
  };
  const fetchPage = async (cursor?: string, limit = pageSize) => unwrap(await api.GET("/v1/admin/audit", { params: { query: { ...query, cursor, limit } } }));
  const log = useInfiniteQuery({
    queryKey: ["admin", "audit", query],
    queryFn: ({ pageParam }) => fetchPage(pageParam),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
  });
  const items = log.data?.pages.flatMap((p) => p.items) ?? [];
  const open = items.find((e) => String(e.id) === record.id);
  const setShow = (show: boolean) =>
    setParams((p) => {
      const out = new URLSearchParams(p);
      if (show) out.set(SIGNINS_PARAM, "show");
      else out.delete(SIGNINS_PARAM);
      return out;
    });

  return (
    <>
      <ListPage<Entry>
        id="admin-audit"
        title={terms.auditLog}
        description="Every administrative and membership change on the platform, and every sign-in: who, what, when and how."
        caption={terms.auditLog}
        columns={columns}
        data={items}
        getRowId={(e) => String(e.id)}
        rowLabel={(e) => `${actionLabel(e.action, e)} ${e.targetLabel ?? ""}`.trim()}
        facets={facets}
        manual
        loading={log.isLoading}
        error={log.error}
        onRetry={() => void log.refetch()}
        onRowClick={(e) => record.open(String(e.id))}
        empty={{ icon: <FileClock />, title: "No audit entries yet." }}
        tableProps={{
          noResults: noMatches,
          facetCounts: false,
          loadMore: { hasMore: Boolean(log.hasNextPage), loading: log.isFetchingNextPage, onLoadMore: () => void log.fetchNextPage() },
          toolbar: (
            <div className={l.toolbar}>
              <Switch label="Hide sign-ins" checked={!showSignIns} disabled={action === "auth."} onCheckedChange={(v) => setShow(!v)} />
              <ExportButton
                filename="audit-log.csv"
                fetchPage={(cursor) => fetchPage(cursor, 200)}
                header={["occurredAt", "actor", "actorEmail", "action", "targetType", "targetId", "target", "teamId", "requestId", "before", "after", "metadata", "via", "viaName", "clientIp"]}
                row={(e) => [
                  e.occurredAt,
                  actorName(e.actor, e),
                  e.actor.email ?? "",
                  e.action,
                  e.targetType,
                  e.targetId,
                  e.targetLabel ?? "",
                  e.teamId ?? "",
                  e.requestId,
                  e.before ?? "",
                  e.after ?? "",
                  e.metadata,
                  e.via?.kind ?? "",
                  e.via?.name ?? "",
                  e.clientIp ?? "",
                ]}
              />
            </div>
          ),
        }}
      />
      <AuditEntryPage id={record.id} listed={open} onClose={record.close} />
    </>
  );
}
