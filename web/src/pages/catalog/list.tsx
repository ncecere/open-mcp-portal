/*
 * Catalog (everyone signed in, with or without a team): the MCP servers
 * teams published, with the owning team, what each offers (approved
 * capabilities only) and its health. Search in ?q=, filtered by the server.
 * On a phone, what a server offers moves under its name. A server whose team records call contents carries the
 * "Records call contents" badge, as on its page, and one whose people each
 * sign in to its own service (authMode oauth) the "Sign-in per person" badge.
 */
import { useInfiniteQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Library } from "lucide-react";
import { api, type Schemas, unwrap } from "../../api/client";
import { catalogKey } from "../../api/queries";
import { CaptureBadge } from "../../components/capture";
import { HealthBadge, SignInBadge } from "../../components/servers/badges";
import { countsText, healthLabels } from "../../components/servers/labels";
import { CountsCell } from "../../components/servers/server-columns";
import { ListPage, timeColumn, useListFilters } from "../../components/templates/list-page";
import { terms } from "../../lib/terms";
import { Alert } from "@/components/ui/alert/alert";
import { CellText, type DataTableColumn } from "@/components/ui/data-table/data-table";
import { TextLink } from "@/components/ui/text-link/text-link";
import { NARROW_QUERY, useMediaQuery } from "@/lib/bitop-utils";
import s from "../shared.module.css";
import { useDebounced } from "../admin/hooks";
import c from "./catalog.module.css";

type Server = Schemas["CatalogServer"];

const link = (x: Server) => <Link to="/catalog/$serverId" params={{ serverId: x.id }} />;

const columns = (narrow: boolean): DataTableColumn<Server>[] => [
  {
    id: "name",
    header: "Server",
    accessor: (x) => x.name,
    rowHeader: true,
    hideable: false,
    sortable: true,
    cell: (x) => (
      <CellText
        className={s.compactCell}
        primary={
          <>
            <TextLink render={link(x)}>{x.name}</TextLink>
            {x.capturePayloads && (
              <>
                {" "}
                <CaptureBadge />
              </>
            )}
            {(x.authMode === "oauth" || x.authMode === "person_secret") && (
              <>
                {" "}
                <SignInBadge authMode={x.authMode} />
              </>
            )}
          </>
        }
        secondary={narrow ? `${x.teamName} · ${countsText(x.counts)}` : x.teamName}
      />
    ),
  },
  {
    id: "description",
    header: "Description",
    accessor: (x) => x.description,
    cell: (x) =>
      x.description ? (
        <span className={c.description} title={x.description}>
          {x.description}
        </span>
      ) : (
        <span className={s.muted}>—</span>
      ),
    defaultHiddenNarrow: true,
  },
  { id: "offers", header: "Offers", accessor: (x) => countsText(x.counts), defaultHiddenNarrow: true, cell: (x) => <CountsCell counts={x.counts} /> },
  { id: "health", header: "Health", accessor: (x) => healthLabels[x.health.status], sortable: true, cell: (x) => <HealthBadge health={x.health} since={false} /> },
  { ...timeColumn<Server>("publishedAt", "Published", (x) => x.publishedAt), defaultHidden: true },
];

/** How people get to use what's in the catalog. */
export const gatewaysNote = "The catalog shows what each server offers. To use its tools, people connect through a gateway, which is where access is granted.";

export function CatalogPage() {
  const { query } = useListFilters();
  const q = useDebounced(query.trim());
  const narrow = useMediaQuery(NARROW_QUERY);
  const servers = useInfiniteQuery({
    queryKey: [...catalogKey, "list", q],
    queryFn: async ({ pageParam }) => unwrap(await api.GET("/v1/catalog/servers", { params: { query: { q: q || undefined, cursor: pageParam, limit: 50 } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
  });
  const items = servers.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <ListPage<Server>
      id="catalog"
      title={terms.catalog}
      description="The company's MCP servers: published by the teams that run them, with the capabilities that were approved."
      notices={<Alert tone="info">{gatewaysNote}</Alert>}
      caption="Published MCP servers"
      columns={columns(narrow)}
      data={items}
      getRowId={(x) => x.id}
      rowLabel={(x) => x.name}
      search={{ label: "Search the catalog", placeholder: "Name, team or description" }}
      manual
      loading={servers.isLoading}
      error={servers.error}
      onRetry={() => void servers.refetch()}
      rowActions={(x) => [{ label: "Open", render: link(x) }]}
      empty={
        q
          ? { icon: <Library />, title: "No servers match." }
          : { icon: <Library />, title: "Nothing in the catalog yet.", description: "Teams publish their MCP servers here. Each one appears once it's approved (or published by a team allowed to self-publish)." }
      }
      tableProps={{ columnsMenuMin: 5, loadMore: { hasMore: Boolean(servers.hasNextPage), loading: servers.isFetchingNextPage, onLoadMore: () => void servers.fetchNextPage() } }}
    />
  );
}
