/*
 * My gateways (/gateways): every gateway the person can connect to, why
 * (a member of its team, or a grant to their team, to them or to one of
 * their SSO groups, named), and how many capabilities it offers them right now.
 * On a phone, where it's from, what it offers and why the person has access
 * stack under its name, one column wide.
 */
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { KeyRound, Network } from "lucide-react";
import { myGatewaysQuery } from "../../api/queries";
import { CaptureBadge } from "../../components/capture";
import { accessLabel, capabilityCount, type MyGateway } from "../../components/gateways/labels";
import { ListPage } from "../../components/templates/list-page";
import { terms } from "../../lib/terms";
import { Badge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { CellText, type DataTableColumn } from "@/components/ui/data-table/data-table";
import { TextLink } from "@/components/ui/text-link/text-link";
import { NARROW_QUERY, useMediaQuery } from "@/lib/bitop-utils";
import s from "../shared.module.css";

/** Why the person may use it, as badges. */
export function AccessBadges({ gateway }: { gateway: Pick<MyGateway, "access" | "teamName" | "groups"> }) {
  return (
    <span className={s.badges}>
      {gateway.access.map((a) => (
        <Badge key={a} size="sm" tone={a === "team_member" ? "neutral" : "info"}>
          {a === "team_member" && gateway.teamName ? `Member of ${gateway.teamName}` : accessLabel(a, gateway.groups)}
        </Badge>
      ))}
    </span>
  );
}

const owner = (g: MyGateway) => (g.ownerKind === "team" ? (g.teamName ?? g.teamSlug ?? "Team") : "Platform");

const columns = (narrow: boolean): DataTableColumn<MyGateway>[] => [
  {
    id: "name",
    header: "Gateway",
    accessor: (g) => `${g.name} ${g.slug} ${g.description}`,
    rowHeader: true,
    hideable: false,
    sortable: true,
    cell: (g) => (
      <CellText
        className={s.compactCell}
        primary={
          <>
            <TextLink render={<Link to="/gateways/$gatewayId" params={{ gatewayId: g.id }} />}>{g.name}</TextLink>
            {g.capturesPayloads && (
              <>
                {" "}
                <CaptureBadge label="Records what you send" />
              </>
            )}
          </>
        }
        secondary={
          narrow ? (
            <>
              {`${owner(g)} · ${capabilityCount(g.capabilityCount)}`}
              <span className={s.secondary}>
                <AccessBadges gateway={g} />
              </span>
            </>
          ) : (
            <span className={s.mono}>{g.slug}</span>
          )
        }
      />
    ),
  },
  { id: "owner", header: "From", accessor: owner, sortable: true, defaultHiddenNarrow: true, cell: (g) => <CellText primary={owner(g)} secondary={g.ownerKind === "team" ? "Team gateway" : "Platform gateway"} /> },
  { id: "access", header: "Why you have access", accessor: (g) => g.access.map((a) => accessLabel(a, g.groups)).join(", "), defaultHiddenNarrow: true, cell: (g) => <AccessBadges gateway={g} /> },
  { id: "capabilities", header: "Offers you", accessor: (g) => g.capabilityCount, sortable: true, defaultHiddenNarrow: true, cell: (g) => <span className={s.nowrap}>{capabilityCount(g.capabilityCount)}</span> },
];

export function MyGatewaysPage() {
  const gateways = useQuery(myGatewaysQuery());
  const narrow = useMediaQuery(NARROW_QUERY);
  const keys = <div className={s.toolbar}>
    <Button variant="secondary" render={<Link to="/access-requests" />}>Request gateway access</Button>
    <Button variant="secondary" render={<Link to="/settings/api-keys" />}>
      <KeyRound aria-hidden /> {terms.apiKeys}
    </Button>
  </div>;
  return (
    <ListPage<MyGateway>
      id="my-gateways"
      title={terms.myGateways}
      description="The gateways you can connect your AI clients to. Each offers you only the tools, prompts and resources you may use."
      primaryAction={keys}
      caption={terms.myGateways}
      columns={columns(narrow)}
      data={gateways.data ?? []}
      getRowId={(g) => g.id}
      rowLabel={(g) => g.name}
      search={{ label: "Search gateways", placeholder: "Name, slug or description" }}
      loading={gateways.isLoading}
      error={gateways.error}
      onRetry={() => void gateways.refetch()}
      rowActions={(g) => [{ label: "Connect", render: <Link to="/gateways/$gatewayId" params={{ gatewayId: g.id }} /> }]}
      empty={{
        icon: <Network />,
        title: "No gateways for you yet.",
        description: "Your teams' gateways, and platform gateways shared with you, your team or your SSO groups, show up here. Ask a team owner or admin if you expected one.",
      }}
      tableProps={{ columnsMenuMin: 5 }}
    />
  );
}
