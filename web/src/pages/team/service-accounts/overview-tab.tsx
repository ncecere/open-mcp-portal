/*
 * A service account's Overview: its role (what minimum roles it passes),
 * who answers for it, and what its keys reach now (decision 23): the team's
 * own gateways, linked, and the platform gateways granted to the team (a
 * team grant covers its service accounts; there are no grants to one
 * account), each with what it reaches with its role
 * (GET .../service-accounts/{id}/gateways). Capabilities that need a
 * person's account (a provider requirement) aren't reached: service accounts
 * are refused them (decision 29), so they're counted apart and noted.
 */
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { capabilityCount } from "../../../components/gateways/labels";
import { serviceAccountsCant } from "../../../components/providers/labels";
import { plural } from "../../../lib/format";
import { terms } from "../../../lib/terms";
import { useCurrentUser } from "../../../session";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { Badge } from "@/components/ui/badge/badge";
import { Card } from "@/components/ui/card/card";
import { DescriptionList } from "@/components/ui/description-list/description-list";
import { Loading } from "@/components/ui/spinner/spinner";
import { Table, Td, Tr } from "@/components/ui/table/table";
import { TextLink } from "@/components/ui/text-link/text-link";
import { Time } from "@/components/ui/time/time";
import s from "../../shared.module.css";
import { useTeam } from "../common";
import { RelayCard } from "./relay-card";
import {
  type AccountGateway,
  accountAccessText,
  accountGatewaysQuery,
  roleExplanation,
  roleLabel,
  type ServiceAccount,
  type ServiceAccountAbilities,
  serviceAccountRoleHelp,
} from "./labels";

type Props = { account: ServiceAccount; abilities: ServiceAccountAbilities };

export function OverviewTab({ account }: Props) {
  const { team } = useTeam();
  return (
    <>
      <Card title="Role" description={roleExplanation}>
        <DescriptionList
          dividers
          items={[
            {
              label: "Role",
              value: (
                <span>
                  <Badge tone={account.role === "editor" ? "info" : "neutral"}>{roleLabel(account.role)}</Badge> <span className={s.secondary}>{serviceAccountRoleHelp[account.role]}</span>
                </span>
              ),
            },
            { label: "Responsible", value: `The owners and admins of ${team.name}. The account stays when the person who created it leaves.` },
            { label: "Created", value: <Time value={account.createdAt} /> },
            ...(account.createdByName ? [{ label: "Created by", value: account.createdByName }] : []),
            { label: "Last changed", value: <Time value={account.updatedAt} /> },
          ]}
        />
      </Card>
      <AccessCard account={account} />
      <RelayCard account={account} />
    </>
  );
}

function AccessCard({ account }: { account: ServiceAccount }) {
  const { slug, team } = useTeam();
  const me = useCurrentUser();
  const staff = me.capabilities.platformAdmin || me.capabilities.platformAuditor;
  const gateways = useQuery(accountGatewaysQuery(slug, account.id));
  const items = gateways.data ?? [];
  const needsPerson = items.reduce((n, g) => n + (g.needsPersonCount ?? 0), 0);
  return (
    <Card
      title="Access"
      description={`The gateways its keys reach now, with its ${roleLabel(account.role).toLowerCase()} role: the gateways of ${team.name}, and the platform gateways granted to ${team.name}. A key can be limited to some of them.`}
      flush={items.length > 0}
    >
      {gateways.isLoading && <Loading label="Loading the gateways it can use…" />}
      <ErrorAlert error={gateways.error} title="Couldn't load the gateways it can use" onRetry={() => void gateways.refetch()} />
      {gateways.isSuccess && items.length === 0 && (
        <p className={s.muted}>{`It can't use any gateway yet. Add a gateway to ${team.name}, or ask a platform admin to grant a platform gateway to ${team.name}.`}</p>
      )}
      {items.length > 0 && (
        <Table caption={`Gateways ${account.name} can use`} columns={["Gateway", "Access", "It reaches"]} stack>
          {items.map((g) => (
            <Tr key={g.id}>
              <Td>
                <GatewayName gateway={g} team={slug} staff={staff} />
                <span className={`${s.secondary} ${s.mono}`}>{g.slug}</span>
              </Td>
              <Td>{accountAccessText(g, team.name)}</Td>
              <Td>
                {capabilityCount(g.capabilityCount)}
                {(g.needsPersonCount ?? 0) > 0 && <span className={s.secondary}>{`${plural(g.needsPersonCount!, "more needs", "more need")} a person's account`}</span>}
              </Td>
            </Tr>
          ))}
        </Table>
      )}
      {needsPerson > 0 && (
        <p className={items.length > 0 ? `${s.muted} ${s.pad}` : s.muted}>
          {`${plural(needsPerson, "capability", "capabilities")} on these gateways ${needsPerson === 1 ? "needs" : "need"} a person's account, such as their GitHub account. ${serviceAccountsCant} Its keys get an error for them; people call them with their own keys or connected apps.`}
        </p>
      )}
      <p className={items.length > 0 ? `${s.muted} ${s.pad}` : s.muted}>
        {`A grant of a platform gateway to ${team.name} covers its service accounts; grants to people or SSO groups don't. `}
        {staff && <TextLink render={<Link to="/admin/gateways" search={{ ownerKind: "platform" }} />}>See platform gateways in Admin › {terms.gateways}</TextLink>}
      </p>
    </Card>
  );
}

/** The gateway's name: linked to the team's gateway, or (for platform staff) to the platform gateway in Admin. */
function GatewayName({ gateway: g, team, staff }: { gateway: AccountGateway; team: string; staff: boolean }) {
  if (g.ownerKind === "team") {
    return (
      <TextLink render={<Link to="/teams/$team/gateways/$gatewayId" params={{ team: g.teamSlug ?? team, gatewayId: g.id }} />} className={s.primary}>
        {g.name}
      </TextLink>
    );
  }
  if (staff) {
    return (
      <TextLink render={<Link to="/admin/gateways/$gatewayId" params={{ gatewayId: g.id }} />} className={s.primary}>
        {g.name}
      </TextLink>
    );
  }
  return <span className={s.primary}>{g.name}</span>;
}
