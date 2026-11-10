/* A destination's delivery log: its last 50 deliveries (kept 14 days) with outcome, attempts, HTTP status and the error. */
import { useQuery } from "@tanstack/react-query";
import { ErrorAlert } from "@/components/ui/alert/alert";
import { StatusBadge } from "@/components/ui/badge/badge";
import { Button } from "@/components/ui/button/button";
import { Dialog } from "@/components/ui/dialog/dialog";
import { Loading } from "@/components/ui/spinner/spinner";
import { Table, Td, Tr } from "@/components/ui/table/table";
import s from "../../../pages/shared.module.css";
import { RelativeTime } from "../../templates/relative-time";
import { eventLabel } from "../events";
import { type Destination, type DestinationScope, deliveriesQuery } from "./api";
import { deliveryStateLabels, deliveryStateTone, errorClassText } from "./labels";

export function DeliveriesDialog({ scope, destination, onClose }: { scope: DestinationScope; destination: Destination; onClose: () => void }) {
  const log = useQuery(deliveriesQuery(scope, destination.id));
  const rows = log.data ?? [];
  return (
    <Dialog
      open
      onOpenChange={(o) => !o && onClose()}
      title={`Delivery log: ${destination.name}`}
      description="The last 50 deliveries, newest first, kept for 14 days. Test messages aren't listed. Messages are never shown here, only how they went."
      size="xl"
      footer={<Button onClick={onClose}>Close</Button>}
    >
      {log.isLoading ? (
        <Loading label="Loading deliveries…" />
      ) : log.error ? (
        <ErrorAlert error={log.error} title="Couldn't load the delivery log" onRetry={() => void log.refetch()} />
      ) : (
        <Table
          caption={`Deliveries to ${destination.name}`}
          columns={["When", "Event", "Outcome", "Attempts", "HTTP", "Error"]}
          density="compact"
          stack
          empty={rows.length === 0 ? <p className={s.muted}>Nothing was sent to this destination in the last 14 days.</p> : undefined}
        >
          {rows.map((d) => (
            <Tr key={d.id}>
              <Td nowrap>
                <RelativeTime value={d.createdAt} />
              </Td>
              <Td>{eventLabel(d.event)}</Td>
              <Td>
                <StatusBadge tone={deliveryStateTone[d.state]}>{deliveryStateLabels[d.state]}</StatusBadge>
                {d.state === "pending" && d.nextAttemptAt && (
                  <span className={s.secondary}>
                    Next try <RelativeTime value={d.nextAttemptAt} />
                  </span>
                )}
              </Td>
              <Td numeric>{d.attempts}</Td>
              <Td numeric>{d.httpStatus ?? "—"}</Td>
              <Td>{d.errorClass ? errorClassText(d.errorClass) : <span className={s.muted}>—</span>}</Td>
            </Tr>
          ))}
        </Table>
      )}
    </Dialog>
  );
}
