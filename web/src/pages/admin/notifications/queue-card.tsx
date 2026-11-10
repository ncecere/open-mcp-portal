/*
 * Admin › Notifications › Delivery: the dispatcher's heartbeat (when it last ran, every how often), what waits in the
 * queue, failures in the last 24 hours and destinations stopped automatically. A dispatcher that hasn't run for much
 * longer than its interval is flagged: nothing is being delivered.
 */
import { Link } from "@tanstack/react-router";
import type { Schemas } from "@/api/client";
import { RelativeTime } from "@/components/templates/relative-time";
import { Alert } from "@/components/ui/alert/alert";
import { Card } from "@/components/ui/card/card";
import { DescriptionList } from "@/components/ui/description-list/description-list";
import { Stack } from "@/components/ui/layout/layout";
import { TextLink } from "@/components/ui/text-link/text-link";

type Settings = Schemas["NotificationSettings"];

/** The dispatcher counts as stalled after this many of its intervals (at least 2 minutes) without a run. */
export function dispatcherStalled(queue: Settings["queue"], now = Date.now()): boolean {
  if (!queue.lastRunAt) return false;
  const limit = Math.max(queue.intervalSeconds * 5, 120) * 1000;
  return now - new Date(queue.lastRunAt).getTime() > limit;
}

export function QueueCard({ settings }: { settings: Settings }) {
  const { queue, webhooks, email } = settings;
  const stalled = dispatcherStalled(queue);
  return (
    <Card title="Delivery" description="The loop that sends notifications runs on one replica, every few seconds.">
      <Stack gap={4}>
        {stalled && (
          <Alert tone="danger" title="The delivery loop hasn't run for a while">
            It last ran <RelativeTime value={queue.lastRunAt} /> and should run every {queue.intervalSeconds} seconds. Notifications are queued, not lost, but nothing is being sent. Check that a replica is running
            and its logs.
          </Alert>
        )}
        {webhooks.stopped > 0 && (
          <Alert tone="warning" title={`${webhooks.stopped} ${webhooks.stopped === 1 ? "destination was" : "destinations were"} stopped after repeated failures`}>
            Open the destination&apos;s delivery log to see why, fix the receiver and turn it back on. Platform destinations are below; a team&apos;s are in its{" "}
            <TextLink render={<Link to="/admin/teams" />}>Team settings › Notifications</TextLink>.
          </Alert>
        )}
        <DescriptionList
          size="sm"
          items={[
            { label: "Dispatcher last ran", value: queue.lastRunAt ? <RelativeTime value={queue.lastRunAt} /> : "Not yet" },
            { label: "Waiting to send", value: queue.pending.toLocaleString() },
            { label: "Oldest waiting", value: queue.oldestPendingAt ? <RelativeTime value={queue.oldestPendingAt} /> : "" },
            { label: "Failed in 24 hours", value: `${queue.failedLast24h.toLocaleString()} (email ${email.failedLast24h.toLocaleString()})` },
            { label: "Webhook destinations", value: `${webhooks.platformDestinations.toLocaleString()} platform, ${webhooks.teamDestinations.toLocaleString()} team` },
          ]}
        />
      </Stack>
    </Card>
  );
}
