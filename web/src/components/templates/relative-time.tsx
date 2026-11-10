/*
 * A relative date ("3 hours ago") with the full date as a tooltip. Its own small module: the app shell uses it
 * (the bell's notification rows), and must not pull the list template and its DataTable into the entry chunk.
 */
import { Time } from "@/components/ui/time/time";
import { formatDate, toDate } from "@/lib/bitop-format";
import { needsCalendarDay, relativeDay } from "@/lib/relative-day";

/** A relative date cell ("3 hours ago"), with the full date as a tooltip. */
export function RelativeTime({ value }: { value: string | Date | null | undefined }) {
  // Days count by the calendar ("yesterday" is the day before today, v0.4.2 US-07).
  const date = needsCalendarDay(value) ? toDate(value) : undefined;
  if (date)
    return (
      <time dateTime={date.toISOString()} title={formatDate(date, { style: "long" })}>
        {relativeDay(date)}
      </time>
    );
  return <Time value={value} format="relative" fallback="—" />;
}
