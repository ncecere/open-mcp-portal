/*
 * Relative dates by calendar day (v0.4.2 US-07): "yesterday" is the day before
 * today, whatever the hour, so a conversation from 10:19 PM two days ago reads
 * "2 days ago" like one from that morning, and agrees with the Today /
 * Yesterday / weekday headings (group-by-day.ts). Under a day, and from a week
 * on, bitop-format's rounding applies. A follow-up for bitop-ui's
 * formatRelativeTime itself.
 */
import { type DateInput, formatRelativeTime, toDate } from "@/lib/bitop-format";

const DAY = 86_400_000;

/** Local midnight of the date. Its own copy: importing the calendar component for it put the calendar in the entry chunk. */
const startOfDay = (d: Date) => new Date(d.getFullYear(), d.getMonth(), d.getDate());

/** Whole calendar days from `date` to `now` (positive in the past), by local midnight. */
export function calendarDays(date: Date, now: Date): number {
  return Math.round((startOfDay(now).getTime() - startOfDay(date).getTime()) / DAY);
}

/** Whether the calendar-day wording differs from bitop-format's for this date (then relativeDay's text is used). */
export function needsCalendarDay(value: DateInput | null | undefined, now = new Date()): boolean {
  const date = toDate(value);
  if (!date) return false;
  const days = calendarDays(date, now);
  return days >= 1 && days < 7 && relativeDay(date, now) !== formatRelativeTime(date, { now });
}

/** "5 minutes ago" today, "yesterday" / "3 days ago" by calendar day this week, "2 weeks ago" from there on. */
export function relativeDay(value: DateInput | null | undefined, now = new Date(), fallback = ""): string {
  const date = toDate(value);
  if (!date) return fallback;
  const days = calendarDays(date, now);
  const sameDayOrFuture = days <= 0;
  // Late last night still reads in hours ("3 hours ago") until it's half a day old.
  const recent = now.getTime() - date.getTime() < DAY / 2;
  if (sameDayOrFuture || recent || days >= 7) return formatRelativeTime(date, { now, fallback });
  try {
    return new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }).format(-days, "day");
  } catch {
    return fallback;
  }
}
