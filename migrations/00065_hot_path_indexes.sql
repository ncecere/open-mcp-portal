-- +goose NO TRANSACTION
-- +goose Up
-- Three indexes for statements that scanned a growing table (measured on
-- 300k calls, 180k outbox rows):
--   * notification_outbox (event_id): the foreign key to notification_events
--     cascades on delete and had no index, so purging old events scanned the
--     outbox once per deleted event (17 s per 1,000-event batch; 9 ms with it).
--   * mcp_calls (outcome, id DESC) WHERE outcome <> 'ok': the call log
--     filtered by a rare outcome read the whole table. Successful calls,
--     nearly all rows, stay out of the index.
--   * notification_outbox (last_attempt_at) WHERE state = 'failed': the
--     admin overview polls for a recent failed email every minute.
-- Additive only: the previous release runs unchanged against this schema.
-- A completed index is cheap to retain; an interrupted invalid build must be removed.
-- +goose StatementBegin
DO $$
DECLARE name text;
BEGIN
 FOREACH name IN ARRAY ARRAY['notification_outbox_event_idx', 'mcp_calls_outcome_idx', 'notification_outbox_failed_idx'] LOOP
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_index WHERE indexrelid = to_regclass('public.' || name) AND NOT indisvalid) THEN
   EXECUTE 'DROP INDEX public.' || quote_ident(name);
  END IF;
 END LOOP;
END $$;
-- +goose StatementEnd
CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_outbox_event_idx ON public.notification_outbox (event_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS mcp_calls_outcome_idx ON public.mcp_calls (outcome, id DESC) WHERE outcome <> 'ok';
CREATE INDEX CONCURRENTLY IF NOT EXISTS notification_outbox_failed_idx ON public.notification_outbox (last_attempt_at) WHERE state = 'failed';
-- +goose Down
SELECT 1;
