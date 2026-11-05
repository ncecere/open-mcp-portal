-- +goose NO TRANSACTION
-- +goose Up
-- A completed index is cheap to retain; an interrupted invalid build must be removed.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM pg_catalog.pg_index WHERE indexrelid=to_regclass('public.audit_log_stream_idx') AND NOT indisvalid) THEN
  DROP INDEX public.audit_log_stream_idx;
 END IF;
 IF EXISTS (SELECT 1 FROM pg_catalog.pg_index WHERE indexrelid=to_regclass('public.audit_log_history_idx') AND NOT indisvalid) THEN
  DROP INDEX public.audit_log_history_idx;
 END IF;
END $$;
-- +goose StatementEnd
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_log_stream_idx ON public.audit_log(txid,id) INCLUDE(row_uid) WHERE txid IS NOT NULL;
-- Pre-existing history only (new rows are always stamped): the sealer's history cursor probe.
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_log_history_idx ON public.audit_log(id) WHERE txid IS NULL;
-- +goose Down
SELECT 1;
