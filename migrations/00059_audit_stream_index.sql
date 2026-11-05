-- +goose NO TRANSACTION
-- +goose Up
-- A completed index is cheap to retain; an interrupted invalid build must be removed.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS (SELECT 1 FROM pg_catalog.pg_index WHERE indexrelid=to_regclass('public.audit_log_stream_idx') AND NOT indisvalid) THEN
  DROP INDEX public.audit_log_stream_idx;
 END IF;
END $$;
-- +goose StatementEnd
CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_log_stream_idx ON public.audit_log(txid,id) INCLUDE(row_uid) WHERE txid IS NOT NULL;
-- +goose Down
SELECT 1;
