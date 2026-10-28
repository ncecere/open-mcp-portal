-- +goose Up
-- Retention floors must measure elapsed days, not calendar days in a caller's
-- TimeZone (which can include a POSIX 24-hour DST jump). Preserve the existing
-- fixed search_path, owner, ACLs, and function bodies from migration 00032.
ALTER FUNCTION public.omp_purge_audit_log(integer, integer) SET TimeZone = 'UTC';
ALTER FUNCTION public.omp_purge_mcp_calls(timestamptz, integer, integer) SET TimeZone = 'UTC';

-- +goose Down
-- Forward-only: reverting TimeZone would reopen the retention-floor boundary.
SELECT 1;
