-- +goose Up
-- Keep the owner-authenticated previous binary working; restricted runtime
-- credentials require this binary's function-based retention path.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_class
               WHERE oid IN ('public.audit_log'::regclass, 'public.mcp_calls'::regclass)
                 AND relowner <> (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                  WHERE n.nspname = 'public'
                    AND p.proname IN ('audit_log_append_only', 'mcp_calls_append_only',
                                      'omp_purge_audit_log', 'omp_purge_mcp_calls')
                    AND p.proowner <> (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)) THEN
        RAISE EXCEPTION 'purge functions and protected tables must be owned by the migration role';
    END IF;
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.audit_log_append_only() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND (current_setting('omp.audit_purge', true) = 'on' OR current_setting('omg.audit_purge', true) = 'on')
       AND current_user = (SELECT r.rolname FROM pg_catalog.pg_class c
                           JOIN pg_catalog.pg_roles r ON r.oid = c.relowner WHERE c.oid = TG_RELID) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit_log is append-only';
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.mcp_calls_append_only() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE'
       AND (current_setting('omp.calls_purge', true) = 'on' OR current_setting('omg.calls_purge', true) = 'on')
       AND current_user = (SELECT r.rolname FROM pg_catalog.pg_class c
                           JOIN pg_catalog.pg_roles r ON r.oid = c.relowner WHERE c.oid = TG_RELID) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'mcp_calls is append-only';
END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.omp_purge_audit_log(days integer, batch_size integer) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    previous_flag text := current_setting('omp.audit_purge', true);
    deleted bigint;
BEGIN
    IF batch_size IS NULL OR batch_size < 1 OR batch_size > 100000 OR days IS NULL THEN
        RAISE EXCEPTION 'invalid purge arguments' USING ERRCODE = '22023';
    END IF;
    PERFORM set_config('omp.audit_purge', 'on', true);
    WITH doomed AS (
        SELECT id FROM public.audit_log
        WHERE occurred_at < now() - make_interval(days => greatest(30, least(days, 3650)))
        ORDER BY id LIMIT batch_size FOR UPDATE SKIP LOCKED
    ), removed AS (
        DELETE FROM public.audit_log WHERE id IN (SELECT id FROM doomed) RETURNING id
    ) SELECT count(*) INTO deleted FROM removed;
    PERFORM set_config('omp.audit_purge', coalesce(previous_flag, ''), true);
    RETURN deleted;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('omp.audit_purge', coalesce(previous_flag, ''), true);
    RAISE;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.omp_purge_audit_log(integer, integer) FROM PUBLIC;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.omp_purge_mcp_calls(watermark timestamptz, platform_days integer, batch_size integer) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    previous_flag text := current_setting('omp.calls_purge', true);
    safe_watermark timestamptz;
    deleted bigint;
BEGIN
    IF batch_size IS NULL OR batch_size < 1 OR batch_size > 100000 OR platform_days IS NULL THEN
        RAISE EXCEPTION 'invalid purge arguments' USING ERRCODE = '22023';
    END IF;
    SELECT date_trunc('hour', rolled_up_to, 'UTC') - interval '1 hour'
      INTO safe_watermark FROM public.usage_rollup_state WHERE id = 1;
    IF watermark IS NULL OR safe_watermark IS NULL THEN
        RETURN 0;
    END IF;
    safe_watermark := least(watermark, safe_watermark);
    PERFORM set_config('omp.calls_purge', 'on', true);
    WITH doomed AS (
        SELECT c.id FROM public.mcp_calls c
        LEFT JOIN public.teams gt ON gt.id = c.gateway_team_id
        LEFT JOIN public.teams st ON st.id = c.server_team_id
        WHERE c.occurred_at < safe_watermark
          AND c.occurred_at < now() - make_interval(days => greatest(1, least(3650, coalesce(least(
              CASE WHEN gt.id IS NOT NULL THEN coalesce((gt.retention_overrides ->> 'call_metadata')::integer, platform_days) END,
              CASE WHEN st.id IS NOT NULL THEN coalesce((st.retention_overrides ->> 'call_metadata')::integer, platform_days) END
          ), platform_days))))
        ORDER BY c.id LIMIT batch_size FOR UPDATE OF c SKIP LOCKED
    ), removed AS (
        DELETE FROM public.mcp_calls WHERE id IN (SELECT id FROM doomed) RETURNING id
    ) SELECT count(*) INTO deleted FROM removed;
    PERFORM set_config('omp.calls_purge', coalesce(previous_flag, ''), true);
    RETURN deleted;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('omp.calls_purge', coalesce(previous_flag, ''), true);
    RAISE;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.omp_purge_mcp_calls(timestamptz, integer, integer) FROM PUBLIC;

-- +goose Down
-- Forward-only: reverting these functions would reopen the privilege boundary.
SELECT 1;
