-- +goose Up
-- Replace migration 35's writer-side singleton mutex without changing applied
-- history. Authority writers append independently; only short approval
-- transactions fence authority tables. No fence may survive network I/O.
CREATE SEQUENCE public.approval_context_events_event_id_seq AS bigint MINVALUE 1 NO CYCLE;
CREATE TABLE public.approval_context_events (
    event_id bigint PRIMARY KEY DEFAULT nextval('public.approval_context_events_event_id_seq'::regclass)
        CHECK (event_id > 0)
);
ALTER SEQUENCE public.approval_context_events_event_id_seq OWNED BY public.approval_context_events.event_id;
REVOKE ALL ON TABLE public.approval_context_events FROM PUBLIC;
REVOKE ALL ON SEQUENCE public.approval_context_events_event_id_seq FROM PUBLIC;

-- One deliberate invalidation, including any pre-existing request snapshot.
-- bigint overflow aborts the migration rather than reusing an old epoch.
UPDATE public.approval_context SET epoch = greatest(epoch,
    coalesce((SELECT max(context_epoch) FROM public.approval_requests), 0)) + 1 WHERE id = 1;

-- A single MVCC snapshot sees either the old base + journal or the compacted
-- base + remaining journal. SUM (not MAX/sequence last_value) is essential:
-- the transaction with the older sequence allocation can commit last.
-- Numeric accumulation and a checked bigint cast fail closed on overflow.
-- +goose StatementBegin
CREATE FUNCTION public.omp_current_approval_context() RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE current_epoch bigint;
BEGIN
    SELECT (c.epoch::numeric + coalesce((SELECT sum(event_id) FROM public.approval_context_events), 0))::bigint
        INTO STRICT current_epoch FROM public.approval_context c WHERE c.id = 1;
    RETURN current_epoch;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.omp_current_approval_context() FROM PUBLIC;

-- Preserve 35's explicit semantic field comparisons, but never acquire the
-- central epoch row. A rolled-back mutation leaves only a sequence gap.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.approval_authority_changed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE old_authority jsonb; new_authority jsonb;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        SELECT jsonb_object_agg(key,value) INTO old_authority FROM jsonb_each(to_jsonb(OLD)) WHERE key = ANY(TG_ARGV);
        SELECT jsonb_object_agg(key,value) INTO new_authority FROM jsonb_each(to_jsonb(NEW)) WHERE key = ANY(TG_ARGV);
        IF old_authority IS NOT DISTINCT FROM new_authority THEN RETURN NULL; END IF;
    END IF;
    INSERT INTO public.approval_context_events DEFAULT VALUES;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.approval_authority_changed() FROM PUBLIC;

-- An authorization-code reconnect is new authority even when scopes and
-- status are unchanged. Ordinary same-scope refresh leaves connected_at alone.
DROP TRIGGER approval_authority_changed ON public.provider_connections;
CREATE TRIGGER approval_authority_changed AFTER INSERT OR UPDATE OR DELETE ON public.provider_connections
    FOR EACH ROW EXECUTE FUNCTION public.approval_authority_changed('id','user_id','provider_id','status','scopes','connected_at');

-- Same interface, conservatively exclusive for both modes. EXCLUSIVE also
-- conflicts with SELECT FOR UPDATE/KEY SHARE's ROW SHARE table lock. NOWAIT
-- is mandatory: never wait while holding a partial fence on a writer that
-- already owns a different authority row/table. A busy fence aborts with
-- 55P03; callers must roll back, not spend an approval or dispatch upstream.
-- No existing user/connection rows are locked by this helper. Human actor
-- KEY SHARE may be taken first (a transaction can upgrade its own table lock).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.omp_lock_approval_context(exclusive boolean) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE current_epoch bigint; event_count bigint; event_sum numeric;
BEGIN
    IF exclusive IS NULL THEN RAISE EXCEPTION 'lock mode is required' USING ERRCODE = '22023'; END IF;
    -- Explicit, fully qualified and alphabetical; keep in step with all
    -- approval_authority_changed triggers, including oauth_tokens.
    LOCK TABLE
        public.api_key_gateways,
        public.api_keys,
        public.approval_context_events,
        public.approval_rule_approvers,
        public.approval_rules,
        public.auth_provider_servers,
        public.auth_provider_teams,
        public.auth_providers,
        public.capture_settings,
        public.gateway_capabilities,
        public.gateway_grants,
        public.gateways,
        public.mcp_capabilities,
        public.mcp_server_credentials,
        public.mcp_server_machine_oauth,
        public.mcp_server_tls,
        public.mcp_servers,
        public.oauth_grants,
        public.oauth_tokens,
        public.person_secrets,
        public.provider_connections,
        public.provider_server_grants,
        public.service_account_key_gateways,
        public.service_account_keys,
        public.service_accounts,
        public.service_connection_accounts,
        public.service_connection_server_grants,
        public.service_connections,
        public.team_members,
        public.teams,
        public.users
    IN EXCLUSIVE MODE NOWAIT;

    -- All authority writers are now excluded, including uncommitted trigger
    -- inserts. Only this owner-definer path can prune the runtime-read-only
    -- journal. Base increment + delete commit atomically, preserving the total.
    SELECT count(*), coalesce(sum(event_id), 0) INTO event_count, event_sum FROM public.approval_context_events;
    IF event_count > 1000 THEN
        UPDATE public.approval_context SET epoch = (epoch::numeric + event_sum)::bigint WHERE id = 1;
        IF NOT FOUND THEN RAISE EXCEPTION 'approval context singleton missing'; END IF;
        DELETE FROM public.approval_context_events;
    END IF;
    current_epoch := public.omp_current_approval_context();
    RETURN current_epoch;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.omp_lock_approval_context(boolean) FROM PUBLIC;

-- +goose Down
-- Forward-only: restoring the old trigger reintroduces writer deadlocks.
SELECT 1;
