-- +goose Up
-- Previous releases inspect every public relation as ordinary runtime storage.
-- Keep the protected approval implementation outside that public contract.
-- Moving objects preserves their OIDs, ACLs, triggers, defaults and live data.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_class
               WHERE oid IN ('public.approval_context'::regclass,
                             'public.approval_context_events'::regclass,
                             'public.approval_context_events_event_id_seq'::regclass,
                             'public.approval_binding_keys'::regclass,
                             'public.users'::regclass,'public.mcp_servers'::regclass)
               AND relowner <> (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc
                  WHERE oid IN ('public.omp_current_approval_context()'::regprocedure,
                                'public.omp_lock_approval_context(boolean)'::regprocedure,
                                'public.omp_ensure_approval_binding_key(bytea)'::regprocedure,
                                'public.approval_authority_changed()'::regprocedure,
                                'public.approval_context_monotonic()'::regprocedure,
                                'public.approval_binding_key_guard()'::regprocedure)
                  AND proowner <> (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)) THEN
        RAISE EXCEPTION 'approval functions and protected tables must be owned by the migration role';
    END IF;
END
$$;
-- +goose StatementEnd
CREATE SCHEMA omp_private;
REVOKE ALL ON SCHEMA omp_private FROM PUBLIC;
ALTER TABLE public.approval_context SET SCHEMA omp_private;
-- SET SCHEMA also moves the sequence OWNED BY this table. Do not move it twice.
ALTER TABLE public.approval_context_events SET SCHEMA omp_private;
ALTER TABLE public.approval_binding_keys SET SCHEMA omp_private;
ALTER FUNCTION public.omp_current_approval_context() SET SCHEMA omp_private;
ALTER FUNCTION public.omp_lock_approval_context(boolean) SET SCHEMA omp_private;
ALTER FUNCTION public.omp_ensure_approval_binding_key(bytea) SET SCHEMA omp_private;
ALTER FUNCTION public.approval_authority_changed() SET SCHEMA omp_private;
ALTER FUNCTION public.approval_context_monotonic() SET SCHEMA omp_private;
ALTER FUNCTION public.approval_binding_key_guard() SET SCHEMA omp_private;

-- PL/pgSQL stores textual references: moving the OID alone is insufficient.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION omp_private.omp_current_approval_context() RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE current_epoch bigint;
BEGIN
    SELECT (c.epoch::numeric + coalesce((SELECT sum(event_id) FROM omp_private.approval_context_events), 0))::bigint
        INTO STRICT current_epoch FROM omp_private.approval_context c WHERE c.id = 1;
    RETURN current_epoch;
END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION omp_private.approval_authority_changed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE old_authority jsonb; new_authority jsonb;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        SELECT jsonb_object_agg(key,value) INTO old_authority FROM jsonb_each(to_jsonb(OLD)) WHERE key = ANY(TG_ARGV);
        SELECT jsonb_object_agg(key,value) INTO new_authority FROM jsonb_each(to_jsonb(NEW)) WHERE key = ANY(TG_ARGV);
        IF old_authority IS NOT DISTINCT FROM new_authority THEN RETURN NULL; END IF;
    END IF;
    INSERT INTO omp_private.approval_context_events DEFAULT VALUES;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION omp_private.omp_ensure_approval_binding_key(cipher bytea) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE stored_cipher bytea;
BEGIN
    INSERT INTO omp_private.approval_binding_keys(id, binding_key_cipher) VALUES (1, cipher)
        ON CONFLICT (id) DO NOTHING;
    SELECT binding_key_cipher INTO STRICT stored_cipher FROM omp_private.approval_binding_keys WHERE id = 1;
    RETURN stored_cipher;
END
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION omp_private.omp_lock_approval_context(exclusive boolean) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE current_epoch bigint; event_count bigint; event_sum numeric;
BEGIN
    IF exclusive IS NULL THEN RAISE EXCEPTION 'lock mode is required' USING ERRCODE = '22023'; END IF;
    LOCK TABLE
        omp_private.approval_context_events,
        public.api_key_gateways,
        public.api_keys,
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
    SELECT count(*), coalesce(sum(event_id), 0) INTO event_count, event_sum FROM omp_private.approval_context_events;
    IF event_count > 1000 THEN
        UPDATE omp_private.approval_context SET epoch = (epoch::numeric + event_sum)::bigint WHERE id = 1;
        IF NOT FOUND THEN RAISE EXCEPTION 'approval context singleton missing'; END IF;
        DELETE FROM omp_private.approval_context_events;
    END IF;
    current_epoch := omp_private.omp_current_approval_context();
    RETURN current_epoch;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA omp_private FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA omp_private FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA omp_private FROM PUBLIC;

-- +goose Down
-- Forward-only: no public compatibility views and no context/root reset.
SELECT 1;
