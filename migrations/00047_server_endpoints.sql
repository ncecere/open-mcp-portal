-- +goose Up
-- Expand-only extra replicas. mcp_servers.url remains the canonical primary;
-- old images can still use it but do not enforce endpoint policy/review.
-- Protect the current private-schema authority layout (migration 42), not the
-- historical public function names. Never adopt an unrelated function owner.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_class
               WHERE oid IN ('public.mcp_servers'::regclass,
                             'omp_private.approval_context'::regclass,
                             'omp_private.approval_context_events'::regclass)
                 AND relowner <> (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc
                  WHERE oid IN ('omp_private.approval_authority_changed()'::regprocedure,
                                'omp_private.omp_lock_approval_context(boolean)'::regprocedure)
                    AND proowner <> (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user)) THEN
        RAISE EXCEPTION 'endpoint and approval objects must be owned by the migration role';
    END IF;
END
$$;
-- +goose StatementEnd

CREATE TABLE public.mcp_server_endpoints (
    id uuid PRIMARY KEY,
    server_id uuid NOT NULL REFERENCES public.mcp_servers(id) ON DELETE CASCADE,
    position smallint NOT NULL CHECK (position BETWEEN 1 AND 2),
    url text NOT NULL CHECK (char_length(url) BETWEEN 1 AND 500),
    enabled boolean NOT NULL DEFAULT true,
    auth_mode text NOT NULL CHECK (auth_mode IN ('none','static_header')),
    credential_origin text NOT NULL CHECK (char_length(credential_origin) BETWEEN 1 AND 500),
    credentials_cipher bytea,
    credential_shapes jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (server_id, position),
    UNIQUE (server_id, url),
    CHECK (jsonb_typeof(credential_shapes)='array' AND jsonb_array_length(credential_shapes)<=8),
    CHECK ((auth_mode='none' AND credentials_cipher IS NULL AND credential_shapes='[]'::jsonb)
        OR (auth_mode='static_header' AND credentials_cipher IS NOT NULL
            AND octet_length(credentials_cipher) BETWEEN 1 AND 263168
            AND jsonb_array_length(credential_shapes) BETWEEN 1 AND 8))
);

-- Keep endpoint identity as historical fact, not a foreign key erased by an
-- endpoint deletion/reorder. Existing/old-image writes default to primary.
ALTER TABLE public.mcp_health_checks
    ADD COLUMN endpoint_id uuid,
    ADD COLUMN endpoint_position smallint NOT NULL DEFAULT 0 CHECK (endpoint_position BETWEEN 0 AND 2),
    ADD CONSTRAINT mcp_health_checks_endpoint_identity CHECK (
        (endpoint_id IS NULL AND endpoint_position=0)
        OR (endpoint_id IS NOT NULL AND endpoint_position BETWEEN 1 AND 2));

CREATE TRIGGER approval_authority_changed AFTER INSERT OR UPDATE OR DELETE ON public.mcp_server_endpoints
    FOR EACH ROW EXECUTE FUNCTION omp_private.approval_authority_changed(
        'id','server_id','position','url','enabled','auth_mode','credential_origin','credentials_cipher','credential_shapes');

-- Add the new authority table to the same conservative, owner-definer NOWAIT
-- fence/compaction protocol. No fence or connection survives upstream I/O.
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
        public.mcp_server_endpoints,
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
REVOKE ALL ON FUNCTION omp_private.omp_lock_approval_context(boolean) FROM PUBLIC;
INSERT INTO omp_private.approval_context_events DEFAULT VALUES;

-- +goose Down
-- Forward-only: never remove encrypted credentials/history or weaken a fence
-- when rolling back a serving image. Drain older workers before using extras.
SELECT 1;
