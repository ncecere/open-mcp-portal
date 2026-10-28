-- +goose Up
-- Storage foundation only: old serving images do not enforce approval rules.
-- Drain them before enabling rules. Historical UUIDs deliberately have NO FKs
-- to authority tables: inserts under the epoch fence must not take FK row locks.
CREATE TABLE approval_context (
    id smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    epoch bigint NOT NULL DEFAULT 1 CHECK (epoch > 0)
);
INSERT INTO approval_context DEFAULT VALUES;

CREATE TABLE approval_rules (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    team_id uuid,
    target_kind text NOT NULL CHECK (target_kind IN ('server', 'gateway')),
    target_id uuid NOT NULL,
    capability_id uuid,
    classes text[] NOT NULL DEFAULT '{}' CHECK (classes <@ ARRAY['read','write','destructive']::text[] AND array_position(classes, NULL) IS NULL),
    enabled boolean NOT NULL DEFAULT true,
    pending_minutes integer NOT NULL DEFAULT 1440 CHECK (pending_minutes BETWEEN 5 AND 1440),
    valid_minutes integer NOT NULL DEFAULT 15 CHECK (valid_minutes BETWEEN 1 AND 60),
    allow_service_account_admins boolean NOT NULL DEFAULT false,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX approval_rules_target ON approval_rules (target_kind, target_id);
CREATE INDEX approval_rules_team ON approval_rules (team_id, id);
CREATE TABLE approval_rule_approvers (
    rule_id uuid NOT NULL REFERENCES approval_rules(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('user', 'group')),
    user_id uuid,
    group_name text CHECK (char_length(group_name) BETWEEN 1 AND 256),
    CHECK ((kind = 'user') = (user_id IS NOT NULL) AND (kind = 'group') = (group_name IS NOT NULL))
);
CREATE UNIQUE INDEX approval_rule_approvers_user ON approval_rule_approvers(rule_id, user_id) WHERE kind = 'user';
CREATE UNIQUE INDEX approval_rule_approvers_group ON approval_rule_approvers(rule_id, group_name) WHERE kind = 'group';

CREATE TABLE approval_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id uuid NOT NULL,
    rule_revision bigint NOT NULL CHECK (rule_revision > 0),
    context_epoch bigint NOT NULL CHECK (context_epoch > 0),
    requester_kind text NOT NULL CHECK (requester_kind IN ('user', 'service_account')),
    requester_id uuid NOT NULL,
    requester_team_id uuid,
    gateway_id uuid NOT NULL,
    server_id uuid NOT NULL,
    capability_id uuid NOT NULL,
    exposed_name text NOT NULL CHECK (char_length(exposed_name) BETWEEN 1 AND 1100),
    tool_class text CHECK (tool_class IN ('read','write','destructive')),
    args_digest text NOT NULL CHECK (args_digest ~ '^[0-9a-f]{64}$'),
    binding_digest text NOT NULL CHECK (binding_digest ~ '^[0-9a-f]{64}$'),
    capability_fingerprint text NOT NULL CHECK (capability_fingerprint ~ '^[0-9a-f]{64}$'),
    server_origin text NOT NULL CHECK (char_length(server_origin) BETWEEN 1 AND 2100),
    preview_cipher bytea,
    preview_truncated boolean NOT NULL DEFAULT false,
    preview_redacted boolean NOT NULL DEFAULT false,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied','expired','used','cancelled')),
    review_revision bigint NOT NULL DEFAULT 1 CHECK (review_revision > 0),
    decided_by uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    valid_until timestamptz,
    decided_at timestamptz,
    used_at timestamptz,
    terminal_at timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '24 hours'),
    CHECK (valid_until IS NULL OR (valid_until <= expires_at AND valid_until > decided_at)),
    CHECK ((status IN ('approved','used')) <= (valid_until IS NOT NULL)),
    CHECK ((status IN ('approved','denied','used')) <= (decided_by IS NOT NULL AND decided_at IS NOT NULL)),
    CHECK ((status = 'used') = (used_at IS NOT NULL)),
    CHECK ((status IN ('denied','expired','used','cancelled')) = (terminal_at IS NOT NULL))
);
CREATE INDEX approval_requests_binding ON approval_requests(binding_digest, status, created_at DESC);
CREATE UNIQUE INDEX approval_requests_live_binding ON approval_requests(binding_digest) WHERE status IN ('pending','approved');
CREATE INDEX approval_requests_requester ON approval_requests(requester_kind, requester_id, status, created_at DESC);
CREATE INDEX approval_requests_expiry ON approval_requests(expires_at) WHERE status IN ('pending','approved');
CREATE INDEX approval_requests_validity ON approval_requests(valid_until) WHERE status = 'approved';
CREATE INDEX approval_requests_terminal ON approval_requests(terminal_at) WHERE terminal_at IS NOT NULL;

-- Even the legacy owner cannot reset/delete the singleton through ordinary
-- DML. Restricted runtime gets SELECT only, with the narrow lock helper
-- below for fences. There is deliberately no callable bump function.
-- +goose StatementBegin
CREATE FUNCTION public.approval_context_monotonic() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.id = OLD.id AND NEW.epoch > OLD.epoch THEN RETURN NEW; END IF;
    END IF;
    RAISE EXCEPTION 'approval context is monotonic and cannot be reset';
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.approval_context_monotonic() FROM PUBLIC;
CREATE TRIGGER approval_context_monotonic BEFORE INSERT OR UPDATE OR DELETE ON approval_context
    FOR EACH ROW EXECUTE FUNCTION public.approval_context_monotonic();
CREATE TRIGGER approval_context_no_truncate BEFORE TRUNCATE ON approval_context
    FOR EACH STATEMENT EXECUTE FUNCTION public.approval_context_monotonic();

-- PostgreSQL row-lock SELECTs require UPDATE privilege. Keep runtime entirely
-- read-only on the singleton instead: this helper exposes ONLY row locking,
-- never an epoch value to write. Locks persist in the caller's transaction.
-- +goose StatementBegin
CREATE FUNCTION public.omp_lock_approval_context(exclusive boolean) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE current_epoch bigint;
BEGIN
    IF exclusive IS NULL THEN RAISE EXCEPTION 'lock mode is required' USING ERRCODE = '22023'; END IF;
    IF exclusive THEN
        SELECT epoch INTO STRICT current_epoch FROM public.approval_context WHERE id = 1 FOR UPDATE;
    ELSE
        SELECT epoch INTO STRICT current_epoch FROM public.approval_context WHERE id = 1 FOR SHARE;
    END IF;
    RETURN current_epoch;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.omp_lock_approval_context(boolean) FROM PUBLIC;

-- Transition safety is a backstop, not eligibility/authority validation.
-- Every service transition still needs the shared epoch fence, conditional
-- update and atomic audit. Terminal metadata may only lose its sealed preview.
-- +goose StatementBegin
CREATE FUNCTION public.approval_request_lifecycle() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status <> 'pending' OR NEW.review_revision <> 1 OR NEW.decided_by IS NOT NULL
           OR NEW.decided_at IS NOT NULL OR NEW.valid_until IS NOT NULL THEN
            RAISE EXCEPTION 'approval request must begin pending';
        END IF;
        RETURN NEW;
    END IF;
    IF (to_jsonb(NEW) - ARRAY['status','review_revision','decided_by','decided_at','valid_until','used_at','terminal_at','preview_cipher'])
       IS DISTINCT FROM
       (to_jsonb(OLD) - ARRAY['status','review_revision','decided_by','decided_at','valid_until','used_at','terminal_at','preview_cipher']) THEN
        RAISE EXCEPTION 'approval request binding is immutable';
    END IF;
    IF NEW.status = OLD.status THEN
        IF ROW(NEW.review_revision,NEW.decided_by,NEW.decided_at,NEW.valid_until,NEW.used_at,NEW.terminal_at)
           IS DISTINCT FROM ROW(OLD.review_revision,OLD.decided_by,OLD.decided_at,OLD.valid_until,OLD.used_at,OLD.terminal_at) THEN
            RAISE EXCEPTION 'approval decision is immutable without a transition';
        END IF;
    ELSIF NOT ((OLD.status = 'pending' AND NEW.status IN ('approved','denied','expired','cancelled'))
           OR (OLD.status = 'approved' AND NEW.status IN ('used','expired','cancelled')))
           OR NEW.review_revision <> OLD.review_revision + 1 THEN
        RAISE EXCEPTION 'invalid approval transition';
    END IF;
    IF OLD.status <> 'pending' AND ROW(NEW.decided_by,NEW.decided_at,NEW.valid_until)
       IS DISTINCT FROM ROW(OLD.decided_by,OLD.decided_at,OLD.valid_until) THEN
        RAISE EXCEPTION 'approval decision is immutable';
    END IF;
    IF OLD.status IN ('denied','expired','used','cancelled') AND NEW.preview_cipher IS NOT NULL
       AND NEW.preview_cipher IS DISTINCT FROM OLD.preview_cipher THEN
        RAISE EXCEPTION 'terminal preview cannot be restored';
    END IF;
    RETURN NEW;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.approval_request_lifecycle() FROM PUBLIC;
CREATE TRIGGER approval_request_lifecycle BEFORE INSERT OR UPDATE ON approval_requests
    FOR EACH ROW EXECUTE FUNCTION public.approval_request_lifecycle();

-- Compare only the explicitly enumerated semantic fields. This catches old
-- replicas' ordinary writes, change-and-revert and cascaded deletes, but not
-- touches, probes or unchanged-authority token refreshes. The coarse epoch
-- intentionally invalidates unrelated approvals too. Every AFTER row trigger
-- takes the same singleton lock; approval consumers MUST NOT lock existing
-- authority rows after fencing (actor KEY SHARE comes first).
-- +goose StatementBegin
CREATE FUNCTION public.approval_authority_changed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE old_authority jsonb; new_authority jsonb;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        SELECT jsonb_object_agg(key,value) INTO old_authority FROM jsonb_each(to_jsonb(OLD)) WHERE key = ANY(TG_ARGV);
        SELECT jsonb_object_agg(key,value) INTO new_authority FROM jsonb_each(to_jsonb(NEW)) WHERE key = ANY(TG_ARGV);
        IF old_authority IS NOT DISTINCT FROM new_authority THEN RETURN NULL; END IF;
    END IF;
    UPDATE public.approval_context SET epoch = epoch + 1 WHERE id = 1;
    IF NOT FOUND THEN RAISE EXCEPTION 'approval context singleton missing'; END IF;
    RETURN NULL;
END
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION public.approval_authority_changed() FROM PUBLIC;

-- Refuse a different migration role rather than leaving a privileged helper
-- owned by an unrelated superuser. Matches the existing purge boundary.
-- +goose StatementBegin
DO $$
DECLARE spec record; args text;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_class WHERE oid IN ('public.users'::regclass,'public.mcp_servers'::regclass)
               AND relowner <> (SELECT oid FROM pg_roles WHERE rolname = current_user)) THEN
        RAISE EXCEPTION 'approval functions and protected tables must be owned by the migration role';
    END IF;
    FOR spec IN SELECT * FROM (VALUES
        ('capture_settings', 'id,patterns,revision'),
        ('users', 'id,status,platform_role,groups'),
        ('teams', 'id,status'),
        ('team_members', 'team_id,user_id,role'),
        ('api_keys', 'id,user_id,digest,pepper_id,expires_at,revoked_at,tool_scope'),
        ('api_key_gateways', 'api_key_id,gateway_id'),
        ('oauth_grants', 'id,user_id,gateway_id,client_id,client_kind,resource,created_at,authorized_at,revoked_at,revoked_reason,tool_scope'),
        ('service_accounts', 'id,team_id,role,enabled,tool_scope,revision'),
        ('service_account_keys', 'id,service_account_id,digest,pepper_id,expires_at,revoked_at,tool_scope'),
        ('service_account_key_gateways', 'key_id,gateway_id'),
        ('gateways', 'id,slug,owner_kind,team_id,enabled,revision'),
        ('gateway_grants', 'id,gateway_id,subject_kind,team_id,user_id,group_name,tool_scope'),
        ('gateway_capabilities', 'gateway_id,capability_id,min_team_role,name_override,description_override,constraints,base_fingerprint'),
        ('mcp_servers', 'id,team_id,slug,url,transport,auth_header_name,auth_value_cipher,timeout_seconds,enabled,publish_state,revision,auth_provider_id,auth_scopes,auth_mode,send_identity,secret_placement,secret_name,secret_prefix'),
        ('mcp_capabilities', 'id,server_id,kind,name,definition,fingerprint,approved_fingerprint,gone_at,requirement_mode,requirement_scopes,tool_class'),
        ('mcp_server_credentials', 'id,server_id,position,kind,name,value_cipher,secondary_cipher'),
        ('mcp_server_machine_oauth', 'server_id,token_url,client_id,client_secret_cipher,token_auth_method,scopes,audience,resource'),
        ('mcp_server_tls', 'server_id,ca_pem,ca_sha256,client_cert_pem,client_key_cipher,client_cert_sha256,client_not_after'),
        ('auth_providers', 'id,slug,kind,enabled,client_id,client_secret_cipher,token_auth_method,pkce,authorization_url,token_url,revocation_url,userinfo_url,default_scopes,scope_param,scope_separator,token_response_format,extra_authorize_params,revision,server_id,link_provider_id,registration,resource,resource_metadata_url,authorization_server,issuer,scopes_supported,send_resource,iss_param_supported,client_secret_expires_at,access_mode,narrow_on_refresh'),
        ('auth_provider_teams', 'provider_id,team_id'),
        ('auth_provider_servers', 'provider_id,server_id'),
        ('provider_connections', 'id,user_id,provider_id,status,scopes'),
        ('provider_server_grants', 'connection_id,server_id,origin,scopes'),
        ('person_secrets', 'id,user_id,server_id,status,origin,secret_cipher'),
        ('service_connections', 'id,team_id,provider_id,revision,generation,status,scopes,connected_by'),
        ('service_connection_accounts', 'connection_id,team_id,provider_id,service_account_id'),
        ('service_connection_server_grants', 'connection_id,server_id,origin,scopes'),
        ('approval_rules', 'id,name,team_id,target_kind,target_id,capability_id,classes,enabled,pending_minutes,valid_minutes,allow_service_account_admins,revision,created_by'),
        ('approval_rule_approvers', 'rule_id,kind,user_id,group_name')
    ) AS definitions(table_name, columns) LOOP
        -- Validate spelling now; silently missing a field would be unsafe.
        IF EXISTS (SELECT 1 FROM unnest(string_to_array(spec.columns, ',')) col
                   WHERE NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = ('public.' || spec.table_name)::regclass
                                     AND attname = col AND attnum > 0 AND NOT attisdropped)) THEN
            RAISE EXCEPTION 'unknown approval authority column on %', spec.table_name;
        END IF;
        SELECT string_agg(quote_literal(col), ',') INTO args FROM unnest(string_to_array(spec.columns, ',')) col;
        EXECUTE format('CREATE TRIGGER approval_authority_changed AFTER INSERT OR UPDATE OR DELETE ON public.%I FOR EACH ROW EXECUTE FUNCTION public.approval_authority_changed(%s)', spec.table_name, args);
    END LOOP;
END
$$;
-- +goose StatementEnd

-- Access-token revocation may delete only the token, not its grant. New
-- tokens and refresh-token rotation do not invalidate unchanged authority.
-- Expired-token housekeeping is harmless; expiry is also checked live by the
-- consumer (the initial epoch must be captured BEFORE authentication).
CREATE TRIGGER approval_oauth_access_update AFTER UPDATE ON oauth_tokens
    FOR EACH ROW WHEN ((OLD.kind = 'access' AND OLD.expires_at > statement_timestamp())
                    OR (NEW.kind = 'access' AND NEW.expires_at > statement_timestamp()))
    EXECUTE FUNCTION public.approval_authority_changed('id','grant_id','kind','token_hash','pepper_id','resource','expires_at');
CREATE TRIGGER approval_oauth_access_delete AFTER DELETE ON oauth_tokens
    FOR EACH ROW WHEN (OLD.kind = 'access' AND OLD.expires_at > statement_timestamp())
    EXECUTE FUNCTION public.approval_authority_changed('id','grant_id','kind','token_hash','pepper_id','resource','expires_at');

ALTER TABLE mcp_calls DROP CONSTRAINT mcp_calls_outcome_check;
ALTER TABLE mcp_calls ADD CONSTRAINT mcp_calls_outcome_check CHECK (outcome IN
    ('ok','tool_error','denied','upstream_error','timeout','too_large','bad_request','needs_authorization','rate_limited','needs_approval'));

-- +goose Down
-- Forward-only. Reverting context/transition guards reopens spent authority.
SELECT 1;
