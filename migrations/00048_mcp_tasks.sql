-- +goose Up
-- Expand-only task-relay storage. This stores mappings, never runs a worker.
-- Older serving/background images ignore it and cannot enforce task policy.
ALTER TABLE public.mcp_servers
    ADD COLUMN supports_tasks boolean NOT NULL DEFAULT false;

ALTER TABLE public.mcp_calls DROP CONSTRAINT mcp_calls_method_check;
ALTER TABLE public.mcp_calls ADD CONSTRAINT mcp_calls_method_check
    CHECK (method IN ('tools/list', 'tools/call', 'prompts/list', 'prompts/get',
                      'resources/list', 'resources/templates/list', 'resources/read',
                      'tasks/get', 'tasks/update', 'tasks/cancel'));

CREATE TABLE public.mcp_tasks (
    id uuid PRIMARY KEY,
    handle_digest text NOT NULL UNIQUE CHECK (handle_digest ~ '^[0-9a-f]{64}$'),
    principal_kind text NOT NULL CHECK (principal_kind IN ('user','service_account')),
    user_id uuid REFERENCES public.users(id) ON DELETE CASCADE,
    service_account_id uuid REFERENCES public.service_accounts(id) ON DELETE CASCADE,
    credential_kind text NOT NULL CHECK (credential_kind IN ('api_key','oauth','service_account')),
    api_key_id uuid REFERENCES public.api_keys(id) ON DELETE CASCADE,
    oauth_grant_id uuid REFERENCES public.oauth_grants(id) ON DELETE CASCADE,
    service_account_key_id uuid REFERENCES public.service_account_keys(id) ON DELETE CASCADE,
    gateway_id uuid NOT NULL REFERENCES public.gateways(id) ON DELETE CASCADE,
    server_id uuid NOT NULL REFERENCES public.mcp_servers(id) ON DELETE CASCADE,
    capability_id uuid NOT NULL REFERENCES public.mcp_capabilities(id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'reserved' CHECK (status IN
        ('reserved','working','input_required','completed','failed','cancelled')),
    -- No raw handle/upstream ID, arguments, input key or credential column.
    -- Binding is non-secret association/digests, checked against sealed state.
    binding jsonb,
    binding_digest text CHECK (binding_digest ~ '^[0-9a-f]{64}$'),
    state_cipher bytea,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    ceiling_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    reservation_deadline timestamptz,
    next_poll_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    poll_interval_ms integer NOT NULL DEFAULT 5000 CHECK (poll_interval_ms BETWEEN 1000 AND 60000),
    upstream_created_at timestamptz,
    upstream_updated_at timestamptz,
    -- Short persisted operation fencing is not a held SQL/authority lock.
    operation_id uuid,
    operation_deadline timestamptz,
    CONSTRAINT mcp_tasks_principal_credential CHECK (
        (principal_kind='user' AND user_id IS NOT NULL AND service_account_id IS NULL
         AND ((credential_kind='api_key' AND api_key_id IS NOT NULL AND oauth_grant_id IS NULL AND service_account_key_id IS NULL)
           OR (credential_kind='oauth' AND oauth_grant_id IS NOT NULL AND api_key_id IS NULL AND service_account_key_id IS NULL)))
        OR (principal_kind='service_account' AND service_account_id IS NOT NULL AND user_id IS NULL
            AND credential_kind='service_account' AND service_account_key_id IS NOT NULL AND api_key_id IS NULL AND oauth_grant_id IS NULL)),
    CONSTRAINT mcp_tasks_lifetime CHECK (
        updated_at >= created_at AND expires_at > created_at AND ceiling_at >= expires_at
        AND ceiling_at <= created_at + interval '24 hours'),
    CONSTRAINT mcp_tasks_reservation CHECK (
        (status='reserved' AND reservation_deadline IS NOT NULL AND reservation_deadline > created_at AND reservation_deadline <= expires_at)
        OR (status<>'reserved' AND reservation_deadline IS NULL)),
    CONSTRAINT mcp_tasks_sealed_binding CHECK (
        (binding IS NULL AND binding_digest IS NULL AND state_cipher IS NULL AND status='reserved')
        OR (binding IS NOT NULL AND jsonb_typeof(binding)='object' AND octet_length(binding::text) <= 8192
            AND binding_digest IS NOT NULL AND state_cipher IS NOT NULL AND octet_length(state_cipher) BETWEEN 1 AND 2098176)),
    CONSTRAINT mcp_tasks_upstream_time CHECK (
        (status='reserved' AND upstream_created_at IS NULL AND upstream_updated_at IS NULL)
        OR (status<>'reserved' AND upstream_created_at IS NOT NULL AND upstream_updated_at IS NOT NULL
            AND upstream_updated_at >= upstream_created_at)),
    CONSTRAINT mcp_tasks_operation_pair CHECK (
        (operation_id IS NULL AND operation_deadline IS NULL)
        OR (operation_id IS NOT NULL AND operation_deadline IS NOT NULL AND operation_deadline > created_at AND operation_deadline <= expires_at))
);

CREATE INDEX mcp_tasks_user_active_idx ON public.mcp_tasks(user_id, expires_at)
    WHERE user_id IS NOT NULL AND status IN ('reserved','working','input_required');
CREATE INDEX mcp_tasks_service_active_idx ON public.mcp_tasks(service_account_id, expires_at)
    WHERE service_account_id IS NOT NULL AND status IN ('reserved','working','input_required');
CREATE INDEX mcp_tasks_expires_idx ON public.mcp_tasks(expires_at);

-- Operational poll/input revisions do not allocate approval authority: they
-- must not churn the global approval epoch or widen any existing rule/grant.
-- Existing authority tables, current no-rule checks and before-transport
-- deadline/credential guards remain authoritative for every task exchange.

-- +goose Down
-- Expand-only rollback: retain mappings, ciphertext, discovery facts and call
-- methods. Drain older replicas; old-image compatibility is not enforcement.
