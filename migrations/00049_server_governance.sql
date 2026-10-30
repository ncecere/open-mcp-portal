-- +goose Up
-- Server governance (#40, decision 88). Expand-only: every new column is
-- nullable or has a default that keeps today's behaviour, so the previous
-- release (v0.9.0) keeps working on this schema. It does NOT enforce the new
-- rules: a gateway ceiling, a sunset date, a transfer and the re-review loop
-- only take effect on binaries that know them, so drain older serving and
-- background-worker replicas before relying on them (docs/registry.md).
--
-- Authority: a server's sensitivity, lifecycle and sunset date and a
-- gateway's ceiling decide whether a selected capability is served, so they
-- join the approval authority journal (migrations 36/42/47) like every other
-- availability input; a spent approval cannot outlive a change of them.
-- Governance bookkeeping (owner, on-call contact, review dates, replacement)
-- decides nothing and stays out of it.
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_class
               WHERE oid IN ('public.mcp_servers'::regclass, 'public.gateways'::regclass,
                             'omp_private.approval_context'::regclass,
                             'omp_private.approval_context_events'::regclass)
                 AND relowner <> (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc
                  WHERE oid IN ('omp_private.approval_authority_changed()'::regprocedure,
                                'omp_private.omp_lock_approval_context(boolean)'::regprocedure)
                    AND proowner <> (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)) THEN
        RAISE EXCEPTION 'governance and approval objects must be owned by the migration role';
    END IF;
END
$$;
-- +goose StatementEnd

ALTER TABLE public.mcp_servers
    -- Who is accountable. SET NULL keeps the server when the person is deleted;
    -- an owner who left the team or was suspended is found by the attention
    -- query, which reads live membership.
    ADD COLUMN owner_user_id uuid REFERENCES public.users (id) ON DELETE SET NULL,
    ADD COLUMN oncall_contact text CHECK (oncall_contact IS NULL OR char_length(oncall_contact) BETWEEN 1 AND 200),
    ADD COLUMN sensitivity text NOT NULL DEFAULT 'internal'
        CHECK (sensitivity IN ('public', 'internal', 'confidential', 'restricted')),
    -- When the last approval (publication or re-review) happened, and when the
    -- next one is due: last_reviewed_at + the platform interval of its
    -- sensitivity (NULL: no re-review). Derived, kept for the loop's index.
    ADD COLUMN last_reviewed_at timestamptz CHECK (last_reviewed_at IS NULL OR isfinite(last_reviewed_at)),
    ADD COLUMN review_due_at timestamptz CHECK (review_due_at IS NULL OR isfinite(review_due_at)),
    ADD COLUMN lifecycle text NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active', 'deprecated', 'sunset')),
    ADD COLUMN deprecated_at timestamptz CHECK (deprecated_at IS NULL OR isfinite(deprecated_at)),
    ADD COLUMN sunset_at timestamptz CHECK (sunset_at IS NULL OR isfinite(sunset_at)),
    ADD COLUMN replacement_server_id uuid REFERENCES public.mcp_servers (id) ON DELETE SET NULL,
    ADD CONSTRAINT mcp_servers_lifecycle_consistent CHECK (
        (lifecycle = 'active' AND deprecated_at IS NULL AND sunset_at IS NULL AND replacement_server_id IS NULL)
        OR (lifecycle = 'deprecated' AND deprecated_at IS NOT NULL)
        OR (lifecycle = 'sunset' AND deprecated_at IS NOT NULL AND sunset_at IS NOT NULL)),
    ADD CONSTRAINT mcp_servers_replacement_not_self CHECK (replacement_server_id IS NULL OR replacement_server_id <> id);

-- Existing published servers keep their approval date as the re-review anchor;
-- no due date is set (every interval starts at 0 for the default label).
UPDATE public.mcp_servers SET last_reviewed_at = COALESCE(publish_reviewed_at, published_at)
WHERE publish_state = 'published';

CREATE INDEX mcp_servers_review_due_idx ON public.mcp_servers (review_due_at, id)
    WHERE publish_state = 'published' AND review_due_at IS NOT NULL;
CREATE INDEX mcp_servers_sunset_idx ON public.mcp_servers (sunset_at, id) WHERE sunset_at IS NOT NULL;
CREATE INDEX mcp_servers_owner_idx ON public.mcp_servers (owner_user_id) WHERE owner_user_id IS NOT NULL;
CREATE INDEX mcp_servers_replacement_idx ON public.mcp_servers (replacement_server_id) WHERE replacement_server_id IS NOT NULL;

-- A gateway's ceiling. The highest label keeps every existing gateway serving
-- what it serves today; the previous release inserts none and gets that too.
ALTER TABLE public.gateways
    ADD COLUMN max_sensitivity text NOT NULL DEFAULT 'restricted'
        CHECK (max_sensitivity IN ('public', 'internal', 'confidential', 'restricted'));

-- Platform settings: the days between re-reviews per sensitivity (0: none) and
-- whether an overdue re-review sends a published server back to review. Their
-- own revision, so the publishing policy's does not move with them.
ALTER TABLE public.platform_settings
    ADD COLUMN review_interval_days_public integer NOT NULL DEFAULT 0 CHECK (review_interval_days_public BETWEEN 0 AND 3650),
    ADD COLUMN review_interval_days_internal integer NOT NULL DEFAULT 0 CHECK (review_interval_days_internal BETWEEN 0 AND 3650),
    ADD COLUMN review_interval_days_confidential integer NOT NULL DEFAULT 180 CHECK (review_interval_days_confidential BETWEEN 0 AND 3650),
    ADD COLUMN review_interval_days_restricted integer NOT NULL DEFAULT 90 CHECK (review_interval_days_restricted BETWEEN 0 AND 3650),
    ADD COLUMN governance_return_overdue boolean NOT NULL DEFAULT false,
    ADD COLUMN governance_revision bigint NOT NULL DEFAULT 1 CHECK (governance_revision > 0),
    ADD COLUMN governance_updated_by uuid REFERENCES public.users (id) ON DELETE SET NULL,
    ADD COLUMN governance_updated_at timestamptz NOT NULL DEFAULT now();

-- Moving a server to another team needs the receiving team's owner to accept.
-- One open transfer per server; finished ones stay as history. Neither team
-- is an authority input: the move itself changes mcp_servers.team_id, which
-- the existing trigger already journals.
CREATE TABLE public.server_transfers (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id       uuid        NOT NULL REFERENCES public.mcp_servers (id) ON DELETE CASCADE,
    from_team_id    uuid        NOT NULL REFERENCES public.teams (id) ON DELETE CASCADE,
    to_team_id      uuid        NOT NULL REFERENCES public.teams (id) ON DELETE CASCADE,
    state           text        NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'accepted', 'declined', 'cancelled', 'forced')),
    -- The server's revision when the transfer was requested: what the
    -- receiving owner was shown is what is accepted.
    server_revision bigint      NOT NULL,
    note            text        CHECK (note IS NULL OR char_length(note) <= 500),
    requested_by    uuid        REFERENCES public.users (id) ON DELETE SET NULL,
    requested_at    timestamptz NOT NULL DEFAULT now(),
    accepted_by     uuid        REFERENCES public.users (id) ON DELETE SET NULL,
    decided_by      uuid        REFERENCES public.users (id) ON DELETE SET NULL,
    decided_at      timestamptz,
    revision        bigint      NOT NULL DEFAULT 1 CHECK (revision > 0),
    CONSTRAINT server_transfers_different_teams CHECK (from_team_id <> to_team_id),
    CONSTRAINT server_transfers_decided CHECK ((state = 'pending') = (decided_at IS NULL))
);
CREATE UNIQUE INDEX server_transfers_one_pending ON public.server_transfers (server_id) WHERE state = 'pending';
CREATE INDEX server_transfers_to_team_idx ON public.server_transfers (to_team_id, requested_at DESC, id);
CREATE INDEX server_transfers_from_team_idx ON public.server_transfers (from_team_id, requested_at DESC, id);

-- What the governance loop has already told people, durably: notification
-- events are purged after 14 days, and an overdue review or a deprecation
-- lasts longer, so the loop's own record (not the event's dedup key) is what
-- keeps it from telling them again. stamp is the date the notice was about
-- (review_due_at, sunset_at or deprecated_at): a new date is a new notice.
CREATE TABLE public.server_governance_notices (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind        text        NOT NULL CHECK (kind IN ('review_due', 'sunset_soon', 'deprecated')),
    server_id   uuid        NOT NULL REFERENCES public.mcp_servers (id) ON DELETE CASCADE,
    -- The gateway whose owners were told (deprecated, sunset_soon); NULL for
    -- the server's own team.
    gateway_id  uuid        REFERENCES public.gateways (id) ON DELETE CASCADE,
    stamp       timestamptz NOT NULL,
    notified_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX server_governance_notices_server ON public.server_governance_notices (kind, server_id, stamp)
    WHERE gateway_id IS NULL;
CREATE UNIQUE INDEX server_governance_notices_gateway ON public.server_governance_notices (kind, server_id, gateway_id, stamp)
    WHERE gateway_id IS NOT NULL;

-- Three more notification events (private notices: in-app and email, never
-- webhooks). Previous names are all kept.
ALTER TABLE public.notification_events DROP CONSTRAINT notification_events_event_check;
ALTER TABLE public.notification_events ADD CONSTRAINT notification_events_event_check CHECK (event IN (
    'server.unhealthy', 'server.recovered', 'capability.changed', 'publish.requested',
    'publish.decided', 'connection.needs_reconsent', 'upstream_signin.lapsed', 'key.expiring',
    'approval.requested', 'approval.decided', 'access.requested', 'access.decided',
    'server.review_due', 'server.sunset_soon', 'server.deprecated'));
ALTER TABLE public.notification_preferences DROP CONSTRAINT notification_preferences_event_check;
ALTER TABLE public.notification_preferences ADD CONSTRAINT notification_preferences_event_check CHECK (event IN (
    'server.unhealthy', 'server.recovered', 'capability.changed', 'publish.requested',
    'publish.decided', 'connection.needs_reconsent', 'upstream_signin.lapsed', 'key.expiring',
    'approval.requested', 'approval.decided', 'access.requested', 'access.decided',
    'server.review_due', 'server.sunset_soon', 'server.deprecated'));

-- Register the availability inputs with the approval authority journal. The
-- column lists are the current ones (migration 35) plus the new inputs; the
-- fence (omp_lock_approval_context) already locks both tables.
DROP TRIGGER approval_authority_changed ON public.mcp_servers;
CREATE TRIGGER approval_authority_changed AFTER INSERT OR UPDATE OR DELETE ON public.mcp_servers
    FOR EACH ROW EXECUTE FUNCTION omp_private.approval_authority_changed(
        'id','team_id','slug','url','transport','auth_header_name','auth_value_cipher','timeout_seconds','enabled','publish_state',
        'revision','auth_provider_id','auth_scopes','auth_mode','send_identity','secret_placement','secret_name','secret_prefix',
        'sensitivity','lifecycle','sunset_at');
DROP TRIGGER approval_authority_changed ON public.gateways;
CREATE TRIGGER approval_authority_changed AFTER INSERT OR UPDATE OR DELETE ON public.gateways
    FOR EACH ROW EXECUTE FUNCTION omp_private.approval_authority_changed(
        'id','slug','owner_kind','team_id','enabled','revision','max_sensitivity');

-- One deliberate invalidation: an approval requested before the new rules
-- existed was not checked against them.
INSERT INTO omp_private.approval_context_events DEFAULT VALUES;

-- +goose Down
-- Forward-only: dropping the columns would silently lift every ceiling and
-- sunset, and the journal registration must not be weakened.
SELECT 1;
