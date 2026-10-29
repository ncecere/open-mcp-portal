-- +goose Up
-- Gateway access requests are distinct from sensitive-call approvals.
ALTER TABLE public.gateways ADD COLUMN access_requests_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE public.gateways ADD CONSTRAINT requestable_platform_gateway
    CHECK (NOT access_requests_enabled OR owner_kind = 'platform');

CREATE TABLE public.gateway_stewards (
    gateway_id uuid NOT NULL REFERENCES public.gateways(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    PRIMARY KEY (gateway_id, user_id)
);
CREATE INDEX gateway_stewards_user ON public.gateway_stewards(user_id, gateway_id);

CREATE TABLE public.access_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    gateway_id uuid NOT NULL REFERENCES public.gateways(id) ON DELETE CASCADE,
    requester_user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    subject_kind text NOT NULL CHECK (subject_kind IN ('user', 'team')),
    team_id uuid REFERENCES public.teams(id) ON DELETE CASCADE,
    reason text NOT NULL CHECK (char_length(btrim(reason)) BETWEEN 1 AND 1000),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'withdrawn')),
    decided_by uuid REFERENCES public.users(id) ON DELETE SET NULL,
    decided_at timestamptz,
    decision_note text NOT NULL DEFAULT '' CHECK (char_length(decision_note) <= 1000),
    -- Snapshot references intentionally do not erase decision history on expiry.
    grant_id uuid,
    grant_expires_at timestamptz CHECK (grant_expires_at IS NULL OR isfinite(grant_expires_at)),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((subject_kind = 'team') = (team_id IS NOT NULL)),
    CHECK ((status = 'pending') = (decided_at IS NULL)),
    CHECK ((status = 'approved') = (grant_id IS NOT NULL)),
    CHECK (decided_by IS NULL OR decided_by <> requester_user_id)
);
CREATE UNIQUE INDEX access_request_pending_user ON public.access_requests(gateway_id, requester_user_id)
    WHERE status = 'pending' AND subject_kind = 'user';
CREATE UNIQUE INDEX access_request_pending_team ON public.access_requests(gateway_id, requester_user_id, team_id)
    WHERE status = 'pending' AND subject_kind = 'team';
CREATE INDEX access_requests_requester ON public.access_requests(requester_user_id, created_at DESC, id DESC);
CREATE INDEX access_requests_gateway ON public.access_requests(gateway_id, status, created_at DESC, id DESC);
CREATE INDEX access_requests_pending ON public.access_requests(requester_user_id) WHERE status = 'pending';

-- +goose Down
-- Forward-only. Keep request/audit history and the opt-in visibility setting.
SELECT 1;
