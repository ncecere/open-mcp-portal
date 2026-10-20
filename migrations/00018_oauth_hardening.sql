-- OAuth hardening for v0.2.2 (docs/threat-model.md H-1, H-3, H-4, H-8; decisions 62 and 63):
--
--   * oauth_settings.open_registration: the admin switch "Allow open client
--     registration" (H-4). On (the default) is today's behaviour; off, the
--     authorization server metadata leaves out registration_endpoint and
--     POST /oauth/register answers 403.
--   * oauth_clients.registered_from: the address a registration came from
--     (as the portal saw it, TRUSTED_PROXIES applied), so one address can't
--     hold more than its share of unused registrations (H-4). Nullable:
--     rows from before this migration have none and are never counted
--     against an address.
--   * oauth_clients.authorized_at: when a registered client first received
--     tokens. A registration that never did is deleted after 24 hours
--     instead of 30 days (H-4). Existing rows that have a grant (a person
--     consented to them) are backfilled with their last use, so nothing
--     that works today stops working; a row that never had a grant has
--     nothing to lose.
--   * oauth_grants.authorized_at: when the person last completed an
--     authorization for the grant (set when it is created, and again each
--     time they sign the app in again). The absolute lifetime of a refresh
--     token chain, OAUTH_REFRESH_ABSOLUTE_TTL, is counted from it (H-8), so
--     signing in again starts a new lifetime instead of failing at once on
--     a grant that was remembered. Existing active grants start their
--     first window at this migration (authorized_at = now()): nobody is
--     signed out by the upgrade, and the longest a grant can live past it
--     is one TTL. A grant created by the previous release while this
--     migration is applied has NULL; the code reads it as created_at.
--   * oauth_grants.revoked_reason accepts 'expired_absolute': a grant
--     revoked because its refresh tokens reached the absolute lifetime.
--
-- Expand only: new nullable columns or columns with defaults, one relaxed
-- check. The previous release keeps working with this schema: it never
-- writes the new columns or the new reason.
--
-- Reversal (Down): drop the columns and the index. Grants revoked as
-- 'expired_absolute' are first given the reason 'client' so the original
-- check can come back. Registrations that were never authorized are not
-- restored (they were deleted on schedule), and the switch is forgotten
-- (registration is open again, as in the previous release).

-- +goose Up
ALTER TABLE oauth_settings ADD COLUMN open_registration boolean NOT NULL DEFAULT true;

ALTER TABLE oauth_clients
    ADD COLUMN registered_from text CHECK (char_length(registered_from) <= 64),
    ADD COLUMN authorized_at   timestamptz;
UPDATE oauth_clients c SET authorized_at = c.last_used_at
WHERE EXISTS (SELECT 1 FROM oauth_grants g WHERE g.client_id = c.client_id);
CREATE INDEX oauth_clients_registered_from_idx ON oauth_clients (registered_from) WHERE registered_from IS NOT NULL AND authorized_at IS NULL;

ALTER TABLE oauth_grants ADD COLUMN authorized_at timestamptz;
UPDATE oauth_grants SET authorized_at = now() WHERE revoked_at IS NULL;

ALTER TABLE oauth_grants DROP CONSTRAINT oauth_grants_revoked_reason_check;
ALTER TABLE oauth_grants ADD CONSTRAINT oauth_grants_revoked_reason_check
    CHECK (revoked_reason IN ('user', 'admin', 'client', 'refresh_reuse', 'expired_absolute'));

-- +goose Down
UPDATE oauth_grants SET revoked_reason = 'client' WHERE revoked_reason = 'expired_absolute';
ALTER TABLE oauth_grants DROP CONSTRAINT oauth_grants_revoked_reason_check;
ALTER TABLE oauth_grants ADD CONSTRAINT oauth_grants_revoked_reason_check
    CHECK (revoked_reason IN ('user', 'admin', 'client', 'refresh_reuse'));
ALTER TABLE oauth_grants DROP COLUMN authorized_at;
DROP INDEX oauth_clients_registered_from_idx;
ALTER TABLE oauth_clients DROP COLUMN authorized_at, DROP COLUMN registered_from;
ALTER TABLE oauth_settings DROP COLUMN open_registration;
