-- +goose Up
-- Expand-only. NULL preserves previous behavior. Older binaries ignore
-- these ceilings: drain them before relying on enforcement or rolling back.
ALTER TABLE api_keys ADD COLUMN tool_scope jsonb;
ALTER TABLE service_accounts ADD COLUMN tool_scope jsonb;
ALTER TABLE service_account_keys ADD COLUMN tool_scope jsonb;
ALTER TABLE oauth_grants ADD COLUMN tool_scope jsonb;
ALTER TABLE gateway_grants ADD COLUMN tool_scope jsonb;
-- Replacing a scope revokes the immutable old grant. Relaxing the check is
-- compatible with the previous binary, which never writes this new reason.
ALTER TABLE oauth_grants DROP CONSTRAINT oauth_grants_revoked_reason_check;
ALTER TABLE oauth_grants ADD CONSTRAINT oauth_grants_revoked_reason_check
    CHECK (revoked_reason IN ('user', 'admin', 'client', 'refresh_reuse', 'expired_absolute', 'scope_changed'));

-- +goose Down
-- Test-only reversal. Production rollback must drain traffic first because
-- removing scopes (like running the previous binary) removes enforcement.
UPDATE oauth_grants SET revoked_reason = 'client' WHERE revoked_reason = 'scope_changed';
ALTER TABLE oauth_grants DROP CONSTRAINT oauth_grants_revoked_reason_check;
ALTER TABLE oauth_grants ADD CONSTRAINT oauth_grants_revoked_reason_check
    CHECK (revoked_reason IN ('user', 'admin', 'client', 'refresh_reuse', 'expired_absolute'));
ALTER TABLE gateway_grants DROP COLUMN tool_scope;
ALTER TABLE oauth_grants DROP COLUMN tool_scope;
ALTER TABLE service_account_keys DROP COLUMN tool_scope;
ALTER TABLE service_accounts DROP COLUMN tool_scope;
ALTER TABLE api_keys DROP COLUMN tool_scope;
