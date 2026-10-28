-- +goose Up
-- Expand-only. NULL preserves previous behavior. Older binaries ignore
-- these ceilings: drain them before relying on enforcement or rolling back.
ALTER TABLE api_keys ADD COLUMN tool_scope jsonb;
ALTER TABLE service_accounts ADD COLUMN tool_scope jsonb;
ALTER TABLE service_account_keys ADD COLUMN tool_scope jsonb;
ALTER TABLE oauth_grants ADD COLUMN tool_scope jsonb;
ALTER TABLE gateway_grants ADD COLUMN tool_scope jsonb;

-- +goose Down
-- Test-only reversal. Production rollback must drain traffic first because
-- removing scopes (like running the previous binary) removes enforcement.
ALTER TABLE gateway_grants DROP COLUMN tool_scope;
ALTER TABLE oauth_grants DROP COLUMN tool_scope;
ALTER TABLE service_account_keys DROP COLUMN tool_scope;
ALTER TABLE service_accounts DROP COLUMN tool_scope;
ALTER TABLE api_keys DROP COLUMN tool_scope;
