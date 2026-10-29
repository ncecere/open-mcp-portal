-- +goose Up
-- Expand-only operational settings. NULL preserves the existing unlimited/
-- inherited behavior. Previous binaries ignore these fields: complete rollout
-- before relying on enforcement. No endpoint/failover credentials are added.
ALTER TABLE mcp_servers
    ADD COLUMN rate_limit_per_minute bigint CHECK (rate_limit_per_minute BETWEEN 1 AND 1000000),
    ADD COLUMN max_concurrent integer CHECK (max_concurrent BETWEEN 1 AND 10000);

-- +goose Down
-- Forward-only: do not erase operational settings when rolling back a binary.
SELECT 1;
