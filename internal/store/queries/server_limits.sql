-- name: CountCappedServers :one
-- Count explicit server overrides above the new platform ceiling. Team
-- overrides are counted separately by CountCappedTeams.
SELECT count(*) FROM mcp_servers WHERE rate_limit_per_minute > @ceiling::bigint;
