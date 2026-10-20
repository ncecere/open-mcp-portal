-- Decision 64 (docs/decisions.md): a call record says whether the portal sent
-- the caller's identity token (name, email, teams) with the request to the
-- MCP server, so a failure at a server that refuses it, and what a third
-- party was told, can be seen in Calls.
--
--   * mcp_calls.identity_sent: true when the identity token was attached to the
--     request to the server (Authorization: Bearer, or MCP-Gateway-Identity),
--     false when the server's "Send identity token" switch was off, and NULL
--     when the call was not forwarded (denied, needs authorization, rate
--     limited, a list) and for every call recorded before this migration,
--     which are not guessed at.
--
-- One nullable column without a default, no backfill, no rewrite of existing
-- rows: the previous release keeps inserting rows without it (expand-only).
-- mcp_calls stays append-only (the trigger is on UPDATE and DELETE).

-- +goose Up
ALTER TABLE mcp_calls ADD COLUMN identity_sent boolean;

-- +goose Down
ALTER TABLE mcp_calls DROP COLUMN identity_sent;
