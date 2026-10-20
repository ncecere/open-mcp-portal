-- #34 (decision 71): a call record names the trace of its request, so a slow
-- or failed call in Calls can be opened in the operator's trace viewer, and
-- a trace can be found from the call.
--
--   * mcp_calls.trace_id: the 32-hex-digit W3C trace ID when the request's
--     trace was sampled (the trace was exported), else NULL: tracing off, a
--     request the sampler dropped, and every call recorded before this
--     migration, which are not guessed at. It is an identifier of a
--     trace in the operator's own backend, not personal data.
--
-- One nullable column without a default, no backfill, no rewrite of existing
-- rows: the previous release keeps inserting rows without it (expand-only).
-- mcp_calls stays append-only (the trigger is on UPDATE and DELETE).

-- +goose Up
ALTER TABLE mcp_calls ADD COLUMN trace_id text;

-- +goose Down
ALTER TABLE mcp_calls DROP COLUMN trace_id;
