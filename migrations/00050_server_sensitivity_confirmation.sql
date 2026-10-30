-- +goose Up
-- Sensitivity confirmation (#40, decision 88 follow-up). Expand-only: one
-- nullable column, no default and no backfill, so the previous releases (v0.9.0
-- and the 00049 governance build) keep working on this schema; they neither
-- read nor write it.
--
-- `sensitivity` defaults to 'internal' (migration 49), so a row that says
-- internal cannot tell a label a team chose from one nobody looked at. This
-- column records the second: it is NULL until an owner or admin of the
-- server's team sends a sensitivity in a governance edit (even the value it
-- already has), and every existing row stays NULL. Deliberately NOT inferred
-- from the label, from earlier governance edits or from publication: nothing
-- before this migration recorded that anybody checked it.
--
-- It is bookkeeping, not authority: it decides nothing (no gateway, approval,
-- ceiling or publication reads it) and so it is NOT one of the columns of the
-- approval authority journal trigger on mcp_servers (migration 49 keeps its
-- list unchanged). The sensitivity itself stays an authority input.
--
-- An older binary that changes a label leaves this column as it was, so a
-- server it labelled shows as unconfirmed until its team confirms it: that is
-- the conservative reading.
ALTER TABLE public.mcp_servers
    ADD COLUMN sensitivity_confirmed_at timestamptz
        CONSTRAINT mcp_servers_sensitivity_confirmed_finite CHECK (sensitivity_confirmed_at IS NULL OR isfinite(sensitivity_confirmed_at));

-- The attention lists read published servers nobody confirmed; the set shrinks
-- as teams confirm.
CREATE INDEX mcp_servers_unconfirmed_sensitivity_idx ON public.mcp_servers (team_id, name, id)
    WHERE publish_state = 'published' AND sensitivity_confirmed_at IS NULL;

-- +goose Down
-- Forward-only: the previous release ignores the column, and dropping it would
-- only forget which labels a person confirmed.
SELECT 1;
