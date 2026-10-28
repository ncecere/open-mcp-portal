-- Browser activity; old sessions receive one complete idle window at upgrade.
-- +goose Up
ALTER TABLE sessions ADD COLUMN last_seen_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX sessions_last_seen_idx ON sessions (last_seen_at);

-- +goose Down
DROP INDEX sessions_last_seen_idx;
ALTER TABLE sessions DROP COLUMN last_seen_at;
