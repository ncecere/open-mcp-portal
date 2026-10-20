-- Per-provider access list and narrower delegated tokens (roadmap #27,
-- decision 69, threat model H-5 and section 7.1):
--
--   * auth_providers.access_mode: 'open' (any team's server may require the
--     provider, as before) or 'restricted' (only a server of a listed team,
--     or a listed server, may). Every existing row is open: nothing changes
--     at the upgrade, and the admin UI flags open providers. The column
--     default stays 'open' so the previous release, which does not know the
--     column, inserts open providers; the portal sets 'restricted' itself
--     when an admin creates one.
--   * auth_provider_teams / auth_provider_servers: the listed teams and
--     servers of a restricted provider. They cascade with the provider, the
--     team and the server. A server-bound provider (kind mcp_server) has no
--     list: its connection is for one server already.
--   * auth_providers.narrow_on_refresh: when on, a call gets a short-lived
--     token refreshed with only the scopes the call needs (RFC 6749 section
--     6), kept in memory; the stored token is never sent. Default off.
--
-- New tables and defaulted columns only (expand/contract): the previous
-- release ignores them.

-- +goose Up
ALTER TABLE auth_providers
    ADD COLUMN access_mode       text    NOT NULL DEFAULT 'open' CONSTRAINT auth_providers_access_mode_check CHECK (access_mode IN ('open', 'restricted')),
    ADD COLUMN narrow_on_refresh boolean NOT NULL DEFAULT false;

CREATE TABLE auth_provider_teams (
    provider_id uuid        NOT NULL REFERENCES auth_providers (id) ON DELETE CASCADE,
    team_id     uuid        NOT NULL REFERENCES teams (id) ON DELETE CASCADE,
    added_at    timestamptz NOT NULL DEFAULT now(),
    added_by    uuid        REFERENCES users (id) ON DELETE SET NULL,
    PRIMARY KEY (provider_id, team_id)
);
CREATE INDEX auth_provider_teams_team_idx ON auth_provider_teams (team_id);

CREATE TABLE auth_provider_servers (
    provider_id uuid        NOT NULL REFERENCES auth_providers (id) ON DELETE CASCADE,
    server_id   uuid        NOT NULL REFERENCES mcp_servers (id) ON DELETE CASCADE,
    added_at    timestamptz NOT NULL DEFAULT now(),
    added_by    uuid        REFERENCES users (id) ON DELETE SET NULL,
    PRIMARY KEY (provider_id, server_id)
);
CREATE INDEX auth_provider_servers_server_idx ON auth_provider_servers (server_id);

-- +goose Down
DROP TABLE auth_provider_servers;
DROP TABLE auth_provider_teams;
ALTER TABLE auth_providers DROP COLUMN narrow_on_refresh, DROP COLUMN access_mode;
