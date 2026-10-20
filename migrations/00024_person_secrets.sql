-- Per-person secrets as an upstream auth mode (roadmap #22, decision 72,
-- docs/person-secrets.md): a server's team says how a secret travels (a
-- header, a bearer token or a query parameter, a name, an optional prefix);
-- each person pastes their own API key or token once, it is sealed with
-- ENCRYPTION_KEY, shown only as a hint, and their calls carry it.
--
--   * mcp_servers.auth_mode accepts 'person_secret'. The new value is added to
--     the existing check as it stands (read from the catalog), not written
--     over it, so this migration applies in any order next to another one that
--     adds a mode.
--   * mcp_servers.secret_placement ('header', 'bearer' or 'query'),
--     secret_name (the header or parameter; null for bearer), secret_prefix
--     (text sent before the secret, for example "Token "), secret_label (what
--     the key is called, "Acme API key"), secret_help (plain text, where to
--     find it) and secret_setup_user_id/secret_setup_at (the editor whose own
--     secret reads the server's capabilities, as oauth_setup_user_id does for
--     OAuth). All null/empty outside person_secret mode.
--   * person_secrets: one sealed secret per (person, server). origin is the
--     server URL's origin when the person entered it (F-1/F-3: a secret goes
--     only to the origin it was entered for; the registry deletes a server's
--     secrets when its origin, mode or placement changes, and a call refuses
--     one whose origin differs from the server's now). secret_cipher is
--     sealed with AAD person_secret:<id>; hint is the last four characters of
--     a secret of eight or more. status is active or rejected (the server
--     answered 401 or 403 to it: it is not sent again until replaced).
--     allow_agents is the person's own switch: an agent that relays a call
--     for them may use it only when it is on (decision 66 and 68: an agent
--     has no browser, so the person decides here, without a link). Deleted
--     with the person or the server. There is no backfill.
--   * secret_requests: the link a call that needs a secret answers (modelled
--     on provider_connect_requests: a 32-byte random ID kept as a digest, the
--     ID sealed so a repeated call gets the same link, bound to the person,
--     the server and its origin, ten minutes, once).
--
-- New tables and nullable/defaulted columns, and a widened check: the previous
-- release reads a person_secret server as one with no credential (it sends
-- nothing, and the server refuses), and ignores the tables.

-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    def text;
BEGIN
    SELECT pg_get_constraintdef(c.oid) INTO def
      FROM pg_constraint c
     WHERE c.conrelid = 'mcp_servers'::regclass AND c.conname = 'mcp_servers_auth_mode_check';
    IF def IS NULL THEN
        RAISE EXCEPTION 'mcp_servers_auth_mode_check not found';
    END IF;
    IF position('person_secret' IN def) = 0 THEN
        IF position('::text]' IN def) = 0 THEN
            RAISE EXCEPTION 'unexpected shape of mcp_servers_auth_mode_check: %', def;
        END IF;
        ALTER TABLE mcp_servers DROP CONSTRAINT mcp_servers_auth_mode_check;
        EXECUTE format('ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_auth_mode_check %s',
                       replace(def, '::text]', '::text, ''person_secret''::text]'));
    END IF;
END
$$;
-- +goose StatementEnd

ALTER TABLE mcp_servers
    ADD COLUMN secret_placement    text CHECK (secret_placement IN ('header', 'bearer', 'query')),
    ADD COLUMN secret_name         text CHECK (char_length(secret_name) BETWEEN 1 AND 100),
    ADD COLUMN secret_prefix       text NOT NULL DEFAULT '' CHECK (char_length(secret_prefix) <= 64),
    ADD COLUMN secret_label        text NOT NULL DEFAULT '' CHECK (char_length(secret_label) <= 100),
    ADD COLUMN secret_help         text NOT NULL DEFAULT '' CHECK (char_length(secret_help) <= 2000),
    ADD COLUMN secret_setup_user_id uuid REFERENCES users (id) ON DELETE SET NULL,
    ADD COLUMN secret_setup_at     timestamptz,
    ADD CONSTRAINT mcp_servers_secret_shape CHECK ((secret_placement = 'bearer') = (secret_name IS NULL) OR secret_placement IS NULL),
    ADD CONSTRAINT mcp_servers_person_secret_config CHECK (auth_mode <> 'person_secret' OR secret_placement IS NOT NULL);

CREATE TABLE person_secrets (
    id             uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    server_id      uuid        NOT NULL REFERENCES mcp_servers (id) ON DELETE CASCADE,
    origin         text        NOT NULL CHECK (char_length(origin) BETWEEN 1 AND 2100),
    secret_cipher  bytea       NOT NULL,
    hint           text        NOT NULL DEFAULT '' CHECK (char_length(hint) <= 4),
    status         text        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'rejected')),
    allow_agents   boolean     NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    rotated_at     timestamptz,
    rejected_at    timestamptz,
    -- Updated at most once a minute.
    last_used_at   timestamptz,
    CONSTRAINT person_secrets_user_server_key UNIQUE (user_id, server_id)
);
CREATE INDEX person_secrets_server_idx ON person_secrets (server_id);

CREATE TABLE secret_requests (
    -- base64url SHA-256 of the link's 32-byte random ID.
    id_digest        text        PRIMARY KEY CHECK (id_digest ~ '^[A-Za-z0-9_-]{43}$'),
    -- The ID sealed with ENCRYPTION_KEY (bound to the digest), so a repeated
    -- call can answer with the same link.
    id_cipher        bytea       NOT NULL,
    user_id          uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    server_id        uuid        NOT NULL REFERENCES mcp_servers (id) ON DELETE CASCADE,
    server_origin    text        NOT NULL CHECK (char_length(server_origin) BETWEEN 1 AND 2100),
    reason           text        NOT NULL CHECK (reason IN ('secret_missing', 'secret_rejected')),
    -- The gateway and capability as they were (no foreign keys).
    gateway_id       uuid        NOT NULL,
    gateway_slug     text        NOT NULL,
    gateway_name     text        NOT NULL,
    capability_id    uuid        NOT NULL,
    capability_kind  text        NOT NULL,
    exposed_name     text        NOT NULL CHECK (char_length(exposed_name) <= 1100),
    capability_title text        NOT NULL DEFAULT '' CHECK (char_length(capability_title) <= 200),
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    used_at          timestamptz
);
CREATE INDEX secret_requests_user_idx ON secret_requests (user_id, created_at);
CREATE INDEX secret_requests_expires_idx ON secret_requests (expires_at);
CREATE INDEX secret_requests_server_idx ON secret_requests (server_id);

-- +goose Down
DROP TABLE secret_requests;
DROP TABLE person_secrets;
ALTER TABLE mcp_servers
    DROP CONSTRAINT mcp_servers_person_secret_config,
    DROP CONSTRAINT mcp_servers_secret_shape,
    DROP COLUMN secret_setup_at,
    DROP COLUMN secret_setup_user_id,
    DROP COLUMN secret_help,
    DROP COLUMN secret_label,
    DROP COLUMN secret_prefix,
    DROP COLUMN secret_name,
    DROP COLUMN secret_placement;
UPDATE mcp_servers SET auth_mode = 'none' WHERE auth_mode = 'person_secret';
-- +goose StatementBegin
DO $$
DECLARE
    def text;
BEGIN
    SELECT pg_get_constraintdef(c.oid) INTO def
      FROM pg_constraint c
     WHERE c.conrelid = 'mcp_servers'::regclass AND c.conname = 'mcp_servers_auth_mode_check';
    IF def IS NOT NULL AND position('person_secret' IN def) > 0 THEN
        ALTER TABLE mcp_servers DROP CONSTRAINT mcp_servers_auth_mode_check;
        EXECUTE format('ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_auth_mode_check %s',
                       replace(def, ', ''person_secret''::text', ''));
    END IF;
END
$$;
-- +goose StatementEnd
