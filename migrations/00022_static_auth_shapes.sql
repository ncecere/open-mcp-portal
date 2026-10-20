-- Several headers, a query key and Basic auth for a server's own credential
-- (roadmap #23, decision 70, docs/registry.md "A server's own credential").
--
--   * mcp_server_credentials: a server's own credential as an ordered list of
--     parts (at most eight): kind header (a header name and its value), bearer
--     (the token, sent as Authorization: Bearer), basic (user and password,
--     sent as Authorization: Basic) and query (a query parameter name and its
--     value, added to the request, never to the saved URL). Every value is
--     sealed with ENCRYPTION_KEY (value_cipher, AAD mcp_server_credential:<id>;
--     secondary_cipher, the Basic password, AAD mcp_server_credential:<id>:
--     secondary) and never returned; hint is the last four characters of a
--     value of eight or more (of the password for basic). A server has at most
--     one part per kind and name (the name compared without case; one bearer,
--     one basic). Deleting the server deletes its parts.
--
-- The legacy columns mcp_servers.auth_header_name, auth_value_cipher and
-- auth_value_hint are not touched and no row is rewritten: a server that has
-- no rows here keeps its one static header there, and the registry reads it as
-- a single header part. Saving a server's credentials with the new list moves
-- them into this table and clears the legacy columns in the same transaction,
-- so a server's credential is in one of the two places, never both. Folding the
-- legacy columns in is a later contract migration. A server with parts here
-- has auth_mode static_header (or oauth, with parts that are not Authorization):
-- the previous release reads such a server as one without credentials, which
-- is why this is expand-only and not a rewrite.
--
-- A new table only (expand/contract): the previous release ignores it.

-- +goose Up
CREATE TABLE mcp_server_credentials (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id        uuid        NOT NULL REFERENCES mcp_servers (id) ON DELETE CASCADE,
    position         smallint    NOT NULL CHECK (position BETWEEN 0 AND 7),
    kind             text        NOT NULL CHECK (kind IN ('header', 'bearer', 'basic', 'query')),
    name             text        CHECK (char_length(name) BETWEEN 1 AND 100),
    value_cipher     bytea       NOT NULL,
    secondary_cipher bytea,
    hint             text        NOT NULL DEFAULT '' CHECK (char_length(hint) <= 4),
    created_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT mcp_server_credentials_name_kind CHECK ((kind IN ('header', 'query')) = (name IS NOT NULL)),
    CONSTRAINT mcp_server_credentials_secondary_kind CHECK ((kind = 'basic') = (secondary_cipher IS NOT NULL)),
    CONSTRAINT mcp_server_credentials_position_key UNIQUE (server_id, position)
);
CREATE UNIQUE INDEX mcp_server_credentials_part_key ON mcp_server_credentials (server_id, kind, lower(coalesce(name, '')));

-- +goose Down
DROP TABLE mcp_server_credentials;
