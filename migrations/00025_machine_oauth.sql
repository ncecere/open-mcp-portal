-- #24 (decision 73): OAuth client credentials for MCP servers that authenticate
-- the portal itself (docs/machine-oauth.md).
--
--   * mcp_servers.auth_mode gains machine_oauth: the portal is an OAuth client
--     of the server's authorization server, gets a token with the
--     client_credentials grant and sends it as Authorization: Bearer to the
--     server's stored URL, for every caller alike (discovery, health checks,
--     Test and forwarded calls, service accounts included). The identity token
--     then travels as MCP-Gateway-Identity, as in oauth mode. Like oauth mode
--     it excludes a static Authorization header and a user authorization
--     requirement (one credential per call; mcp_servers_machine_single_credential);
--     a server's static parts that are not Authorization may stay.
--   * mcp_server_machine_oauth: one row per such server. token_url is the
--     authorization server's token endpoint (checked against the address rules
--     when saved and again at every request), client_id and the client secret
--     (client_secret_cipher, sealed with ENCRYPTION_KEY, AAD
--     machine_oauth:<server id>; client_secret_hint is its last four characters
--     when it has eight or more; never returned), token_auth_method (how the
--     client authenticates at the token endpoint: HTTP Basic or the form), the
--     scopes asked for, and the optional audience and resource (RFC 8707)
--     parameters. No token is stored: tokens live in memory, per replica.
--     Deleting the server deletes the row.
--
-- Expand-only: a new table, and a CHECK that accepts one more value. The
-- previous release ignores the table and reads a machine_oauth server as one
-- with no authentication (it does not know the mode), which is why a server is
-- only put in this mode by this release.

-- +goose Up
ALTER TABLE mcp_servers DROP CONSTRAINT IF EXISTS mcp_servers_auth_mode_check;
ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_auth_mode_check
    CHECK (auth_mode IN ('none', 'static_header', 'oauth', 'machine_oauth'));
ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_machine_single_credential
    CHECK (auth_mode <> 'machine_oauth' OR (auth_provider_id IS NULL AND (auth_header_name IS NULL OR lower(auth_header_name) <> 'authorization')));

CREATE TABLE mcp_server_machine_oauth (
    server_id            uuid        PRIMARY KEY REFERENCES mcp_servers (id) ON DELETE CASCADE,
    token_url            text        NOT NULL CHECK (char_length(token_url) BETWEEN 1 AND 1000),
    client_id            text        NOT NULL CHECK (char_length(client_id) BETWEEN 1 AND 500),
    client_secret_cipher bytea       NOT NULL,
    client_secret_hint   text        NOT NULL DEFAULT '' CHECK (char_length(client_secret_hint) <= 4),
    token_auth_method    text        NOT NULL DEFAULT 'client_secret_basic'
        CHECK (token_auth_method IN ('client_secret_basic', 'client_secret_post')),
    scopes               text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(scopes) <= 50),
    audience             text        CHECK (char_length(audience) BETWEEN 1 AND 500),
    resource             text        CHECK (char_length(resource) BETWEEN 1 AND 500),
    created_by           uuid        REFERENCES users (id) ON DELETE SET NULL,
    updated_by           uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE mcp_server_machine_oauth;
ALTER TABLE mcp_servers DROP CONSTRAINT mcp_servers_machine_single_credential;
UPDATE mcp_servers SET auth_mode = 'none' WHERE auth_mode = 'machine_oauth';
ALTER TABLE mcp_servers DROP CONSTRAINT mcp_servers_auth_mode_check;
ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_auth_mode_check CHECK (auth_mode IN ('none', 'static_header', 'oauth'));
