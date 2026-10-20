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
-- Expand-only: a new table, and a CHECK that accepts one more value (added to
-- the check as it stands in the catalog, like 00024 does for person_secret, so
-- the two apply in either order and the check keeps every mode). The
-- previous release ignores the table and reads a machine_oauth server as one
-- with no authentication (it does not know the mode), which is why a server is
-- only put in this mode by this release.

-- +goose Up
-- +goose StatementBegin
-- The check is read from the catalog and machine_oauth is ADDED to it, not
-- written over it: another migration of this release (00024) adds person_secret
-- to the same check, and a fixed list here would drop it. Applying this after
-- or before such a migration, or twice, gives a check with every mode.
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
    IF position('machine_oauth' IN def) = 0 THEN
        IF position('::text]' IN def) = 0 THEN
            RAISE EXCEPTION 'unexpected shape of mcp_servers_auth_mode_check: %', def;
        END IF;
        ALTER TABLE mcp_servers DROP CONSTRAINT mcp_servers_auth_mode_check;
        EXECUTE format('ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_auth_mode_check %s',
                       replace(def, '::text]', '::text, ''machine_oauth''::text]'));
    END IF;
END
$$;
-- +goose StatementEnd
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
-- Removes only machine_oauth: a server in that mode goes back to static_header
-- when it still has a static credential of its own (a header or parts), else
-- to none, and its client (the table) is dropped with the secret. Servers in
-- every other mode are untouched and the check keeps every other value, so this
-- never fails because rows of another mode exist.
DROP TABLE mcp_server_machine_oauth;
ALTER TABLE mcp_servers DROP CONSTRAINT mcp_servers_machine_single_credential;
UPDATE mcp_servers SET auth_mode = CASE
        WHEN auth_header_name IS NOT NULL OR EXISTS (SELECT 1 FROM mcp_server_credentials c WHERE c.server_id = mcp_servers.id)
        THEN 'static_header' ELSE 'none' END
 WHERE auth_mode = 'machine_oauth';
-- +goose StatementBegin
DO $$
DECLARE
    def text;
BEGIN
    SELECT pg_get_constraintdef(c.oid) INTO def
      FROM pg_constraint c
     WHERE c.conrelid = 'mcp_servers'::regclass AND c.conname = 'mcp_servers_auth_mode_check';
    IF def IS NOT NULL AND position('machine_oauth' IN def) > 0 THEN
        ALTER TABLE mcp_servers DROP CONSTRAINT mcp_servers_auth_mode_check;
        EXECUTE format('ALTER TABLE mcp_servers ADD CONSTRAINT mcp_servers_auth_mode_check %s',
                       replace(def, ', ''machine_oauth''::text', ''));
    END IF;
END
$$;
-- +goose StatementEnd
