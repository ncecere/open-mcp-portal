-- +goose Up
-- Separate OAuth state is essential: old replicas must never consume service
-- consent and store the resulting tokens in a personal connection.
CREATE TABLE service_connections (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    provider_id uuid NOT NULL REFERENCES auth_providers(id) ON DELETE CASCADE,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    status text NOT NULL DEFAULT 'needs_reconsent' CHECK (status IN ('active', 'needs_reconsent')),
    scopes text[] NOT NULL DEFAULT '{}',
    account_label text,
    access_token_cipher bytea,
    refresh_token_cipher bytea,
    expires_at timestamptz,
    connected_by uuid REFERENCES users(id) ON DELETE SET NULL,
    connected_at timestamptz,
    refreshed_at timestamptz,
    last_used_at timestamptz,
    last_error_class text,
    revision bigint NOT NULL DEFAULT 1,
    generation bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (team_id, provider_id, name),
    UNIQUE (id, team_id, provider_id),
    CHECK (status <> 'active' OR access_token_cipher IS NOT NULL)
);
ALTER TABLE service_accounts ADD CONSTRAINT service_accounts_id_team_unique UNIQUE (id, team_id);
CREATE TABLE service_connection_accounts (
    connection_id uuid NOT NULL,
    team_id uuid NOT NULL,
    provider_id uuid NOT NULL,
    service_account_id uuid NOT NULL,
    PRIMARY KEY (service_account_id, provider_id),
    FOREIGN KEY (connection_id, team_id, provider_id) REFERENCES service_connections(id, team_id, provider_id) ON DELETE CASCADE,
    FOREIGN KEY (service_account_id, team_id) REFERENCES service_accounts(id, team_id) ON DELETE CASCADE
);
CREATE INDEX service_connection_accounts_connection ON service_connection_accounts(connection_id);
CREATE TABLE service_connection_server_grants (
    connection_id uuid NOT NULL REFERENCES service_connections(id) ON DELETE CASCADE,
    server_id uuid NOT NULL REFERENCES mcp_servers(id) ON DELETE CASCADE,
    origin text NOT NULL,
    scopes text[] NOT NULL DEFAULT '{}',
    granted_by uuid REFERENCES users(id) ON DELETE SET NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (connection_id, server_id)
);
CREATE TABLE service_connection_auth_states (
    state_digest text PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_digest text NOT NULL,
    connection_id uuid NOT NULL REFERENCES service_connections(id) ON DELETE CASCADE,
    revision bigint NOT NULL,
    generation bigint NOT NULL,
    provider_id uuid NOT NULL REFERENCES auth_providers(id) ON DELETE CASCADE,
    provider_revision bigint NOT NULL,
    client_revision bigint NOT NULL,
    scopes text[] NOT NULL,
    code_verifier_cipher bytea,
    resource text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX service_connection_auth_states_session ON service_connection_auth_states(session_digest);
-- Protect origin grants even when an old replica edits a server. Path-only
-- changes are checked at runtime and do not remove grants here.
-- +goose StatementBegin
CREATE FUNCTION service_connection_origin(value text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
    WITH authority AS (
        SELECT regexp_replace(lower(substring(btrim(value) from '^([^/]+://[^/]+)')), '\.(:[0-9]+)?$', '\1') AS v
    ) SELECT CASE WHEN v LIKE 'https://%' THEN regexp_replace(v, ':443$', '')
                  WHEN v LIKE 'http://%' THEN regexp_replace(v, ':80$', '') ELSE v END FROM authority;
$$;
CREATE FUNCTION reset_service_connection_grants() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE removed bigint;
BEGIN
    IF OLD.auth_provider_id IS DISTINCT FROM NEW.auth_provider_id OR OLD.auth_mode IS DISTINCT FROM NEW.auth_mode
       OR service_connection_origin(OLD.url) IS DISTINCT FROM service_connection_origin(NEW.url) THEN
        -- Changing a consented destination also invalidates pending consent
        -- snapshots and narrowed caches, without destroying the shared account.
        WITH affected AS MATERIALIZED (
            SELECT sc.id FROM service_connections sc JOIN service_connection_server_grants g ON g.connection_id = sc.id
            WHERE g.server_id = NEW.id ORDER BY sc.id FOR UPDATE OF sc
        ) UPDATE service_connections sc SET revision = revision + 1, generation = generation + 1
            FROM affected WHERE sc.id = affected.id;
        DELETE FROM service_connection_auth_states WHERE connection_id IN
            (SELECT connection_id FROM service_connection_server_grants WHERE server_id = NEW.id);
        DELETE FROM service_connection_server_grants WHERE server_id = NEW.id;
        GET DIAGNOSTICS removed = ROW_COUNT;
        IF removed > 0 THEN
            INSERT INTO audit_log(actor_kind, team_id, action, target_type, target_id, metadata)
            VALUES ('system', NEW.team_id, 'mcp_server.service_grants_reset', 'mcp_server', NEW.id::text,
                jsonb_build_object('grantsDeleted',removed,'oldOrigin',service_connection_origin(OLD.url),
                    'newOrigin',service_connection_origin(NEW.url)));
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER service_connection_grants_reset AFTER UPDATE ON mcp_servers FOR EACH ROW EXECUTE FUNCTION reset_service_connection_grants();
-- Session-first deletion, including logout/expiry/suspension and old replicas.
-- +goose StatementBegin
CREATE FUNCTION delete_service_session_states() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM service_connection_auth_states WHERE session_digest = encode(sha256(convert_to(OLD.id::text, 'UTF8')), 'hex');
    RETURN OLD;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER service_session_states_delete AFTER DELETE ON sessions FOR EACH ROW EXECUTE FUNCTION delete_service_session_states();
-- +goose StatementBegin
CREATE FUNCTION reset_service_provider_connections() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.client_id IS DISTINCT FROM NEW.client_id OR OLD.token_url IS DISTINCT FROM NEW.token_url
       OR OLD.authorization_url IS DISTINCT FROM NEW.authorization_url OR OLD.resource IS DISTINCT FROM NEW.resource
       OR OLD.issuer IS DISTINCT FROM NEW.issuer OR OLD.link_provider_id IS DISTINCT FROM NEW.link_provider_id THEN
        UPDATE service_connections SET status = 'needs_reconsent', access_token_cipher = NULL, refresh_token_cipher = NULL,
            last_error_class = 'config', revision = revision + 1, generation = generation + 1
            WHERE provider_id = NEW.id OR provider_id IN (SELECT id FROM auth_providers WHERE link_provider_id = NEW.id);
        DELETE FROM service_connection_auth_states WHERE provider_id = NEW.id
            OR provider_id IN (SELECT id FROM auth_providers WHERE link_provider_id = NEW.id);
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER service_provider_connections_reset AFTER UPDATE ON auth_providers FOR EACH ROW EXECUTE FUNCTION reset_service_provider_connections();

-- +goose Down
DROP TRIGGER service_provider_connections_reset ON auth_providers;
DROP FUNCTION reset_service_provider_connections();
DROP TRIGGER service_session_states_delete ON sessions;
DROP FUNCTION delete_service_session_states();
DROP TRIGGER service_connection_grants_reset ON mcp_servers;
DROP FUNCTION reset_service_connection_grants();
DROP FUNCTION service_connection_origin(text);
DROP TABLE service_connection_auth_states;
DROP TABLE service_connection_server_grants;
DROP TABLE service_connection_accounts;
DROP TABLE service_connections;
ALTER TABLE service_accounts DROP CONSTRAINT service_accounts_id_team_unique;
