-- Trusted agent platforms (roadmap #55-#58, decisions 65 and 66,
-- docs/agent-platforms.md): the portal can trust an external agent platform
-- (Pi Durable Platform) that relays its agents' calls through a team service
-- account and names the person each agent acts for in a signed token.
--
--   * agent_platforms: the platforms a platform admin trusts as issuers: name,
--     issuer (iss), JWKS URL, the audience the portal expects, enabled, and the
--     result of the last JWKS fetch (when, ok, error code, key IDs). No
--     secrets: the keys are public.
--   * agent_token_jtis: the jti of every accepted token, kept until the token
--     can no longer be valid (exp plus the clock skew), so a token is used once
--     across every replica. Deleted by the retention loop.
--   * service_accounts.relay_platform_id (+ who and when): the account is a
--     relay for that platform, set only by a platform admin. Only a relay
--     account's calls may carry an agent token. Deleting the platform clears
--     the mark (the account is an ordinary service account again).
--   * mcp_calls.agent_id/agent_name/via_platform_id/via_platform_name/
--     person_present: the agent a relayed call came from, the platform it came
--     through and whether the person was present. user_id of a relayed call is
--     the person; the principal stays the relay service account.
--   * mcp_servers.requires_present_person and mcp_capabilities.
--     requires_present_person: relayed calls whose person is not present are
--     refused (the capability's value, when set, wins over the server's).
--     NULL on a capability: follow the server. Default off.
--
-- New tables and nullable or defaulted columns only (expand/contract): the
-- previous release ignores them. No CHECK on mcp_calls.outcome or error_class
-- changes: the refusals use outcomes and classes that exist.

-- +goose Up
CREATE TABLE agent_platforms (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text        NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
    issuer          text        NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 500),
    jwks_url        text        NOT NULL CHECK (char_length(jwks_url) BETWEEN 1 AND 500),
    audience        text        NOT NULL CHECK (char_length(audience) BETWEEN 1 AND 500),
    enabled         boolean     NOT NULL DEFAULT true,
    revision        bigint      NOT NULL DEFAULT 1,
    -- The last JWKS fetch by any replica (an admin's Test or a verification).
    jwks_checked_at timestamptz,
    jwks_ok         boolean,
    jwks_error      text        CHECK (char_length(jwks_error) <= 64),
    jwks_key_ids    text[]      NOT NULL DEFAULT '{}' CHECK (cardinality(jwks_key_ids) <= 32),
    created_by      uuid        REFERENCES users (id) ON DELETE SET NULL,
    updated_by      uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT agent_platforms_name_key UNIQUE (name),
    CONSTRAINT agent_platforms_issuer_key UNIQUE (issuer),
    CONSTRAINT agent_platforms_jwks_result CHECK ((jwks_checked_at IS NULL) = (jwks_ok IS NULL))
);

CREATE TABLE agent_token_jtis (
    platform_id uuid        NOT NULL REFERENCES agent_platforms (id) ON DELETE CASCADE,
    jti         text        NOT NULL CHECK (char_length(jti) BETWEEN 1 AND 128),
    expires_at  timestamptz NOT NULL,
    PRIMARY KEY (platform_id, jti)
);
CREATE INDEX agent_token_jtis_expires_idx ON agent_token_jtis (expires_at);

ALTER TABLE service_accounts
    ADD COLUMN relay_platform_id uuid        REFERENCES agent_platforms (id) ON DELETE SET NULL,
    ADD COLUMN relay_marked_by   uuid        REFERENCES users (id) ON DELETE SET NULL,
    ADD COLUMN relay_marked_at   timestamptz;
CREATE INDEX service_accounts_relay_idx ON service_accounts (relay_platform_id) WHERE relay_platform_id IS NOT NULL;

ALTER TABLE mcp_calls
    ADD COLUMN agent_id          text    CHECK (char_length(agent_id) <= 128),
    ADD COLUMN agent_name        text    CHECK (char_length(agent_name) <= 200),
    ADD COLUMN via_platform_id   uuid,
    ADD COLUMN via_platform_name text    CHECK (char_length(via_platform_name) <= 100),
    ADD COLUMN person_present    boolean;
CREATE INDEX mcp_calls_via_platform_idx ON mcp_calls (via_platform_id, id DESC) WHERE via_platform_id IS NOT NULL;

ALTER TABLE mcp_servers ADD COLUMN requires_present_person boolean NOT NULL DEFAULT false;
ALTER TABLE mcp_capabilities ADD COLUMN requires_present_person boolean;

-- +goose Down
ALTER TABLE mcp_capabilities DROP COLUMN requires_present_person;
ALTER TABLE mcp_servers DROP COLUMN requires_present_person;
DROP INDEX mcp_calls_via_platform_idx;
ALTER TABLE mcp_calls
    DROP COLUMN person_present,
    DROP COLUMN via_platform_name,
    DROP COLUMN via_platform_id,
    DROP COLUMN agent_name,
    DROP COLUMN agent_id;
DROP INDEX service_accounts_relay_idx;
ALTER TABLE service_accounts
    DROP COLUMN relay_marked_at,
    DROP COLUMN relay_marked_by,
    DROP COLUMN relay_platform_id;
DROP TABLE agent_token_jtis;
DROP TABLE agent_platforms;
