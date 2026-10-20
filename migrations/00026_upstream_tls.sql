-- mTLS client certificates and a per-server CA for upstream connections
-- (roadmap #25, decision 74, docs/registry.md "TLS to the server").
--
--   * mcp_server_tls: at most one row per server (cascading) holding what its
--     TLS layer needs beyond the system defaults:
--       - ca_pem: a bundle of CA certificates (public; at most 64 KiB and ten
--         certificates, checked by the registry) that REPLACES the system
--         roots for this server only, and ca_sha256, the fingerprint of the
--         normalized bundle (what a review and the audit show);
--       - client_cert_pem: the client certificate chain the portal presents
--         (leaf first; public), client_key_cipher: its private key, sealed with
--         ENCRYPTION_KEY (internal/secrets, AAD "mcp_server_tls:<server id>:
--         client_key"), never returned, logged, audited or captured;
--         client_cert_sha256 (the leaf's fingerprint) and client_not_after (the
--         leaf's expiry, for the warnings).
--     The certificate and its key are set together, and a row exists only
--     while it holds something. TLS 1.2 is the minimum and there is no setting
--     that turns verification off.
--
--   * mcp_health_checks.error_class: the enumerated CHECK from 00003 gets in
--     the way of every new class (the new one is 'tls'), so it is replaced by
--     the length bound the other class columns have. The class names stay
--     enumerated in the application and the API. The previous release never
--     writes 'tls' and reads the column as text.
--
-- A new table and a widened check only (expand/contract): the previous release
-- ignores the table, and a server with a row here is reached by it without
-- the certificate or CA (its calls fail with a TLS error, never with a wider
-- trust).

-- +goose Up
CREATE TABLE mcp_server_tls (
    server_id          uuid        PRIMARY KEY REFERENCES mcp_servers (id) ON DELETE CASCADE,
    ca_pem             text        CHECK (char_length(ca_pem) BETWEEN 1 AND 65536),
    ca_sha256          text        CHECK (ca_sha256 ~ '^[0-9a-f]{64}$'),
    client_cert_pem    text        CHECK (char_length(client_cert_pem) BETWEEN 1 AND 65536),
    client_key_cipher  bytea,
    client_cert_sha256 text        CHECK (client_cert_sha256 ~ '^[0-9a-f]{64}$'),
    client_not_after   timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT mcp_server_tls_ca_together CHECK ((ca_pem IS NULL) = (ca_sha256 IS NULL)),
    CONSTRAINT mcp_server_tls_client_together CHECK (
        (client_cert_pem IS NULL) = (client_key_cipher IS NULL)
        AND (client_cert_pem IS NULL) = (client_cert_sha256 IS NULL)
        AND (client_cert_pem IS NULL) = (client_not_after IS NULL)),
    CONSTRAINT mcp_server_tls_something CHECK (ca_pem IS NOT NULL OR client_cert_pem IS NOT NULL)
);
CREATE INDEX mcp_server_tls_expiry_idx ON mcp_server_tls (client_not_after) WHERE client_not_after IS NOT NULL;

ALTER TABLE mcp_health_checks DROP CONSTRAINT IF EXISTS mcp_health_checks_error_class_check;
ALTER TABLE mcp_health_checks ADD CONSTRAINT mcp_health_checks_error_class_length CHECK (char_length(error_class) <= 64);

-- +goose Down
UPDATE mcp_health_checks SET error_class = 'unavailable' WHERE error_class = 'tls';
ALTER TABLE mcp_health_checks DROP CONSTRAINT IF EXISTS mcp_health_checks_error_class_length;
ALTER TABLE mcp_health_checks ADD CONSTRAINT mcp_health_checks_error_class_check CHECK (error_class IN ('unavailable', 'auth', 'not_found', 'rate_limited', 'bad_request',
                                                    'bad_response', 'config', 'timeout', 'too_large', 'not_allowed'));
DROP TABLE mcp_server_tls;
