-- Call records of /mcp/{slug} (internal/calls). Metadata only.

-- name: InsertMCPCall :one
INSERT INTO mcp_calls (
    request_id, method, exposed_name, gateway_id, gateway_slug, gateway_name, gateway_team_id,
    server_id, server_slug, server_name, server_team_id, capability_id, principal_kind, user_id, api_key_id,
    key_name, service_account_id, service_account_name, service_account_team_id, oauth_grant_id, oauth_client_name,
    oauth_client_kind, client_name, outcome, error_class, latency_ms, request_bytes, response_bytes, provider_slug, identity_sent,
    agent_id, agent_name, via_platform_id, via_platform_name, person_present, trace_id
) VALUES (
    @request_id, @method, @exposed_name, @gateway_id, @gateway_slug, @gateway_name, @gateway_team_id,
    @server_id, @server_slug, @server_name, @server_team_id, @capability_id, @principal_kind, @user_id, @api_key_id,
    @key_name, @service_account_id, @service_account_name, @service_account_team_id, @oauth_grant_id, @oauth_client_name,
    @oauth_client_kind, @client_name, @outcome, @error_class, @latency_ms, @request_bytes, @response_bytes, @provider_slug, @identity_sent,
    @agent_id, @agent_name, @via_platform_id, @via_platform_name, @person_present, @trace_id
)
RETURNING id, occurred_at;

-- name: ListMCPCalls :many
-- One page of calls, newest first. team_id: calls through the team's
-- gateways, to its servers, or by its service accounts (through any
-- gateway). Gateway, server, key and service account names are the current
-- ones while they exist, else the ones recorded. An OAuth client is verified
-- when it identified itself with a metadata document (recorded with the
-- call; older records: read from the grant while it exists).
SELECT c.id, c.occurred_at, c.request_id, c.method, c.exposed_name, c.gateway_id, c.server_id,
       c.principal_kind, c.user_id, c.client_name, c.outcome, c.error_class, c.latency_ms,
       c.request_bytes, c.response_bytes, c.service_account_id, c.oauth_client_name, c.provider_slug, c.identity_sent,
       c.agent_id, c.agent_name, c.via_platform_id, c.via_platform_name, c.person_present, c.trace_id,
       (g.id IS NOT NULL)::bool AS gateway_exists,
       COALESCE(g.slug, c.gateway_slug)::text AS gateway_slug, COALESCE(g.name, c.gateway_name)::text AS gateway_name,
       (s.id IS NOT NULL)::bool AS server_exists,
       COALESCE(s.slug, c.server_slug, '')::text AS server_slug, COALESCE(s.name, c.server_name, '')::text AS server_name,
       COALESCE(u.email::text, '')::text AS user_email,
       (CASE WHEN c.principal_kind = 'service_account' THEN COALESCE(sa.name, c.service_account_name, '')
             ELSE COALESCE(u.display_name, '') END)::text AS user_display_name,
       COALESCE(u.display_name, '')::text AS person_display_name,
       COALESCE(k.name, sk.name, c.key_name, '')::text AS api_key_name,
       COALESCE(st.slug, '')::text AS service_account_team_slug,
       (sa.id IS NOT NULL)::bool AS service_account_exists,
       (COALESCE(c.oauth_client_kind, og.client_kind, '') = 'metadata')::bool AS oauth_client_verified,
       c.gateway_team_id, c.server_team_id,
       COALESCE(p.by_gateway, false)::bool AS payload_by_gateway, COALESCE(p.by_server, false)::bool AS payload_by_server
FROM mcp_calls c
LEFT JOIN mcp_call_payloads p ON p.call_id = c.id
LEFT JOIN gateways g ON g.id = c.gateway_id
LEFT JOIN mcp_servers s ON s.id = c.server_id
LEFT JOIN users u ON u.id = c.user_id
LEFT JOIN api_keys k ON k.id = c.api_key_id AND c.principal_kind = 'api_key'
LEFT JOIN service_account_keys sk ON sk.id = c.api_key_id AND c.principal_kind = 'service_account'
LEFT JOIN service_accounts sa ON sa.id = c.service_account_id
LEFT JOIN teams st ON st.id = c.service_account_team_id
LEFT JOIN oauth_grants og ON og.id = c.oauth_grant_id AND c.principal_kind = 'oauth' AND c.oauth_client_kind IS NULL
WHERE (sqlc.narg(team_id)::uuid IS NULL
       OR c.gateway_team_id = sqlc.narg(team_id)::uuid OR c.server_team_id = sqlc.narg(team_id)::uuid
       OR c.service_account_team_id = sqlc.narg(team_id)::uuid)
  AND (sqlc.narg(gateway_id)::uuid IS NULL OR c.gateway_id = sqlc.narg(gateway_id)::uuid)
  AND (sqlc.narg(server_id)::uuid IS NULL OR c.server_id = sqlc.narg(server_id)::uuid)
  AND (sqlc.narg(user_id)::uuid IS NULL OR c.user_id = sqlc.narg(user_id)::uuid)
  AND (sqlc.narg(service_account_id)::uuid IS NULL OR c.service_account_id = sqlc.narg(service_account_id)::uuid)
  AND (sqlc.narg(outcome)::text IS NULL OR c.outcome = sqlc.narg(outcome)::text)
  AND (sqlc.narg(identity_sent)::bool IS NULL OR c.identity_sent = sqlc.narg(identity_sent)::bool)
  AND (sqlc.narg(occurred_from)::timestamptz IS NULL OR c.occurred_at >= sqlc.narg(occurred_from)::timestamptz)
  AND (sqlc.narg(occurred_to)::timestamptz IS NULL OR c.occurred_at < sqlc.narg(occurred_to)::timestamptz)
  AND (sqlc.narg(before_id)::bigint IS NULL OR c.id < sqlc.narg(before_id)::bigint)
  AND (sqlc.narg(call_id)::bigint IS NULL OR c.id = sqlc.narg(call_id)::bigint)
ORDER BY c.id DESC
LIMIT @page_size;
