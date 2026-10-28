-- name: InsertAudit :exec
INSERT INTO audit_log (
    actor_kind, actor_user_id, team_id, action, target_type, target_id,
    before_state, after_state, metadata, request_id, client_ip,
    actor_token_id, actor_token_name, actor_token_kind
) VALUES (
    @actor_kind, @actor_user_id, @team_id, @action, @target_type, @target_id,
    @before_state, @after_state, @metadata, @request_id, @client_ip,
    @actor_token_id, @actor_token_name, @actor_token_kind
);

-- name: ListAudit :many
-- One page of the audit log, newest first, with the actor and the target's
-- name resolved at read time. live_label is the target's current name (''
-- when it no longer exists); recorded_label is the last name the log
-- recorded for the same target, used for deleted targets ('' when none).
-- Names are never empty, so '' means unknown.
-- Every target type the code audits is covered here (a test enumerates them).
-- action_prefix and exclude_prefixes are LIKE-escaped by the caller.
-- actor_kind: 'system' for the system's entries.
SELECT a.id, a.occurred_at, a.actor_kind, a.actor_user_id, a.team_id, a.action,
       a.target_type, a.target_id, a.before_state, a.after_state, a.metadata,
       a.request_id, a.client_ip, a.actor_token_id, a.actor_token_name, a.actor_token_kind,
       COALESCE(u.email::text, '')::text AS actor_email,
       COALESCE(tm.name, '')::text AS team_name, COALESCE(tm.slug, '')::text AS team_slug,
       u.display_name AS actor_display_name,
       COALESCE(live.label, '')::text AS live_label,
       COALESCE(CASE WHEN live.label IS NULL THEN (
           SELECT COALESCE(h.metadata->>'name', h.after_state->>'name', h.after_state->>'displayName',
                           h.after_state->>'email', h.before_state->>'name',
                           h.before_state->>'displayName', h.before_state->>'email')
           FROM audit_log h
           WHERE h.target_type = a.target_type AND h.target_id = a.target_id AND a.target_id <> ''
             AND COALESCE(h.metadata->>'name', h.after_state->>'name', h.after_state->>'displayName',
                          h.after_state->>'email', h.before_state->>'name',
                          h.before_state->>'displayName', h.before_state->>'email') IS NOT NULL
           ORDER BY h.id DESC
           LIMIT 1
       ) END, '')::text AS recorded_label
FROM audit_log a
CROSS JOIN LATERAL (
    SELECT CASE WHEN a.target_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                THEN a.target_id::uuid END AS target_uuid
) ids
LEFT JOIN users u ON u.id = a.actor_user_id
LEFT JOIN teams tm ON tm.id = a.team_id
CROSS JOIN LATERAL (
    SELECT (CASE a.target_type
        WHEN 'team' THEN (SELECT t.name FROM teams t WHERE t.id = ids.target_uuid)
        WHEN 'user' THEN (SELECT COALESCE(NULLIF(x.display_name, ''), x.email::text) FROM users x WHERE x.id = ids.target_uuid)
        WHEN 'team_invite' THEN (SELECT i.email::text FROM team_invites i WHERE i.id = ids.target_uuid)
        WHEN 'mcp_server' THEN (SELECT s.name FROM mcp_servers s WHERE s.id = ids.target_uuid)
        WHEN 'mcp_capability' THEN (SELECT s.name || ' · ' || c.name FROM mcp_capabilities c JOIN mcp_servers s ON s.id = c.server_id
                                    WHERE c.id = ids.target_uuid)
        WHEN 'gateway' THEN (SELECT g.name FROM gateways g WHERE g.id = ids.target_uuid)
        WHEN 'approval_rule' THEN (SELECT r.name FROM approval_rules r WHERE r.id = ids.target_uuid)
        WHEN 'approval_request' THEN (SELECT r.exposed_name FROM approval_requests r WHERE r.id = ids.target_uuid)
        WHEN 'gateway_grant' THEN (SELECT g.name || ' · ' || COALESCE(t.slug, u.email::text, gg.group_name)
                                   FROM gateway_grants gg JOIN gateways g ON g.id = gg.gateway_id
                                   LEFT JOIN teams t ON t.id = gg.team_id LEFT JOIN users u ON u.id = gg.user_id
                                   WHERE gg.id = ids.target_uuid)
        WHEN 'api_key' THEN (SELECT k.name FROM api_keys k WHERE k.id = ids.target_uuid)
        WHEN 'oauth_client' THEN (SELECT oc.client_name FROM oauth_clients oc WHERE oc.id = ids.target_uuid)
        WHEN 'oauth_grant' THEN (SELECT og.client_name || ' · ' || g.name FROM oauth_grants og JOIN gateways g ON g.id = og.gateway_id
                                 WHERE og.id = ids.target_uuid)
        WHEN 'automation_token' THEN (SELECT at.name FROM automation_tokens at WHERE at.id = ids.target_uuid)
        WHEN 'notification_destination' THEN (SELECT nd.name FROM notification_destinations nd WHERE nd.id = ids.target_uuid)
        WHEN 'service_connection' THEN (SELECT sc.name FROM service_connections sc WHERE sc.id = ids.target_uuid)
        WHEN 'service_account' THEN (SELECT sa.name FROM service_accounts sa WHERE sa.id = ids.target_uuid)
        WHEN 'service_account_key' THEN (SELECT sa.name || ' · ' || k.name FROM service_account_keys k
                                         JOIN service_accounts sa ON sa.id = k.service_account_id WHERE k.id = ids.target_uuid)
        WHEN 'auth_provider' THEN (SELECT ap.name FROM auth_providers ap WHERE ap.id = ids.target_uuid)
        WHEN 'agent_platform' THEN (SELECT p.name FROM agent_platforms p WHERE p.id = ids.target_uuid)
        WHEN 'provider_connection' THEN (SELECT COALESCE(NULLIF(cu.display_name, ''), cu.email::text) || ' · ' || cp.name
                                         FROM provider_connections pc JOIN users cu ON cu.id = pc.user_id
                                         JOIN auth_providers cp ON cp.id = pc.provider_id WHERE pc.id = ids.target_uuid)
        WHEN 'person_secret' THEN (SELECT COALESCE(NULLIF(pu.display_name, ''), pu.email::text) || ' · ' || ps2.name
                                   FROM person_secrets ps JOIN users pu ON pu.id = ps.user_id
                                   JOIN mcp_servers ps2 ON ps2.id = ps.server_id WHERE ps.id = ids.target_uuid)
        WHEN 'platform_settings' THEN (CASE a.target_id WHEN 'publishing' THEN 'Publishing settings' WHEN 'network' THEN 'Internal networks'
                                       WHEN 'oauth_clients' THEN 'Trusted clients' WHEN 'limits' THEN 'Rate limits'
                                       WHEN 'capture' THEN 'Payload capture' WHEN 'retention' THEN 'Retention'
                                       WHEN 'keys' THEN 'Encryption keys' WHEN 'notifications' THEN 'Notifications' END)
        WHEN 'mcp_call' THEN (SELECT 'Call ' || mc.id::text || ' · ' || COALESCE(mc.exposed_name, mc.method) FROM mcp_calls mc
                              WHERE mc.id = (CASE WHEN a.target_id ~ '^[0-9]{1,18}$' THEN a.target_id::bigint END))
    END)::text AS label
) live
WHERE (sqlc.narg(team_id)::uuid IS NULL OR a.team_id = sqlc.narg(team_id)::uuid)
  AND (sqlc.narg(before_id)::bigint IS NULL OR a.id < sqlc.narg(before_id)::bigint)
  AND (sqlc.narg(action)::text IS NULL OR a.action = sqlc.narg(action)::text)
  AND (sqlc.narg(action_prefix)::text IS NULL OR a.action LIKE sqlc.narg(action_prefix)::text || '%' ESCAPE '\')
  AND NOT EXISTS (SELECT 1 FROM unnest(sqlc.arg(exclude_prefixes)::text[]) AS x(prefix) WHERE a.action LIKE x.prefix || '%' ESCAPE '\')
  AND (sqlc.narg(actor_user_id)::uuid IS NULL OR a.actor_user_id = sqlc.narg(actor_user_id)::uuid)
  AND (sqlc.narg(actor_kind)::text IS NULL OR a.actor_kind = sqlc.narg(actor_kind)::text)
  AND (sqlc.narg(target_type)::text IS NULL OR a.target_type = sqlc.narg(target_type)::text)
  AND (sqlc.narg(occurred_from)::timestamptz IS NULL OR a.occurred_at >= sqlc.narg(occurred_from)::timestamptz)
  AND (sqlc.narg(occurred_to)::timestamptz IS NULL OR a.occurred_at < sqlc.narg(occurred_to)::timestamptz)
ORDER BY a.id DESC
LIMIT @page_size;

-- name: CountTokenAuditEntries :one
-- Audit entries one automation token wrote for one request (the request ID
-- is on every entry), so a token's mutation that wrote none can be recorded.
SELECT count(*) FROM audit_log
WHERE actor_token_id = @token_id AND request_id = @request_id AND occurred_at > now() - interval '5 minutes';
