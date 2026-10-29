-- name: ListMCPServerEndpoints :many
SELECT * FROM mcp_server_endpoints WHERE server_id = $1 ORDER BY position;

-- name: ListMCPServerEndpointsForServers :many
SELECT * FROM mcp_server_endpoints WHERE server_id = ANY(sqlc.arg(server_ids)::uuid[]) ORDER BY server_id, position;

-- name: DeleteMCPServerEndpoints :exec
DELETE FROM mcp_server_endpoints WHERE server_id = $1;

-- name: InsertMCPServerEndpoint :one
INSERT INTO mcp_server_endpoints
    (id, server_id, position, url, enabled, auth_mode, credential_origin, credentials_cipher, credential_shapes, created_at, updated_at)
VALUES
    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: InsertMCPServerEndpointHealthCheck :one
INSERT INTO mcp_health_checks
    (server_id, ok, latency_ms, error_class, http_status, message, trigger, triggered_by, endpoint_id, endpoint_position, status_since, sign_in_required)
SELECT @server_id, @ok::bool, @latency_ms, @error_class, @http_status, @message, @trigger, @triggered_by,
       @endpoint_id::uuid, @endpoint_position::smallint,
       COALESCE((SELECT CASE WHEN p.ok = @ok::bool THEN p.status_since END
                 FROM mcp_health_checks p WHERE p.server_id = @server_id AND p.endpoint_id = @endpoint_id::uuid
                 ORDER BY p.checked_at DESC,p.id DESC LIMIT 1),now()),false
RETURNING *;
