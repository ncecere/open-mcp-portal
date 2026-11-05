-- name: UpdateDefinitionScanMode :one
UPDATE platform_settings SET definition_scan_mode = @mode, scan_revision = scan_revision + 1
WHERE id = 1 RETURNING *;

-- name: DeleteDefinitionFindings :exec
DELETE FROM scan_findings WHERE capability_id = @capability_id;

-- name: StoreDefinitionScan :exec
INSERT INTO definition_scans(capability_id,fingerprint,ruleset_version,status,reason)
VALUES (@capability_id,@fingerprint,@ruleset_version,@status,@reason)
ON CONFLICT (capability_id) DO UPDATE SET fingerprint=excluded.fingerprint,
 ruleset_version=excluded.ruleset_version,status=excluded.status,reason=excluded.reason,scanned_at=now();

-- name: InsertDefinitionFinding :exec
INSERT INTO scan_findings(capability_id,fingerprint,rule_id,ruleset_version,severity,count,location)
VALUES (@capability_id,@fingerprint,@rule_id,@ruleset_version,@severity,@count,@location);

-- name: GetDefinitionScan :one
SELECT * FROM definition_scans WHERE capability_id = @capability_id;

-- name: ListDefinitionFindings :many
SELECT * FROM scan_findings WHERE capability_id = @capability_id ORDER BY id;

-- name: DefinitionScanBackfill :many
SELECT c.server_id FROM mcp_capabilities c
LEFT JOIN definition_scans s ON s.capability_id=c.id
WHERE c.gone_at IS NULL AND (s.capability_id IS NULL OR s.fingerprint<>c.fingerprint OR s.ruleset_version<> @version OR s.status='incomplete')
GROUP BY c.server_id ORDER BY min(s.scanned_at) NULLS FIRST, c.server_id LIMIT 10;
