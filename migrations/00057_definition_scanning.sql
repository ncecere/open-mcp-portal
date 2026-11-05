-- +goose Up
-- Expand-only: previous releases ignore these fields and tables. Runtime grants
-- are reconciled by store.ReconcileRuntimeGrants (ordinary public CRUD tables).
ALTER TABLE platform_settings
 ADD COLUMN definition_scan_mode text NOT NULL DEFAULT 'shadow' CHECK (definition_scan_mode IN ('off','shadow')),
 ADD COLUMN scan_revision bigint NOT NULL DEFAULT 1;
CREATE TABLE definition_scans (
 capability_id uuid PRIMARY KEY REFERENCES mcp_capabilities(id) ON DELETE CASCADE,
 fingerprint text NOT NULL,
 ruleset_version text NOT NULL CHECK (ruleset_version ~ '^[a-z0-9_.-]{1,32}$'),
 status text NOT NULL CHECK (status IN ('scanned','incomplete')),
 reason text NOT NULL CHECK (reason IN ('','budget','depth','size','panic','invalid_json','busy')),
 scanned_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE scan_findings (
 id bigserial PRIMARY KEY,
 occurred_at timestamptz NOT NULL DEFAULT now(),
 capability_id uuid NOT NULL REFERENCES mcp_capabilities(id) ON DELETE CASCADE,
 fingerprint text NOT NULL,
 stage text NOT NULL DEFAULT 'definition' CHECK (stage = 'definition'),
 rule_id text NOT NULL CHECK (rule_id ~ '^[a-z0-9_.:-]{1,64}$'),
 ruleset_version text NOT NULL CHECK (ruleset_version ~ '^[a-z0-9_.-]{1,32}$'),
 severity text NOT NULL CHECK (severity IN ('info','low','medium','high')),
 count integer NOT NULL CHECK (count BETWEEN 1 AND 100000),
 action text NOT NULL DEFAULT 'annotated' CHECK (action = 'annotated'),
 location text NOT NULL CHECK (length(location)<=200 AND location ~ '^(/[a-zA-Z0-9_@.-]+)*$')
);
CREATE INDEX scan_findings_capability ON scan_findings(capability_id);
-- Definition findings are replaced with their scan, and both child tables are
-- deleted by capability/server/team deletion. No mcp_calls child or purge-function
-- change is needed; payload retention is intentionally unrelated.
