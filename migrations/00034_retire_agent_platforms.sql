-- External-platform impersonation is retired (#68). Retain original tables,
-- marks and call/audit history. Never convert a legacy relay into ordinary
-- authority. Old replicas must fail closed too.
-- +goose Up

-- Serialize against old trust, assignment and key writers for this upgrade.
LOCK TABLE agent_platforms, service_accounts, service_account_keys IN SHARE ROW EXCLUSIVE MODE;

WITH platforms AS (
    UPDATE agent_platforms SET enabled = false, revision = revision + 1, updated_at = now()
    WHERE enabled RETURNING id
), accounts AS (
    UPDATE service_accounts SET enabled = false, revision = revision + 1, updated_at = now()
    WHERE relay_platform_id IS NOT NULL RETURNING id
), keys AS (
    UPDATE service_account_keys SET revoked_at = now()
    WHERE revoked_at IS NULL AND service_account_id IN
        (SELECT id FROM service_accounts WHERE relay_platform_id IS NOT NULL)
    RETURNING id
)
INSERT INTO audit_log (actor_kind, action, target_type, target_id, metadata)
SELECT 'system', 'agent_platform.retire', 'platform', 'external-agent-platforms',
    jsonb_build_object(
        'platformCount', (SELECT count(*) FROM platforms),
        'platformIds', (SELECT coalesce(jsonb_agg(id ORDER BY id), '[]'::jsonb) FROM platforms),
        'accountCount', (SELECT count(*) FROM accounts),
        'accountIds', (SELECT coalesce(jsonb_agg(id ORDER BY id), '[]'::jsonb) FROM accounts),
        'revokedKeyCount', (SELECT count(*) FROM keys),
        'revokedKeyIds', (SELECT coalesce(jsonb_agg(id ORDER BY id), '[]'::jsonb) FROM keys));

-- Static invoker functions: no dynamic SQL, no elevated role, no new grants.
-- +goose StatementBegin
CREATE FUNCTION retire_agent_platform_trust() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF NEW.enabled THEN
        RAISE EXCEPTION 'external agent-platform trust is permanently retired' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER retired_agent_platform_trust
BEFORE INSERT OR UPDATE ON agent_platforms
FOR EACH ROW EXECUTE FUNCTION retire_agent_platform_trust();

-- +goose StatementBegin
CREATE FUNCTION retire_relay_account() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.relay_platform_id IS NOT NULL THEN
            RAISE EXCEPTION 'new relay assignments are retired' USING ERRCODE = '23514';
        END IF;
    ELSE
        IF NEW.relay_platform_id IS DISTINCT FROM OLD.relay_platform_id THEN
            RAISE EXCEPTION 'retired relay marks cannot be assigned, changed or cleared' USING ERRCODE = '23514';
        END IF;
        IF OLD.relay_platform_id IS NOT NULL AND NEW.enabled THEN
            RAISE EXCEPTION 'retired relay accounts cannot be enabled; create a new ordinary account' USING ERRCODE = '23514';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER retired_relay_account
BEFORE INSERT OR UPDATE ON service_accounts
FOR EACH ROW EXECUTE FUNCTION retire_relay_account();

-- Old replicas cannot issue usable keys for retired accounts, or un-revoke
-- one. The table locks above serialize retirement with existing key writers.
-- +goose StatementBegin
CREATE FUNCTION retire_relay_key() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog, public, pg_temp AS $$
BEGIN
    IF NEW.revoked_at IS NULL AND EXISTS (
        SELECT 1 FROM public.service_accounts
        WHERE id = NEW.service_account_id AND relay_platform_id IS NOT NULL
    ) THEN
        RAISE EXCEPTION 'retired relay accounts cannot have active keys' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER retired_relay_key
BEFORE INSERT OR UPDATE ON service_account_keys
FOR EACH ROW EXECUTE FUNCTION retire_relay_key();

-- +goose Down
-- Forward-only security retirement. A downgrade must not restore trust,
-- credentials or authority. Restoring a backup also restores the old risk.
SELECT 1;
