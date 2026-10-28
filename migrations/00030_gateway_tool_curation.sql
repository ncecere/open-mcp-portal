-- +goose Up
ALTER TABLE gateway_capabilities
    ADD COLUMN name_override text CHECK (name_override ~ '^[A-Za-z0-9_.-]{1,128}$'),
    ADD COLUMN description_override text CHECK (char_length(description_override) <= 2000),
    ADD COLUMN constraints jsonb,
    ADD COLUMN base_fingerprint text,
    ADD COLUMN curated_by uuid REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN curated_at timestamptz,
    ADD CONSTRAINT gateway_curation_shape CHECK (
        (base_fingerprint IS NULL AND name_override IS NULL AND description_override IS NULL AND constraints IS NULL AND curated_at IS NULL AND curated_by IS NULL)
        OR (base_fingerprint IS NOT NULL AND curated_at IS NOT NULL AND constraints IS NOT NULL AND jsonb_typeof(constraints) = 'object')
    );

-- +goose Down
ALTER TABLE gateway_capabilities
    DROP CONSTRAINT gateway_curation_shape,
    DROP COLUMN curated_at,
    DROP COLUMN curated_by,
    DROP COLUMN base_fingerprint,
    DROP COLUMN constraints,
    DROP COLUMN description_override,
    DROP COLUMN name_override;
