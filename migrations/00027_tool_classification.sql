-- +goose Up
ALTER TABLE mcp_capabilities
    ADD COLUMN tool_class text CHECK (tool_class IN ('read', 'write', 'destructive')),
    ADD COLUMN class_set_by uuid REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN class_set_at timestamptz,
    ADD CONSTRAINT mcp_capabilities_tool_class_tools_only CHECK (kind = 'tool' OR (tool_class IS NULL AND class_set_by IS NULL AND class_set_at IS NULL));
ALTER TABLE mcp_calls ADD COLUMN tool_class text CHECK (tool_class IN ('read', 'write', 'destructive'));

-- +goose Down
ALTER TABLE mcp_calls DROP COLUMN tool_class;
ALTER TABLE mcp_capabilities DROP CONSTRAINT mcp_capabilities_tool_class_tools_only,
    DROP COLUMN class_set_at, DROP COLUMN class_set_by, DROP COLUMN tool_class;
