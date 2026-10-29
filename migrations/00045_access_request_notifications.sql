-- +goose Up
-- Private notices, never webhook subscriptions. Preserve all prior event names.
ALTER TABLE notification_events DROP CONSTRAINT notification_events_event_check;
ALTER TABLE notification_events ADD CONSTRAINT notification_events_event_check CHECK (event IN (
    'server.unhealthy', 'server.recovered', 'capability.changed', 'publish.requested',
    'publish.decided', 'connection.needs_reconsent', 'upstream_signin.lapsed', 'key.expiring',
    'approval.requested', 'approval.decided', 'access.requested', 'access.decided'));
ALTER TABLE notification_preferences DROP CONSTRAINT notification_preferences_event_check;
ALTER TABLE notification_preferences ADD CONSTRAINT notification_preferences_event_check CHECK (event IN (
    'server.unhealthy', 'server.recovered', 'capability.changed', 'publish.requested',
    'publish.decided', 'connection.needs_reconsent', 'upstream_signin.lapsed', 'key.expiring',
    'approval.requested', 'approval.decided', 'access.requested', 'access.decided'));

-- +goose Down
SELECT 1;
