-- Private sensitive-call workflow notices. Expand the event/preference checks
-- without removing any event understood by the previous release. Approval
-- events deliberately do NOT expand webhook destination subscription choices.
-- +goose Up
ALTER TABLE notification_events DROP CONSTRAINT notification_events_event_check;
ALTER TABLE notification_events ADD CONSTRAINT notification_events_event_check CHECK (event IN (
    'server.unhealthy', 'server.recovered', 'capability.changed', 'publish.requested',
    'publish.decided', 'connection.needs_reconsent', 'upstream_signin.lapsed', 'key.expiring',
    'approval.requested', 'approval.decided'));

ALTER TABLE notification_preferences DROP CONSTRAINT notification_preferences_event_check;
ALTER TABLE notification_preferences ADD CONSTRAINT notification_preferences_event_check CHECK (event IN (
    'server.unhealthy', 'server.recovered', 'capability.changed', 'publish.requested',
    'publish.decided', 'connection.needs_reconsent', 'upstream_signin.lapsed', 'key.expiring',
    'approval.requested', 'approval.decided'));

-- +goose Down
-- Forward-only: shrinking the checks would reject rows written by this release.
SELECT 1;
