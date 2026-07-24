ALTER TABLE smart_alarm.notification_events
    ADD COLUMN IF NOT EXISTS lease_token bigint NOT NULL DEFAULT 0;

COMMENT ON COLUMN smart_alarm.notification_events.lease_token IS
    'Monotonic fencing token for notification delivery ownership.';
