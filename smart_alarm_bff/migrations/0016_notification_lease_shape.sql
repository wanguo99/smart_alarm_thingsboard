ALTER TABLE smart_alarm.notification_events
    DROP CONSTRAINT IF EXISTS notification_events_lease_shape_ck,
    ADD CONSTRAINT notification_events_lease_shape_ck CHECK (
        (delivery_status = 'LEASED') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
    );
