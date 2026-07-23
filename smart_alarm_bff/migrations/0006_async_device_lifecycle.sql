ALTER TABLE smart_alarm.tenants
    ADD COLUMN service_identity_secret_ref text CHECK (service_identity_secret_ref IS NULL OR length(service_identity_secret_ref) BETWEEN 1 AND 512);

ALTER TABLE smart_alarm.devices
    ALTER COLUMN thingsboard_device_id DROP NOT NULL,
    ALTER COLUMN credential_secret_ref DROP NOT NULL,
    ADD CONSTRAINT device_platform_binding_ck CHECK (
        lifecycle_state IN ('ACTIVATING', 'ACTIVATION_FAILED')
        OR (thingsboard_device_id IS NOT NULL AND credential_secret_ref IS NOT NULL)
    );
