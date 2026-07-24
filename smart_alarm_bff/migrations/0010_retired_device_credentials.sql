ALTER TABLE smart_alarm.device_activation_grants
    DROP CONSTRAINT device_activation_grants_check1;

ALTER TABLE smart_alarm.device_activation_grants
    ADD CONSTRAINT device_activation_grants_consumed_at_ck CHECK (
        (status = 'CONSUMED' AND consumed_at IS NOT NULL)
        OR (status IN ('READY', 'REVOKED'))
    );

ALTER TABLE smart_alarm.devices
    DROP CONSTRAINT device_platform_binding_ck;

ALTER TABLE smart_alarm.devices
    ADD CONSTRAINT device_platform_binding_ck CHECK (
        lifecycle_state IN ('ACTIVATING', 'ACTIVATION_FAILED')
        OR (
            lifecycle_state = 'RETIRED'
            AND thingsboard_device_id IS NOT NULL
            AND credential_secret_ref IS NULL
        )
        OR (
            thingsboard_device_id IS NOT NULL
            AND credential_secret_ref IS NOT NULL
        )
    );

COMMENT ON CONSTRAINT device_platform_binding_ck ON smart_alarm.devices IS
    'Active platform bindings keep an encrypted credential reference; retired devices retain only the ThingsBoard entity ID for history';
