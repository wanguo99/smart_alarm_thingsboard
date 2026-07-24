ALTER TABLE smart_alarm.assets
    ADD COLUMN platform_sync_status text NOT NULL DEFAULT 'LOCAL_ONLY'
        CHECK (platform_sync_status IN (
            'LOCAL_ONLY', 'PENDING_CREATE', 'PENDING_UPDATE', 'PENDING_DELETE', 'SYNCED', 'ERROR'
        )),
    ADD COLUMN platform_error_code text,
    ADD COLUMN platform_synced_at timestamptz;

UPDATE smart_alarm.assets
SET platform_sync_status = 'SYNCED', platform_synced_at = clock_timestamp()
WHERE thingsboard_asset_id IS NOT NULL;

ALTER TABLE smart_alarm.device_profiles
    ADD COLUMN platform_sync_status text NOT NULL DEFAULT 'LOCAL_ONLY'
        CHECK (platform_sync_status IN (
            'LOCAL_ONLY', 'PENDING_CREATE', 'PENDING_UPDATE', 'PENDING_DELETE', 'SYNCED', 'ERROR'
        )),
    ADD COLUMN platform_error_code text,
    ADD COLUMN platform_synced_at timestamptz;

UPDATE smart_alarm.device_profiles
SET platform_sync_status = 'SYNCED', platform_synced_at = clock_timestamp()
WHERE thingsboard_profile_id IS NOT NULL;

CREATE INDEX assets_platform_sync_idx
    ON smart_alarm.assets (tenant_id, platform_sync_status, updated_at);

CREATE INDEX device_profiles_platform_sync_idx
    ON smart_alarm.device_profiles (tenant_id, platform_sync_status, updated_at);

COMMENT ON COLUMN smart_alarm.assets.platform_sync_status IS
    'Product-to-ThingsBoard Asset synchronization state; LOCAL_ONLY is never treated as synchronized';
COMMENT ON COLUMN smart_alarm.device_profiles.platform_sync_status IS
    'Product-to-ThingsBoard Device Profile synchronization state; LOCAL_ONLY is never treated as synchronized';
