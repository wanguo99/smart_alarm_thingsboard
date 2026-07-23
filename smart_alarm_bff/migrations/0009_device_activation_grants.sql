CREATE TABLE smart_alarm.device_activation_grants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES smart_alarm.tenants(id),
    device_id uuid NOT NULL,
    operation_id uuid NOT NULL REFERENCES smart_alarm.operations(id),
    request_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    credential_version bigint NOT NULL CHECK (credential_version > 0),
    credential_secret_ref text NOT NULL CHECK (length(credential_secret_ref) BETWEEN 1 AND 1024),
    status text NOT NULL DEFAULT 'READY' CHECK (status IN ('READY', 'CONSUMED', 'REVOKED')),
    expires_at timestamptz NOT NULL,
    delivered_at timestamptz,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, device_id, credential_version),
    UNIQUE (operation_id, credential_version),
    FOREIGN KEY (tenant_id, device_id) REFERENCES smart_alarm.devices(tenant_id, id),
    CHECK (expires_at > created_at),
    CHECK ((status = 'CONSUMED') = (consumed_at IS NOT NULL)),
    CHECK (status <> 'READY' OR consumed_at IS NULL)
);

CREATE INDEX device_activation_grants_ready_idx
    ON smart_alarm.device_activation_grants (expires_at, device_id)
    WHERE status = 'READY';

ALTER TABLE smart_alarm.device_activation_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE smart_alarm.device_activation_grants FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_device_activation_grants
    ON smart_alarm.device_activation_grants
    USING (smart_alarm.is_system_scope() OR tenant_id = smart_alarm.current_tenant_id())
    WITH CHECK (smart_alarm.is_system_scope() OR tenant_id = smart_alarm.current_tenant_id());

COMMENT ON TABLE smart_alarm.device_activation_grants IS
    'One-time device credential delivery metadata; credential_secret_ref is an encrypted file reference and never plaintext';
COMMENT ON COLUMN smart_alarm.device_activation_grants.credential_secret_ref IS
    'Versioned encrypted file reference shared by the BFF API and lifecycle worker';
