ALTER TABLE smart_alarm.operations
    ADD COLUMN platform_rpc_id uuid,
    ADD COLUMN command_expires_at timestamptz;

CREATE UNIQUE INDEX operations_platform_rpc_uq
    ON smart_alarm.operations (tenant_id, platform_rpc_id)
    WHERE platform_rpc_id IS NOT NULL;

CREATE INDEX operations_command_pending_idx
    ON smart_alarm.operations (command_expires_at, updated_at, id)
    WHERE operation_type = 'device-command'
      AND state IN ('PENDING', 'QUEUED', 'OUTCOME_UNKNOWN');

ALTER TABLE smart_alarm.command_approvals
    DROP CONSTRAINT IF EXISTS command_approvals_reason_check,
    ADD CONSTRAINT command_approvals_reason_check
        CHECK (length(btrim(reason)) BETWEEN 1 AND 500),
    ADD COLUMN request_idempotency_key text
        CHECK (request_idempotency_key IS NULL OR length(request_idempotency_key) BETWEEN 8 AND 255),
    ADD COLUMN request_hash bytea
        CHECK (request_hash IS NULL OR octet_length(request_hash) = 32),
    ADD COLUMN decision_idempotency_key text
        CHECK (decision_idempotency_key IS NULL OR length(decision_idempotency_key) BETWEEN 8 AND 255),
    ADD COLUMN decision_hash bytea
        CHECK (decision_hash IS NULL OR octet_length(decision_hash) = 32),
    ADD COLUMN decision_reason text
        CHECK (decision_reason IS NULL OR length(btrim(decision_reason)) BETWEEN 1 AND 500),
    ADD COLUMN consumed_at timestamptz;

CREATE UNIQUE INDEX command_approvals_request_idempotency_uq
    ON smart_alarm.command_approvals (tenant_id, request_idempotency_key)
    WHERE request_idempotency_key IS NOT NULL;

CREATE UNIQUE INDEX command_approvals_decision_idempotency_uq
    ON smart_alarm.command_approvals (tenant_id, decision_idempotency_key)
    WHERE decision_idempotency_key IS NOT NULL;

CREATE INDEX command_batch_items_operation_idx
    ON smart_alarm.command_batch_items (tenant_id, operation_id)
    WHERE operation_id IS NOT NULL;

COMMENT ON COLUMN smart_alarm.operations.platform_rpc_id IS
    'Official ThingsBoard persistent RPC identity used for restart-safe reconciliation';
COMMENT ON COLUMN smart_alarm.operations.command_expires_at IS
    'Server-owned deadline after which an unresolved command converges to a terminal result';
