"""Tenant-scoped durable device command, approval and batch APIs."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any, Awaitable, Callable
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .command_handlers import (
    CANCELLATION_WARNING,
    COMMAND_CANCEL_EVENT,
    COMMAND_POLICIES,
    COMMAND_SUBMIT_EVENT,
    PENDING_PLATFORM_STATUSES,
)
from .device_routes import _read_guard
from .directory_routes import _scoped_connection
from .policy import PolicyError, ProductPrincipal
from .session import SessionService
from .write_routes import (
    WriteError,
    _audit,
    _body_hash,
    _guard,
    _idempotency,
    _outbox,
    _tenant_scope,
    _write_error,
)


_COMMANDS = frozenset(COMMAND_POLICIES)
_BATCH_COMMANDS = frozenset({"ping", "health"})
_APPROVAL_STATUSES = frozenset({"PENDING", "APPROVED", "REJECTED", "CONSUMED", "EXPIRED"})


def _text(value: object, field: str, *, maximum: int = 256, required: bool = False) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise WriteError(f"invalid_{field}")
    return value


def _operation_status(state: str) -> str:
    return "PENDING" if state in {"PENDING", "QUEUED", "OUTCOME_UNKNOWN"} else state


def _command_response(row: Any) -> dict[str, object]:
    result = dict(row["result"])
    if row["state"] == "FAILED" and "error" not in result:
        result["error"] = {"code": row["error_code"] or "operation_failed"}
    return {
        "operationId": str(row["id"]),
        "status": _operation_status(row["state"]),
        "result": result,
    }


def _cancel_response(row: Any) -> dict[str, object]:
    return {
        "operationId": str(row["id"]),
        "kind": "command-cancel",
        "status": _operation_status(row["state"]),
        "result": dict(row["result"]),
    }


def _public_approval(row: Any) -> dict[str, object]:
    return {
        "approvalId": str(row["id"]),
        "deviceUid": str(row["device_uid"]),
        "command": row["command_type"],
        "reason": row["reason"],
        "requestedBy": str(row["requester_platform_user_id"]),
        "status": row["status"],
        "decidedBy": str(row["decision_platform_user_id"]) if row["decision_platform_user_id"] else None,
        "decisionReason": row["decision_reason"],
        "createdAt": int(row["created_at"].timestamp() * 1000),
        "expiresAt": int(row["expires_at"].timestamp() * 1000),
        "decidedAt": int(row["decided_at"].timestamp() * 1000) if row["decided_at"] else None,
        "consumedAt": int(row["consumed_at"].timestamp() * 1000) if row["consumed_at"] else None,
    }


async def _approval_row(connection: Any, tenant_id: UUID, approval_id: UUID) -> Any:
    return await connection.fetchrow(
        """
        SELECT a.*, d.device_uid,
               requester.thingsboard_user_id AS requester_platform_user_id,
               decision.thingsboard_user_id AS decision_platform_user_id
        FROM smart_alarm.command_approvals a
        JOIN smart_alarm.devices d ON d.tenant_id = a.tenant_id AND d.id = a.device_id
        JOIN smart_alarm.users requester ON requester.id = a.requester_user_id
        LEFT JOIN smart_alarm.users decision ON decision.id = a.decision_user_id
        WHERE a.tenant_id = $1 AND a.id = $2
        """,
        tenant_id, approval_id,
    )


async def _public_batch(connection: Any, tenant_id: UUID, batch_id: UUID) -> dict[str, object]:
    batch = await connection.fetchrow(
        """
        SELECT b.*, o.idempotency_key, o.result, u.thingsboard_user_id AS requested_by
        FROM smart_alarm.command_batches b
        JOIN smart_alarm.operations o ON o.id = b.operation_id AND o.tenant_id = b.tenant_id
        JOIN smart_alarm.users u ON u.id = o.actor_user_id
        WHERE b.tenant_id = $1 AND b.id = $2
        """,
        tenant_id, batch_id,
    )
    if batch is None:
        raise WriteError("command_batch_not_found", 404)
    items = await connection.fetch(
        """
        SELECT d.device_uid, i.operation_id, i.status, i.error_code
        FROM smart_alarm.command_batch_items i
        JOIN smart_alarm.devices d ON d.tenant_id = i.tenant_id AND d.id = i.device_id
        WHERE i.tenant_id = $1 AND i.batch_id = $2
        ORDER BY i.created_at, d.device_uid
        """,
        tenant_id, batch_id,
    )
    result = dict(batch["result"])
    status = {
        "PENDING": "CREATED",
        "RUNNING": "SUBMITTED" if batch["failed_count"] == 0 else "PARTIAL_FAILED",
        "COMPLETED": "SUBMITTED",
        "PARTIAL": "PARTIAL_FAILED",
        "FAILED": "FAILED",
        "CANCELLED": "FAILED",
    }[batch["status"]]
    return {
        "batchId": str(batch["id"]),
        "requestId": batch["idempotency_key"],
        "command": batch["command_type"],
        "reason": result.get("reason"),
        "requestedBy": str(batch["requested_by"]),
        "status": status,
        "totalCount": batch["total_count"],
        "acceptedCount": batch["accepted_count"],
        "failedCount": batch["failed_count"],
        "createdAt": int(batch["created_at"].timestamp() * 1000),
        "updatedAt": int(batch["updated_at"].timestamp() * 1000),
        "items": [
            {
                "deviceUid": str(item["device_uid"]),
                "operationId": str(item["operation_id"]) if item["operation_id"] else None,
                "status": "PENDING" if item["status"] in {"PENDING", "ACCEPTED"} else item["status"],
                "errorCode": item["error_code"],
            }
            for item in items
        ],
    }


async def _existing_operation(
    connection: Any,
    tenant_id: UUID,
    operation_type: str,
    key: str,
    request_hash: bytes,
) -> Any | None:
    row = await connection.fetchrow(
        """
        SELECT * FROM smart_alarm.operations
        WHERE tenant_id = $1 AND operation_type = $2 AND idempotency_key = $3
        """,
        tenant_id, operation_type, key,
    )
    if row is not None and bytes(row["request_hash"]) != request_hash:
        raise WriteError("idempotency_conflict", 409)
    return row


async def _command_device(
    connection: Any,
    tenant_id: UUID,
    customer_scope: UUID | None,
    device_uid: UUID,
) -> Any:
    row = await connection.fetchrow(
        """
        SELECT id, device_uid, customer_id, lifecycle_state, thingsboard_device_id
        FROM smart_alarm.devices
        WHERE tenant_id = $1 AND device_uid = $2
          AND ($3::uuid IS NULL OR customer_id = $3)
        FOR UPDATE
        """,
        tenant_id, device_uid, customer_scope,
    )
    if row is None:
        raise WriteError("device_not_found", 404)
    if row["lifecycle_state"] != "ACTIVE" or row["thingsboard_device_id"] is None:
        raise WriteError("device_not_commandable", 409)
    return row


async def _wait_for_operation(
    database: Callable[[], Awaitable[Any]],
    principal: ProductPrincipal,
    operation_id: UUID,
    timeout_seconds: float = 8.0,
) -> Any:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    while True:
        async with _scoped_connection(await database(), principal) as connection:
            row = await connection.fetchrow("SELECT * FROM smart_alarm.operations WHERE id = $1", operation_id)
        if row is None or row["state"] not in {"PENDING", "QUEUED", "OUTCOME_UNKNOWN"}:
            return row
        if loop.time() >= deadline:
            return row
        await asyncio.sleep(0.2)


def register_command_routes(
    router: APIRouter,
    sessions: SessionService,
    database: Callable[[], Awaitable[Any]],
) -> None:
    @router.post("/api/v1/device-management/devices/{device_uid}/commands")
    async def execute_command(device_uid: str, request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "devices:command:execute")
            tenant_id, customer_scope = _tenant_scope(principal)
            if set(body).difference({"command", "reason", "approvalId"}):
                raise WriteError("invalid_command")
            uid = UUID(device_uid)
            command = _text(body.get("command"), "command", maximum=32, required=True)
            reason = _text(body.get("reason"), "command_reason")
            approval_id = UUID(str(body["approvalId"])) if body.get("approvalId") is not None else None
            if command not in _COMMANDS:
                raise WriteError("invalid_command")
            if command in {"clearFaults", "reboot"} and reason is None:
                raise WriteError("command_reason_required")
            if command == "reboot" and approval_id is None:
                raise WriteError("command_approval_required", 409)
            if command != "reboot" and approval_id is not None:
                raise WriteError("invalid_command_approval")
            key = _idempotency(request)
            normalized: dict[str, object] = {"deviceUid": str(uid), "command": command}
            if reason is not None:
                normalized["reason"] = reason
            if approval_id is not None:
                normalized["approvalId"] = str(approval_id)
            request_hash = _body_hash(normalized)
            async with _scoped_connection(await database(), principal) as connection:
                existing = await _existing_operation(connection, tenant_id, "device-command", key, request_hash)
                if existing is not None:
                    return _command_response(existing)
                device = await _command_device(connection, tenant_id, customer_scope, uid)
                now = datetime.now(UTC)
                expires_at = now + timedelta(seconds=int(COMMAND_POLICIES[command]["expirationSeconds"]))
                if approval_id is not None:
                    approval = await connection.fetchrow(
                        """
                        SELECT * FROM smart_alarm.command_approvals
                        WHERE id = $1 AND tenant_id = $2 AND device_id = $3
                          AND command_type = 'reboot'
                        FOR UPDATE
                        """,
                        approval_id, tenant_id, device["id"],
                    )
                    if approval is None:
                        raise WriteError("command_approval_not_found", 404)
                    if approval["expires_at"] <= now:
                        await connection.execute(
                            "UPDATE smart_alarm.command_approvals SET status = 'EXPIRED', updated_at = clock_timestamp() WHERE id = $1 AND status IN ('PENDING', 'APPROVED')",
                            approval_id,
                        )
                        raise WriteError("approval_expired", 409)
                    if approval["status"] != "APPROVED":
                        raise WriteError("command_approval_unavailable", 409)
                    if approval["requester_user_id"] != principal.local_user_id or approval["reason"] != reason:
                        raise WriteError("command_approval_mismatch", 409)
                result = {
                    "command": command,
                    **({"reason": reason} if reason is not None else {}),
                    **({"approvalId": str(approval_id)} if approval_id is not None else {}),
                    "requestedBy": str(principal.platform_user_id),
                    "risk": COMMAND_POLICIES[command]["risk"],
                    "retryCount": COMMAND_POLICIES[command]["retries"],
                    "platformStatus": "SUBMITTING",
                    "expirationTime": int(expires_at.timestamp() * 1000),
                }
                operation = await connection.fetchrow(
                    """
                    INSERT INTO smart_alarm.operations (
                        tenant_id, customer_id, actor_user_id, operation_type, resource_type,
                        resource_id, idempotency_key, request_hash, state, result, command_expires_at
                    ) VALUES ($1, $2, $3, 'device-command', 'DEVICE', $4, $5, $6, 'QUEUED', $7::jsonb, $8)
                    RETURNING *
                    """,
                    tenant_id, principal.internal_customer_id, principal.local_user_id,
                    str(uid), key, request_hash, result, expires_at,
                )
                if approval_id is not None:
                    changed = await connection.fetchval(
                        """
                        UPDATE smart_alarm.command_approvals
                        SET status = 'CONSUMED', consumed_operation_id = $2,
                            consumed_at = clock_timestamp(), updated_at = clock_timestamp()
                        WHERE id = $1 AND status = 'APPROVED'
                        RETURNING 1
                        """,
                        approval_id, operation["id"],
                    )
                    if changed != 1:
                        raise WriteError("command_approval_unavailable", 409)
                    await _audit(
                        connection, principal, key, "DEVICE_COMMAND_APPROVAL_CONSUMED", "DEVICE",
                        str(uid), {"approvalId": str(approval_id), "operationId": str(operation["id"])},
                    )
                await _outbox(
                    connection, tenant_id, "DEVICE", str(device["id"]), COMMAND_SUBMIT_EVENT,
                    {"operationId": str(operation["id"]), "deviceUid": str(uid)},
                )
                await _audit(
                    connection, principal, key, "DEVICE_COMMAND_ACCEPTED", "DEVICE", str(uid),
                    {"operationId": str(operation["id"]), "command": command, "reason": reason}, "ACCEPTED",
                )
            return _command_response(operation)
        except (WriteError, PolicyError, ValueError) as exc:
            if isinstance(exc, PolicyError):
                exc = WriteError("capability_required", 403)
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))

    @router.get("/api/v1/device-management/operations/{operation_id}")
    async def command_operation(operation_id: str, request: Request):
        try:
            principal = await _read_guard(request, sessions, database, "devices:read")
            tenant_id, customer_scope = _tenant_scope(principal)
            operation_uuid = UUID(operation_id)
            async with _scoped_connection(await database(), principal) as connection:
                row = await connection.fetchrow(
                    """
                    SELECT o.* FROM smart_alarm.operations o
                    JOIN smart_alarm.devices d ON d.tenant_id = o.tenant_id
                      AND d.device_uid::text = o.resource_id
                    WHERE o.id = $1 AND o.tenant_id = $2 AND o.operation_type = 'device-command'
                      AND ($3::uuid IS NULL OR d.customer_id = $3)
                    """,
                    operation_uuid, tenant_id, customer_scope,
                )
            if row is None:
                raise WriteError("operation_not_found", 404)
            return _command_response(row)
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))

    @router.post("/api/v1/device-management/devices/{device_uid}/command-approvals")
    async def request_approval(device_uid: str, request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "devices:command:execute")
            tenant_id, customer_scope = _tenant_scope(principal)
            if set(body) != {"command", "reason"} or body.get("command") != "reboot":
                raise WriteError("invalid_command_approval")
            uid = UUID(device_uid)
            reason = _text(body.get("reason"), "approval_reason", required=True)
            assert reason is not None
            key = _idempotency(request)
            request_hash = _body_hash({"deviceUid": str(uid), "command": "reboot", "reason": reason})
            async with _scoped_connection(await database(), principal) as connection:
                existing = await connection.fetchrow(
                    "SELECT id, request_hash FROM smart_alarm.command_approvals WHERE tenant_id = $1 AND request_idempotency_key = $2",
                    tenant_id, key,
                )
                if existing is not None:
                    if bytes(existing["request_hash"]) != request_hash:
                        raise WriteError("idempotency_conflict", 409)
                    row = await _approval_row(connection, tenant_id, existing["id"])
                    return _public_approval(row)
                device = await _command_device(connection, tenant_id, customer_scope, uid)
                row = await connection.fetchrow(
                    """
                    INSERT INTO smart_alarm.command_approvals (
                        tenant_id, customer_id, device_id, command_type, reason,
                        requester_user_id, expires_at, request_idempotency_key, request_hash
                    ) VALUES ($1, $2, $3, 'reboot', $4, $5,
                              clock_timestamp() + interval '15 minutes', $6, $7)
                    RETURNING id
                    """,
                    tenant_id, principal.internal_customer_id, device["id"], reason,
                    principal.local_user_id, key, request_hash,
                )
                await _audit(
                    connection, principal, key, "DEVICE_COMMAND_APPROVAL_REQUESTED", "DEVICE", str(uid),
                    {"approvalId": str(row["id"]), "command": "reboot", "reason": reason}, "ACCEPTED",
                )
                approval = await _approval_row(connection, tenant_id, row["id"])
            return _public_approval(approval)
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))

    @router.get("/api/v1/device-management/command-approvals")
    async def list_approvals(request: Request):
        try:
            principal = await _read_guard(request, sessions, database, "devices:read")
            tenant_id, customer_scope = _tenant_scope(principal)
            status = request.query_params.get("status")
            if status is not None and status not in _APPROVAL_STATUSES:
                raise WriteError("invalid_approval_status")
            async with _scoped_connection(await database(), principal) as connection:
                await connection.execute(
                    """
                    UPDATE smart_alarm.command_approvals
                    SET status = 'EXPIRED', updated_at = clock_timestamp()
                    WHERE tenant_id = $1 AND status IN ('PENDING', 'APPROVED')
                      AND expires_at <= clock_timestamp()
                    """,
                    tenant_id,
                )
                rows = await connection.fetch(
                    """
                    SELECT a.*, d.device_uid,
                           requester.thingsboard_user_id AS requester_platform_user_id,
                           decision.thingsboard_user_id AS decision_platform_user_id
                    FROM smart_alarm.command_approvals a
                    JOIN smart_alarm.devices d ON d.tenant_id = a.tenant_id AND d.id = a.device_id
                    JOIN smart_alarm.users requester ON requester.id = a.requester_user_id
                    LEFT JOIN smart_alarm.users decision ON decision.id = a.decision_user_id
                    WHERE a.tenant_id = $1 AND ($2::uuid IS NULL OR d.customer_id = $2)
                      AND ($3::text IS NULL OR a.status = $3)
                    ORDER BY a.created_at DESC, a.id DESC
                    LIMIT 200
                    """,
                    tenant_id, customer_scope, status,
                )
            data = [_public_approval(row) for row in rows]
            return {"data": data, "totalElements": len(data)}
        except WriteError as exc:
            return _write_error(exc)

    @router.post("/api/v1/device-management/command-approvals/{approval_id}/decision")
    async def decide_approval(approval_id: str, request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "devices:command:approve")
            tenant_id, customer_scope = _tenant_scope(principal)
            if set(body) != {"decision", "reason"}:
                raise WriteError("invalid_approval_decision")
            approval_uuid = UUID(approval_id)
            decision = _text(body.get("decision"), "approval_decision", maximum=16, required=True)
            reason = _text(body.get("reason"), "approval_decision_reason", required=True)
            assert decision is not None and reason is not None
            decision = decision.upper()
            if decision not in {"APPROVE", "REJECT"}:
                raise WriteError("invalid_approval_decision")
            key = _idempotency(request)
            request_hash = _body_hash({"approvalId": str(approval_uuid), "decision": decision, "reason": reason})
            async with _scoped_connection(await database(), principal) as connection:
                row = await connection.fetchrow(
                    """
                    SELECT a.*, d.device_uid, d.customer_id AS device_customer_id
                    FROM smart_alarm.command_approvals a
                    JOIN smart_alarm.devices d ON d.tenant_id = a.tenant_id AND d.id = a.device_id
                    WHERE a.id = $1 AND a.tenant_id = $2
                      AND ($3::uuid IS NULL OR d.customer_id = $3)
                    FOR UPDATE OF a
                    """,
                    approval_uuid, tenant_id, customer_scope,
                )
                if row is None:
                    raise WriteError("approval_not_found", 404)
                if row["decision_idempotency_key"] == key:
                    if bytes(row["decision_hash"]) != request_hash:
                        raise WriteError("idempotency_conflict", 409)
                    approval = await _approval_row(connection, tenant_id, approval_uuid)
                    return _public_approval(approval)
                conflict = await connection.fetchval(
                    "SELECT 1 FROM smart_alarm.command_approvals WHERE tenant_id = $1 AND decision_idempotency_key = $2",
                    tenant_id, key,
                )
                if conflict == 1:
                    raise WriteError("idempotency_conflict", 409)
                if row["requester_user_id"] == principal.local_user_id:
                    raise WriteError("self_approval_forbidden", 403)
                if row["expires_at"] <= datetime.now(UTC):
                    await connection.execute(
                        "UPDATE smart_alarm.command_approvals SET status = 'EXPIRED', updated_at = clock_timestamp() WHERE id = $1 AND status IN ('PENDING', 'APPROVED')",
                        approval_uuid,
                    )
                    raise WriteError("approval_expired", 409)
                if row["status"] != "PENDING":
                    raise WriteError("approval_already_decided", 409)
                next_status = "APPROVED" if decision == "APPROVE" else "REJECTED"
                await connection.execute(
                    """
                    UPDATE smart_alarm.command_approvals
                    SET status = $2, decision_user_id = $3, decision_reason = $4,
                        decision_idempotency_key = $5, decision_hash = $6,
                        decided_at = clock_timestamp(), updated_at = clock_timestamp()
                    WHERE id = $1 AND status = 'PENDING'
                    """,
                    approval_uuid, next_status, principal.local_user_id, reason, key, request_hash,
                )
                await _audit(
                    connection, principal, key, "DEVICE_COMMAND_APPROVAL_DECIDED", "DEVICE",
                    str(row["device_uid"]), {"approvalId": str(approval_uuid), "decision": next_status, "reason": reason},
                )
                approval = await _approval_row(connection, tenant_id, approval_uuid)
            return _public_approval(approval)
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))

    @router.post("/api/v1/device-management/command-batches")
    async def execute_batch(request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "devices:command:execute")
            tenant_id, customer_scope = _tenant_scope(principal)
            if set(body).difference({"deviceUids", "command", "reason"}):
                raise WriteError("invalid_command_batch")
            raw_uids = body.get("deviceUids")
            if not isinstance(raw_uids, list) or not 1 <= len(raw_uids) <= 100:
                raise WriteError("invalid_command_batch")
            try:
                device_uids = [UUID(str(value)) for value in raw_uids]
            except ValueError as exc:
                raise WriteError("invalid_command_batch") from exc
            if len(set(device_uids)) != len(device_uids):
                raise WriteError("duplicate_device_uid")
            command = _text(body.get("command"), "command", maximum=32, required=True)
            reason = _text(body.get("reason"), "command_reason")
            if command not in _BATCH_COMMANDS:
                raise WriteError("batch_command_not_allowed")
            key = _idempotency(request)
            request_hash = _body_hash({
                "deviceUids": [str(uid) for uid in device_uids], "command": command, "reason": reason,
            })
            async with _scoped_connection(await database(), principal) as connection:
                existing = await _existing_operation(connection, tenant_id, "device-command-batch", key, request_hash)
                if existing is not None:
                    batch_id = await connection.fetchval(
                        "SELECT id FROM smart_alarm.command_batches WHERE operation_id = $1", existing["id"],
                    )
                    if batch_id is None:
                        raise WriteError("operation_in_progress", 409)
                    return await _public_batch(connection, tenant_id, batch_id)
                devices = await connection.fetch(
                    """
                    SELECT id, device_uid, customer_id, lifecycle_state, thingsboard_device_id
                    FROM smart_alarm.devices
                    WHERE tenant_id = $1 AND device_uid = ANY($2::uuid[])
                      AND ($3::uuid IS NULL OR customer_id = $3)
                    FOR UPDATE
                    """,
                    tenant_id, device_uids, customer_scope,
                )
                by_uid = {row["device_uid"]: row for row in devices}
                if len(by_uid) != len(device_uids):
                    raise WriteError("device_not_found", 404)
                if any(row["lifecycle_state"] != "ACTIVE" or row["thingsboard_device_id"] is None for row in devices):
                    raise WriteError("device_not_commandable", 409)
                parent = await connection.fetchrow(
                    """
                    INSERT INTO smart_alarm.operations (
                        tenant_id, customer_id, actor_user_id, operation_type, resource_type,
                        idempotency_key, request_hash, state, result
                    ) VALUES ($1, $2, $3, 'device-command-batch', 'DEVICE_BATCH',
                              $4, $5, 'PENDING', $6::jsonb)
                    RETURNING *
                    """,
                    tenant_id, principal.internal_customer_id, principal.local_user_id,
                    key, request_hash, {"command": command, "reason": reason},
                )
                batch = await connection.fetchrow(
                    """
                    INSERT INTO smart_alarm.command_batches (
                        tenant_id, customer_id, operation_id, command_type, status,
                        total_count, accepted_count, failed_count
                    ) VALUES ($1, $2, $3, $4, 'RUNNING', $5, $5, 0)
                    RETURNING id
                    """,
                    tenant_id, principal.internal_customer_id, parent["id"], command, len(device_uids),
                )
                now = datetime.now(UTC)
                for index, uid in enumerate(device_uids):
                    device = by_uid[uid]
                    expires_at = now + timedelta(seconds=int(COMMAND_POLICIES[command]["expirationSeconds"]))
                    child_result = {
                        "command": command,
                        **({"reason": reason} if reason else {}),
                        "requestedBy": str(principal.platform_user_id),
                        "risk": COMMAND_POLICIES[command]["risk"],
                        "retryCount": COMMAND_POLICIES[command]["retries"],
                        "platformStatus": "SUBMITTING",
                        "expirationTime": int(expires_at.timestamp() * 1000),
                    }
                    child_key = f"batch-{batch['id']}-{index:03d}"
                    child = await connection.fetchrow(
                        """
                        INSERT INTO smart_alarm.operations (
                            tenant_id, customer_id, actor_user_id, operation_type, resource_type,
                            resource_id, idempotency_key, request_hash, state, result,
                            command_expires_at
                        ) VALUES ($1, $2, $3, 'device-command', 'DEVICE', $4, $5, $6,
                                  'QUEUED', $7::jsonb, $8)
                        RETURNING id
                        """,
                        tenant_id, principal.internal_customer_id, principal.local_user_id,
                        str(uid), child_key,
                        _body_hash({"deviceUid": str(uid), "command": command, "reason": reason}),
                        child_result, expires_at,
                    )
                    await connection.execute(
                        """
                        INSERT INTO smart_alarm.command_batch_items (
                            batch_id, tenant_id, device_id, operation_id, status
                        ) VALUES ($1, $2, $3, $4, 'ACCEPTED')
                        """,
                        batch["id"], tenant_id, device["id"], child["id"],
                    )
                    await _outbox(
                        connection, tenant_id, "DEVICE", str(device["id"]), COMMAND_SUBMIT_EVENT,
                        {"operationId": str(child["id"]), "deviceUid": str(uid), "batchId": str(batch["id"])},
                    )
                response = await _public_batch(connection, tenant_id, batch["id"])
                await connection.execute(
                    """
                    UPDATE smart_alarm.operations
                    SET state = 'SUCCEEDED', result = $2::jsonb, resource_id = $3,
                        finished_at = clock_timestamp(), updated_at = clock_timestamp(), version = version + 1
                    WHERE id = $1
                    """,
                    parent["id"], response, str(batch["id"]),
                )
                await _audit(
                    connection, principal, key, "DEVICE_COMMAND_BATCH_ACCEPTED", "DEVICE_BATCH",
                    str(batch["id"]), {"command": command, "deviceUids": [str(uid) for uid in device_uids]},
                    "ACCEPTED",
                )
            return response
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))

    @router.get("/api/v1/device-management/command-batches/{batch_id}")
    async def command_batch(batch_id: str, request: Request):
        try:
            principal = await _read_guard(request, sessions, database, "devices:read")
            tenant_id, customer_scope = _tenant_scope(principal)
            batch_uuid = UUID(batch_id)
            async with _scoped_connection(await database(), principal) as connection:
                visible = await connection.fetchval(
                    """
                    SELECT count(*) = b.total_count
                    FROM smart_alarm.command_batches b
                    JOIN smart_alarm.command_batch_items i ON i.batch_id = b.id AND i.tenant_id = b.tenant_id
                    JOIN smart_alarm.devices d ON d.id = i.device_id AND d.tenant_id = i.tenant_id
                    WHERE b.id = $1 AND b.tenant_id = $2
                      AND ($3::uuid IS NULL OR d.customer_id = $3)
                    GROUP BY b.total_count
                    """,
                    batch_uuid, tenant_id, customer_scope,
                )
                if visible is not True:
                    raise WriteError("command_batch_not_found", 404)
                return await _public_batch(connection, tenant_id, batch_uuid)
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))

    async def create_cancellation(
        principal: ProductPrincipal,
        source_operation_id: UUID,
        reason: str,
        key: str,
        *,
        retry_of: UUID | None = None,
    ) -> Any:
        tenant_id, customer_scope = _tenant_scope(principal)
        request_hash = _body_hash({
            "commandOperationId": str(source_operation_id), "reason": reason,
            "retryOfOperationId": str(retry_of) if retry_of else None,
        })
        async with _scoped_connection(await database(), principal) as connection:
            existing = await _existing_operation(
                connection, tenant_id, "device-command-cancel", key, request_hash,
            )
            if existing is not None:
                return existing
            source = await connection.fetchrow(
                """
                SELECT o.*, d.id AS device_id, d.customer_id AS device_customer_id
                FROM smart_alarm.operations o
                JOIN smart_alarm.devices d ON d.tenant_id = o.tenant_id
                  AND d.device_uid::text = o.resource_id
                WHERE o.id = $1 AND o.tenant_id = $2 AND o.operation_type = 'device-command'
                  AND ($3::uuid IS NULL OR d.customer_id = $3)
                FOR UPDATE OF o
                """,
                source_operation_id, tenant_id, customer_scope,
            )
            if source is None:
                raise WriteError("operation_not_found", 404)
            source_result = dict(source["result"])
            if (
                source["state"] not in {"PENDING", "QUEUED", "OUTCOME_UNKNOWN"}
                or source["platform_rpc_id"] is None
                or source_result.get("platformStatus") not in PENDING_PLATFORM_STATUSES
            ):
                raise WriteError("command_not_cancellable", 409)
            result = {
                "commandOperationId": str(source_operation_id),
                "command": source_result.get("command"),
                "reason": reason,
                "requestedBy": str(principal.platform_user_id),
                "rpcId": str(source["platform_rpc_id"]),
                "platformStatus": "SUBMITTING",
            }
            operation = await connection.fetchrow(
                """
                INSERT INTO smart_alarm.operations (
                    tenant_id, customer_id, actor_user_id, operation_type, resource_type,
                    resource_id, idempotency_key, request_hash, state, result, parent_operation_id
                ) VALUES ($1, $2, $3, 'device-command-cancel', 'DEVICE', $4, $5, $6,
                          'QUEUED', $7::jsonb, $8)
                RETURNING *
                """,
                tenant_id, principal.internal_customer_id, principal.local_user_id,
                source["resource_id"], key, request_hash, result,
                retry_of or source_operation_id,
            )
            await _outbox(
                connection, tenant_id, "DEVICE", str(source["device_id"]), COMMAND_CANCEL_EVENT,
                {"operationId": str(operation["id"]), "commandOperationId": str(source_operation_id)},
            )
            await _audit(
                connection, principal, key, "DEVICE_COMMAND_CANCEL_ACCEPTED", "DEVICE",
                source["resource_id"], {
                    "operationId": str(operation["id"]),
                    "commandOperationId": str(source_operation_id),
                    "reason": reason,
                    "warning": CANCELLATION_WARNING,
                }, "ACCEPTED",
            )
        return operation

    async def cancellation_result(principal: ProductPrincipal, operation: Any) -> Any:
        settled = await _wait_for_operation(database, principal, operation["id"])
        if settled is None:
            raise WriteError("operation_not_found", 404)
        if settled["state"] in {"PENDING", "QUEUED", "OUTCOME_UNKNOWN"}:
            return JSONResponse(status_code=503, content={"error": {
                "code": "command_cancel_pending",
                "message": "command cancellation is still being reconciled",
                "operationId": str(settled["id"]),
            }})
        if settled["state"] == "FAILED":
            return JSONResponse(status_code=409 if settled["error_code"] == "command_not_cancellable" else 502, content={"error": {
                "code": settled["error_code"] or "command_cancel_failed",
                "message": "command cancellation failed",
                "operationId": str(settled["id"]),
            }})
        return _cancel_response(settled)

    @router.post("/api/v1/device-management/operations/{operation_id}/cancellations")
    async def cancel_command(operation_id: str, request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "devices:command:execute")
            if set(body) != {"reason"}:
                raise WriteError("invalid_command_cancel")
            reason = _text(body.get("reason"), "command_cancel_reason", required=True)
            assert reason is not None
            operation = await create_cancellation(
                principal, UUID(operation_id), reason, _idempotency(request),
            )
            return await cancellation_result(principal, operation)
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))

    @router.post("/api/v1/device-management/operations/{cancel_operation_id}/cancellations/retry")
    async def retry_cancellation(cancel_operation_id: str, request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "devices:command:execute")
            tenant_id, customer_scope = _tenant_scope(principal)
            if set(body) != {"reason"}:
                raise WriteError("invalid_command_cancel")
            reason = _text(body.get("reason"), "command_cancel_reason", required=True)
            assert reason is not None
            previous_id = UUID(cancel_operation_id)
            async with _scoped_connection(await database(), principal) as connection:
                previous = await connection.fetchrow(
                    """
                    SELECT o.* FROM smart_alarm.operations o
                    JOIN smart_alarm.devices d ON d.tenant_id = o.tenant_id
                      AND d.device_uid::text = o.resource_id
                    WHERE o.id = $1 AND o.tenant_id = $2
                      AND o.operation_type = 'device-command-cancel'
                      AND ($3::uuid IS NULL OR d.customer_id = $3)
                    """,
                    previous_id, tenant_id, customer_scope,
                )
                if previous is None:
                    raise WriteError("operation_not_found", 404)
                if previous["state"] != "FAILED" or previous["error_code"] != "command_cancel_outcome_unknown":
                    raise WriteError("operation_not_retryable", 409)
                source_id = UUID(str(dict(previous["result"]).get("commandOperationId")))
            operation = await create_cancellation(
                principal, source_id, reason, _idempotency(request), retry_of=previous_id,
            )
            async with _scoped_connection(await database(), principal) as connection:
                await connection.execute(
                    """
                    UPDATE smart_alarm.operations
                    SET result = result || jsonb_build_object('retryOperationId', $2::text),
                        updated_at = clock_timestamp(), version = version + 1
                    WHERE id = $1
                    """,
                    previous_id, operation["id"],
                )
            return await cancellation_result(principal, operation)
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))


def mount_command_routes(
    app: Any,
    sessions: SessionService,
    database: Callable[[], Awaitable[Any]],
) -> None:
    router = APIRouter()
    register_command_routes(router, sessions, database)
    app.include_router(router)
