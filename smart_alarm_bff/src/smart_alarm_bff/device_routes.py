"""Device claim, metadata and retirement request endpoints."""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any, Awaitable, Callable
from uuid import UUID

from fastapi import APIRouter, Request

from .directory_routes import _scoped_connection
from .policy import PolicyError
from .session import SessionService
from .write_routes import (
    WriteError,
    _audit,
    _begin_operation,
    _body_hash,
    _guard,
    _idempotency,
    _outbox,
    _queue_operation,
    _tenant_scope,
    _write_error,
)


_SERIAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{5,63}$")


def _optional_uuid(value: object, field: str) -> UUID | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise WriteError(f"invalid_{field}")
    try:
        return UUID(value)
    except ValueError as exc:
        raise WriteError(f"invalid_{field}") from exc


def _public_device(row: Any) -> dict[str, object]:
    return {
        "id": str(row["id"]),
        "deviceUid": str(row["device_uid"]),
        "serialNumber": row["serial_number"],
        "technicalName": row["technical_name"],
        "name": row["display_name"],
        "label": row["display_name"],
        "type": "smart-alarm",
        "active": row["lifecycle_state"] == "ACTIVE",
        "customerId": str(row["customer_id"]) if row["customer_id"] else None,
        "assetId": str(row["asset_id"]) if row["asset_id"] else None,
        "groupId": str(row["business_group_id"]) if row["business_group_id"] else None,
        "deviceProfileId": str(row["device_profile_id"]),
        "deviceProfileName": row["profile_name"],
        "lifecycleState": row["lifecycle_state"],
        "credentialVersion": int(row["credential_version"]),
        **({"thingsboardDeviceId": str(row["thingsboard_device_id"])} if row["thingsboard_device_id"] else {}),
        **({"retiredAt": int(row["retired_at"].timestamp() * 1000)} if row["retired_at"] else {}),
    }


async def _device_row(connection: Any, tenant_id: UUID, device_uid: UUID) -> Any:
    return await connection.fetchrow(
        """
        SELECT d.*, i.serial_number, p.name AS profile_name
        FROM smart_alarm.devices d
        JOIN smart_alarm.device_inventory i ON i.device_uid = d.device_uid
        JOIN smart_alarm.device_profiles p ON p.tenant_id = d.tenant_id AND p.id = d.device_profile_id
        WHERE d.tenant_id = $1 AND d.device_uid = $2
        """,
        tenant_id, device_uid,
    )


async def _validate_assignments(connection: Any, tenant_id: UUID, customer_id: UUID | None, asset_id: UUID | None, group_id: UUID | None) -> None:
    if customer_id is not None and await connection.fetchval("SELECT 1 FROM smart_alarm.customers WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'", tenant_id, customer_id) != 1:
        raise WriteError("customer_not_found", 404)
    if asset_id is not None:
        asset = await connection.fetchrow("SELECT customer_id FROM smart_alarm.assets WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'", tenant_id, asset_id)
        if asset is None or asset["customer_id"] != customer_id:
            raise WriteError("asset_scope_mismatch", 404)
    if group_id is not None:
        group = await connection.fetchrow("SELECT customer_id FROM smart_alarm.business_groups WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'", tenant_id, group_id)
        if group is None or group["customer_id"] != customer_id:
            raise WriteError("group_scope_mismatch", 404)


def register_device_routes(router: APIRouter, sessions: SessionService, database: Callable[[], Awaitable[Any]]) -> None:
    @router.post("/api/v1/device-management/devices")
    async def register_device(request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "devices:register")
            tenant_id, session_customer = _tenant_scope(principal)
            device_uid = _optional_uuid(body.get("deviceUid"), "device_uid")
            if device_uid is None:
                raise WriteError("invalid_device_uid")
            serial_number, claim_token, display_name = body.get("serialNumber"), body.get("claimToken"), body.get("displayName")
            if not isinstance(serial_number, str) or not _SERIAL.fullmatch(serial_number):
                raise WriteError("invalid_serial_number")
            if not isinstance(claim_token, str) or not 16 <= len(claim_token) <= 512 or any(char.isspace() for char in claim_token):
                raise WriteError("invalid_claim_token")
            if not isinstance(display_name, str) or not display_name or display_name != display_name.strip() or len(display_name) > 255:
                raise WriteError("invalid_display_name")
            customer_id = _optional_uuid(body.get("customerId"), "customer_id") or session_customer
            asset_id = _optional_uuid(body.get("assetId"), "asset_id")
            group_id = _optional_uuid(body.get("groupId"), "group_id")
            profile_id = _optional_uuid(body.get("deviceProfileId"), "device_profile_id")
            if session_customer is not None and customer_id != session_customer:
                raise WriteError("scope_mismatch", 404)
            key = _idempotency(request)
            fingerprint = {key: value for key, value in body.items() if key != "claimToken"}
            fingerprint["claimTokenDigest"] = hashlib.sha256(claim_token.encode("utf-8")).hexdigest()
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "device-register", "DEVICE", _body_hash(fingerprint))
                if replay is not None:
                    return replay
                inventory = await connection.fetchrow("SELECT device_uid, serial_number, claim_token_hash, claim_expires_at, claim_consumed_at, status FROM smart_alarm.device_inventory WHERE device_uid = $1 FOR UPDATE", device_uid)
                if inventory is None or inventory["serial_number"] != serial_number:
                    raise WriteError("inventory_not_found", 404)
                claim_digest = hashlib.sha256(claim_token.encode("utf-8")).digest()
                if inventory["status"] != "UNCLAIMED" or inventory["claim_consumed_at"] is not None or not hmac.compare_digest(bytes(inventory["claim_token_hash"]), claim_digest):
                    raise WriteError("claim_rejected", 409)
                if await connection.fetchval("SELECT $1 <= clock_timestamp()", inventory["claim_expires_at"]):
                    raise WriteError("claim_expired", 409)
                if profile_id is None:
                    profile_id = await connection.fetchval("SELECT id FROM smart_alarm.device_profiles WHERE tenant_id = $1 AND status = 'ACTIVE' ORDER BY is_default DESC, created_at, id LIMIT 1", tenant_id)
                if profile_id is None or await connection.fetchval("SELECT 1 FROM smart_alarm.device_profiles WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'", tenant_id, profile_id) != 1:
                    raise WriteError("device_profile_not_found", 404)
                await _validate_assignments(connection, tenant_id, customer_id, asset_id, group_id)
                await connection.execute("UPDATE smart_alarm.device_inventory SET status = 'CLAIMED', claim_consumed_at = clock_timestamp(), updated_at = clock_timestamp() WHERE device_uid = $1", device_uid)
                device = await connection.fetchrow("INSERT INTO smart_alarm.devices (tenant_id, device_uid, customer_id, asset_id, business_group_id, device_profile_id, technical_name, display_name, lifecycle_state) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'ACTIVATING') RETURNING id", tenant_id, device_uid, customer_id, asset_id, group_id, profile_id, f"stc-{device_uid}", display_name)
                if asset_id is not None:
                    await connection.execute("INSERT INTO smart_alarm.entity_relations (tenant_id, from_type, from_id, to_type, to_id, relation_type, status) VALUES ($1, 'ASSET', $2, 'DEVICE', $3, 'Contains', 'PENDING_CREATE') ON CONFLICT DO NOTHING", tenant_id, asset_id, device["id"])
                await _outbox(connection, tenant_id, "DEVICE", str(device["id"]), "device.activation.requested", {"operationId": str(operation_id), "deviceId": str(device["id"]), "deviceUid": str(device_uid)})
                row = await _device_row(connection, tenant_id, device_uid)
                result = {"operationId": str(operation_id), "kind": "register", "status": "QUEUED", "result": {"device": _public_device(row)}}
                await _queue_operation(connection, operation_id, result, str(device_uid))
                await _audit(connection, principal, key, "DEVICE_ACTIVATION_ACCEPTED", "DEVICE", str(device_uid), {"deviceId": str(device["id"])}, "ACCEPTED")
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))

    @router.patch("/api/v1/device-management/devices/{device_uid}")
    async def update_device(device_uid: str, request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "devices:metadata:update")
            principal.require("devices:assignment:update")
            tenant_id, session_customer = _tenant_scope(principal)
            uid, key = UUID(device_uid), _idempotency(request)
            async with _scoped_connection(await database(), principal) as connection:
                current = await _device_row(connection, tenant_id, uid)
                if current is None or (session_customer is not None and current["customer_id"] != session_customer):
                    raise WriteError("not_found", 404)
                if current["lifecycle_state"] != "ACTIVE":
                    raise WriteError("device_not_editable", 409)
                display_name = body.get("displayName", current["display_name"])
                customer_id = _optional_uuid(body.get("customerId"), "customer_id") if "customerId" in body else current["customer_id"]
                asset_id = _optional_uuid(body.get("assetId"), "asset_id") if "assetId" in body else current["asset_id"]
                group_id = _optional_uuid(body.get("groupId"), "group_id") if "groupId" in body else current["business_group_id"]
                if not isinstance(display_name, str) or not display_name or display_name != display_name.strip() or len(display_name) > 255:
                    raise WriteError("invalid_display_name")
                if session_customer is not None and customer_id != session_customer:
                    raise WriteError("scope_mismatch", 404)
                await _validate_assignments(connection, tenant_id, customer_id, asset_id, group_id)
                operation_id, replay = await _begin_operation(connection, principal, key, "device-update", "DEVICE", _body_hash({"deviceUid": device_uid, **body}))
                if replay is not None:
                    return replay
                if current["asset_id"] is not None and current["asset_id"] != asset_id:
                    await connection.execute(
                        "UPDATE smart_alarm.entity_relations SET status = 'PENDING_DELETE', version = version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND from_type = 'ASSET' AND from_id = $2 AND to_type = 'DEVICE' AND to_id = $3 AND relation_type = 'Contains'",
                        tenant_id, current["asset_id"], current["id"],
                    )
                await connection.execute("UPDATE smart_alarm.devices SET display_name = $3, customer_id = $4, asset_id = $5, business_group_id = $6, version = version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND device_uid = $2", tenant_id, uid, display_name, customer_id, asset_id, group_id)
                if asset_id is not None and current["asset_id"] != asset_id:
                    await connection.execute(
                        "INSERT INTO smart_alarm.entity_relations (tenant_id, from_type, from_id, to_type, to_id, relation_type, status) VALUES ($1, 'ASSET', $2, 'DEVICE', $3, 'Contains', 'PENDING_CREATE') ON CONFLICT (tenant_id, from_type, from_id, to_type, to_id, relation_type) DO UPDATE SET status = 'PENDING_CREATE', version = smart_alarm.entity_relations.version + 1, updated_at = clock_timestamp()",
                        tenant_id, asset_id, current["id"],
                    )
                await _outbox(connection, tenant_id, "DEVICE", str(current["id"]), "device.metadata.sync.requested", {"operationId": str(operation_id), "deviceId": str(current["id"]), "deviceUid": device_uid})
                row = await _device_row(connection, tenant_id, uid)
                result = {"operationId": str(operation_id), "kind": "update", "status": "QUEUED", "device": _public_device(row)}
                await _queue_operation(connection, operation_id, result, device_uid)
                await _audit(connection, principal, key, "DEVICE_UPDATE_ACCEPTED", "DEVICE", device_uid, {}, "ACCEPTED")
            return result
        except (WriteError, PolicyError, ValueError) as exc:
            if isinstance(exc, PolicyError):
                exc = WriteError("capability_required", 403)
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))

    @router.post("/api/v1/device-management/devices/{device_uid}/retirements")
    async def retire_device(device_uid: str, request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "devices:retire")
            tenant_id, _ = _tenant_scope(principal)
            uid, key = UUID(device_uid), _idempotency(request)
            reason = body.get("reason")
            if not isinstance(reason, str) or not 8 <= len(reason.strip()) <= 500:
                raise WriteError("retirement_reason_required")
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "device-retire", "DEVICE", _body_hash({"deviceUid": device_uid, **body}))
                if replay is not None:
                    return replay
                row = await connection.fetchrow("UPDATE smart_alarm.devices SET lifecycle_state = 'RETIRING', version = version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND device_uid = $2 AND lifecycle_state IN ('ACTIVE', 'RETIREMENT_FAILED') RETURNING id", tenant_id, uid)
                if row is None:
                    raise WriteError("device_not_retirable", 409)
                await _outbox(connection, tenant_id, "DEVICE", str(row["id"]), "device.retirement.requested", {"operationId": str(operation_id), "deviceId": str(row["id"]), "deviceUid": device_uid, "reason": reason.strip()})
                device = await _device_row(connection, tenant_id, uid)
                result = {"operationId": str(operation_id), "kind": "retire", "status": "QUEUED", "result": {"device": _public_device(device)}}
                await _queue_operation(connection, operation_id, result, device_uid)
                await _audit(connection, principal, key, "DEVICE_RETIREMENT_ACCEPTED", "DEVICE", device_uid, {"reason": reason.strip()}, "ACCEPTED")
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))


def mount_device_routes(app: Any, sessions: SessionService, database: Callable[[], Awaitable[Any]]) -> None:
    router = APIRouter()
    register_device_routes(router, sessions, database)
    app.include_router(router)
