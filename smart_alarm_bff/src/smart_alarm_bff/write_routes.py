"""Transactional Tenant/Customer lifecycle routes.

The handler performs the product mutation, idempotency record and audit event
in one PostgreSQL transaction. ThingsBoard side effects are deliberately left
to the outbox/adapter stage and are never performed in a browser request.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any, Awaitable, Callable
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .directory_routes import DirectoryError, _error, _scoped_connection
from .policy import PolicyError, ProductPrincipal
from .platform_handlers import ASSET_SYNC_EVENT, PROFILE_SYNC_EVENT
from .session import SessionContext, SessionError, SessionService
from .thingsboard import ThingsBoardClient, ThingsBoardError, normalize_email, normalize_username


_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9._:-]{8,255}$")
_LOGGER = logging.getLogger(__name__)


class WriteError(RuntimeError):
    def __init__(self, code: str, status_code: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


def _write_error(exc: WriteError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": {"code": exc.code, "message": "write request failed"}})


def _body_hash(body: dict[str, object]) -> bytes:
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).digest()


def _json_object(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            return parsed
    return {}


def _name(body: dict[str, object], maximum: int = 255) -> str:
    value = body.get("name")
    if not isinstance(value, str) or not value or len(value) > maximum or value != value.strip():
        raise WriteError("invalid_name")
    return value


def _account_input(body: dict[str, object], allowed_roles: set[str]) -> tuple[str, str | None, str, str, str]:
    try:
        username = normalize_username(body.get("username"))
        email = normalize_email(body.get("email"))
    except PolicyError as exc:
        raise WriteError("invalid_account_identity") from exc
    password = body.get("initialPassword")
    if (
        not isinstance(password, str)
        or not 8 <= len(password) <= 128
        or any(ord(char) < 32 or ord(char) == 127 for char in password)
    ):
        raise WriteError("invalid_initial_password")
    role = body.get("productRole")
    if role not in allowed_roles:
        raise WriteError("invalid_product_role")
    status = body.get("status", "ACTIVE")
    if status not in {"ACTIVE", "SUSPENDED"}:
        raise WriteError("invalid_user_status")
    return username, email, password, role, status


def _account_request_hash(body: dict[str, object]) -> bytes:
    safe = {key: value for key, value in body.items() if key != "initialPassword"}
    safe["initialPasswordProvided"] = isinstance(body.get("initialPassword"), str)
    return _body_hash(safe)


def _tenant_scope(principal: ProductPrincipal) -> tuple[UUID, UUID | None]:
    if principal.internal_tenant_id is None:
        raise WriteError("tenant_scope_required", 403)
    return principal.internal_tenant_id, principal.internal_customer_id


def _idempotency(request: Request) -> str:
    value = request.headers.get("Idempotency-Key", "")
    if not _IDEMPOTENCY.fullmatch(value):
        raise WriteError("idempotency_key_required")
    return value


async def _begin_operation(connection: Any, principal: ProductPrincipal, key: str, operation_type: str, resource_type: str, request_hash: bytes) -> tuple[UUID, dict[str, object] | None]:
    row = await connection.fetchrow(
        """
        INSERT INTO smart_alarm.operations (tenant_id, customer_id, actor_user_id, operation_type, resource_type, idempotency_key, request_hash, state)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'PENDING')
        ON CONFLICT (tenant_id, operation_type, idempotency_key) DO NOTHING
        RETURNING id
        """,
        principal.internal_tenant_id, principal.internal_customer_id, principal.local_user_id,
        operation_type, resource_type, key, request_hash,
    )
    if row is not None:
        return row["id"], None
    existing = await connection.fetchrow(
        "SELECT id, request_hash, state, result FROM smart_alarm.operations WHERE tenant_id IS NOT DISTINCT FROM $1 AND operation_type = $2 AND idempotency_key = $3",
        principal.internal_tenant_id, operation_type, key,
    )
    if existing is None or bytes(existing["request_hash"]) != request_hash:
        raise WriteError("idempotency_conflict", 409)
    if existing["state"] in {"QUEUED", "SUCCEEDED"} and _json_object(existing["result"]):
        return existing["id"], _json_object(existing["result"])
    raise WriteError("operation_in_progress", 409)


async def _finish_operation(connection: Any, operation_id: UUID, result: dict[str, object], resource_id: str | None = None) -> None:
    await connection.execute(
        "UPDATE smart_alarm.operations SET state = 'SUCCEEDED', result = $2::jsonb, resource_id = $3, finished_at = clock_timestamp(), updated_at = clock_timestamp(), version = version + 1 WHERE id = $1",
        operation_id, result, resource_id,
    )


async def _queue_operation(connection: Any, operation_id: UUID, result: dict[str, object], resource_id: str | None = None) -> None:
    await connection.execute(
        "UPDATE smart_alarm.operations SET state = 'QUEUED', result = $2::jsonb, resource_id = $3, updated_at = clock_timestamp(), version = version + 1 WHERE id = $1",
        operation_id, result, resource_id,
    )


async def _fail_operation(
    database: Callable[[], Awaitable[Any]], principal: ProductPrincipal, operation_id: UUID, code: str,
) -> None:
    async with _scoped_connection(await database(), principal) as connection:
        await connection.execute(
            "UPDATE smart_alarm.operations SET state = 'FAILED', error_code = $2, finished_at = clock_timestamp(), updated_at = clock_timestamp(), version = version + 1 WHERE id = $1 AND state = 'PENDING'",
            operation_id, code,
        )


def _platform_write_error(exc: ThingsBoardError) -> WriteError:
    if exc.code == "platform_user_operation_forbidden":
        return WriteError(exc.code, 403)
    return WriteError(exc.code, 503 if exc.retryable else 502)


def _platform_context(request: Request, thingsboard: ThingsBoardClient | None) -> tuple[SessionContext, ThingsBoardClient]:
    context = getattr(request.state, "session_context", None)
    if not isinstance(context, SessionContext):
        raise WriteError("session_required", 401)
    if thingsboard is None:
        raise WriteError("platform_user_management_unavailable", 503)
    return context, thingsboard


async def _audit(connection: Any, principal: ProductPrincipal, request_id: str, action: str, resource_type: str, resource_id: str | None, detail: dict[str, object], outcome: str = "SUCCEEDED") -> None:
    tenant_key = str(principal.internal_tenant_id) if principal.internal_tenant_id else "SYSTEM"
    await connection.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", tenant_key)
    previous = await connection.fetchval(
        "SELECT event_hash FROM smart_alarm.audit_events WHERE tenant_id IS NOT DISTINCT FROM $1 ORDER BY id DESC LIMIT 1",
        principal.internal_tenant_id,
    )
    canonical = json.dumps({
        "tenantId": str(principal.internal_tenant_id) if principal.internal_tenant_id else None,
        "customerId": str(principal.internal_customer_id) if principal.internal_customer_id else None,
        "actorUserId": str(principal.local_user_id),
        "requestId": request_id,
        "action": action,
        "resourceType": resource_type,
        "resourceId": resource_id,
        "outcome": outcome,
        "detail": detail,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    event_hash = hashlib.sha256((bytes(previous) if previous else b"") + canonical).digest()
    await connection.execute(
        "INSERT INTO smart_alarm.audit_events (tenant_id, customer_id, actor_user_id, request_id, action, resource_type, resource_id, outcome, detail, previous_hash, event_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11)",
        principal.internal_tenant_id, principal.internal_customer_id, principal.local_user_id, request_id, action, resource_type, resource_id,
        outcome, detail, previous, event_hash,
    )


async def _outbox(connection: Any, tenant_id: UUID | None, aggregate_type: str, aggregate_id: str, event_type: str, payload: dict[str, object]) -> None:
    await connection.execute(
        "INSERT INTO smart_alarm.outbox_events (tenant_id, aggregate_type, aggregate_id, event_type, payload) VALUES ($1, $2, $3, $4, $5::jsonb)",
        tenant_id, aggregate_type, aggregate_id, event_type, payload,
    )


async def _guard(request: Request, sessions: SessionService, database: Callable[[], Awaitable[Any]], capability: str) -> ProductPrincipal:
    context = getattr(request.state, "session_context", None)
    if not isinstance(context, SessionContext):
        try:
            context = await sessions.resolve(await database(), request.cookies.get(sessions.cookie_name))
        except SessionError as exc:
            raise WriteError(exc.code, exc.status_code) from exc
    try:
        context.principal.require(capability)
    except PolicyError as exc:
        raise WriteError("capability_required", 403) from exc
    try:
        await sessions.require_csrf(await database(), request.cookies.get(sessions.cookie_name), request.headers.get("X-CSRF-Token"))
    except SessionError as exc:
        raise WriteError(exc.code, exc.status_code) from exc
    request.state.session_context = context
    return context.principal


def register_write_routes(
    router: APIRouter,
    sessions: SessionService,
    database: Callable[[], Awaitable[Any]],
    thingsboard: ThingsBoardClient | None = None,
) -> None:
    @router.post("/api/v1/system/tenants")
    async def create_tenant(request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "system:tenants:write")
            context, platform = _platform_context(request, thingsboard)
            name = _name(body)
            key = _idempotency(request)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "tenant-create", "TENANT", _body_hash(body))
                if replay is not None:
                    return replay
            try:
                platform_tenant_id = await platform.create_tenant(context.platform_token, name=name)
            except ThingsBoardError as exc:
                await _fail_operation(database, principal, operation_id, exc.code)
                raise _platform_write_error(exc) from exc
            try:
                async with _scoped_connection(await database(), principal) as connection:
                    row = await connection.fetchrow(
                        "INSERT INTO smart_alarm.tenants (thingsboard_tenant_id, name) VALUES ($1, $2) RETURNING id, name, thingsboard_tenant_id",
                        platform_tenant_id, name,
                    )
                    result = {"operationId": str(operation_id), "kind": "system-tenant-create", "status": "SUCCEEDED", "tenant": {"id": str(row["id"]), "name": row["name"], "thingsboardTenantId": str(row["thingsboard_tenant_id"])}}
                    await _finish_operation(connection, operation_id, result, str(row["id"]))
                    await _audit(connection, principal, key, "TENANT_CREATED", "TENANT", str(row["id"]), {"name": name, "thingsboardTenantId": str(platform_tenant_id)})
                return result
            except Exception as exc:
                _LOGGER.exception(
                    "failed to persist ThingsBoard tenant %s in the product directory",
                    platform_tenant_id,
                )
                try:
                    await platform.delete_tenant(context.platform_token, platform_tenant_id, missing_ok=True)
                except ThingsBoardError:
                    pass
                await _fail_operation(database, principal, operation_id, "local_tenant_persist_failed")
                if isinstance(exc, WriteError):
                    raise
                raise WriteError("local_tenant_persist_failed", 503) from exc
        except (WriteError, ThingsBoardError) as exc:
            if isinstance(exc, ThingsBoardError):
                return _write_error(_platform_write_error(exc))
            return _write_error(exc)

    @router.patch("/api/v1/system/tenants/{tenant_id}")
    async def update_tenant(tenant_id: str, request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "system:tenants:write")
            context, platform = _platform_context(request, thingsboard)
            name = _name(body)
            key = _idempotency(request)
            tenant_uuid = UUID(tenant_id)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "tenant-update", "TENANT", _body_hash({"tenantId": tenant_id, **body}))
                if replay is not None:
                    return replay
                current = await connection.fetchrow(
                    "SELECT thingsboard_tenant_id, name FROM smart_alarm.tenants WHERE id = $1 AND status = 'ACTIVE'",
                    tenant_uuid,
                )
                if current is None:
                    raise WriteError("not_found", 404)
                platform_tenant_id, previous_name = current["thingsboard_tenant_id"], current["name"]
                if platform_tenant_id is None:
                    raise WriteError("tenant_identity_mapping_required", 409)
            try:
                await platform.update_tenant(context.platform_token, platform_tenant_id, name=name)
            except ThingsBoardError as exc:
                await _fail_operation(database, principal, operation_id, exc.code)
                raise _platform_write_error(exc) from exc
            try:
                async with _scoped_connection(await database(), principal) as connection:
                    row = await connection.fetchrow("UPDATE smart_alarm.tenants SET name = $2, version = version + 1, updated_at = clock_timestamp() WHERE id = $1 AND status = 'ACTIVE' RETURNING id, name", tenant_uuid, name)
                    if row is None:
                        raise WriteError("not_found", 404)
                    result = {"operationId": str(operation_id), "kind": "system-tenant-update", "status": "SUCCEEDED", "tenant": {"id": str(row["id"]), "name": row["name"]}}
                    await _finish_operation(connection, operation_id, result, tenant_id)
                    await _audit(connection, principal, key, "TENANT_UPDATED", "TENANT", tenant_id, {"name": name})
                return result
            except Exception as exc:
                try:
                    await platform.update_tenant(context.platform_token, platform_tenant_id, name=previous_name)
                except ThingsBoardError:
                    _LOGGER.exception("failed to compensate ThingsBoard tenant rename %s", platform_tenant_id)
                await _fail_operation(database, principal, operation_id, "local_tenant_update_failed")
                if isinstance(exc, WriteError):
                    raise
                raise WriteError("local_tenant_update_failed", 503) from exc
        except (WriteError, ValueError, ThingsBoardError) as exc:
            if isinstance(exc, ThingsBoardError):
                return _write_error(_platform_write_error(exc))
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("not_found", 404))

    @router.post("/api/v1/system/tenants/{tenant_id}/archive")
    async def archive_tenant(tenant_id: str, request: Request):
        try:
            principal = await _guard(request, sessions, database, "system:tenants:write")
            context, platform = _platform_context(request, thingsboard)
            key = _idempotency(request)
            tenant_uuid = UUID(tenant_id)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "tenant-archive", "TENANT", _body_hash({"tenantId": tenant_id}))
                if replay is not None:
                    return replay
                current = await connection.fetchrow(
                    "SELECT thingsboard_tenant_id, name FROM smart_alarm.tenants WHERE id = $1 AND status = 'ACTIVE'",
                    tenant_uuid,
                )
                if current is None:
                    raise WriteError("not_found", 404)
                resource_count = await connection.fetchval(
                    """
                    SELECT
                        (SELECT count(*) FROM smart_alarm.customers WHERE tenant_id = $1 AND status = 'ACTIVE') +
                        (SELECT count(*) FROM smart_alarm.users WHERE tenant_id = $1 AND status <> 'ARCHIVED') +
                        (SELECT count(*) FROM smart_alarm.devices WHERE tenant_id = $1 AND lifecycle_state <> 'RETIRED') +
                        (SELECT count(*) FROM smart_alarm.assets WHERE tenant_id = $1 AND status = 'ACTIVE') +
                        (SELECT count(*) FROM smart_alarm.device_profiles WHERE tenant_id = $1 AND status = 'ACTIVE')
                    """,
                    tenant_uuid,
                )
                if resource_count:
                    raise WriteError("tenant_has_customers", 409)
                platform_tenant_id, tenant_name = current["thingsboard_tenant_id"], current["name"]
                if platform_tenant_id is None:
                    raise WriteError("tenant_identity_mapping_required", 409)
            try:
                await platform.delete_tenant(context.platform_token, platform_tenant_id)
            except ThingsBoardError as exc:
                await _fail_operation(database, principal, operation_id, exc.code)
                raise _platform_write_error(exc) from exc
            try:
                async with _scoped_connection(await database(), principal) as connection:
                    row = await connection.fetchrow("UPDATE smart_alarm.tenants SET status = 'ARCHIVED', archived_at = clock_timestamp(), version = version + 1, updated_at = clock_timestamp() WHERE id = $1 AND status = 'ACTIVE' RETURNING id, name, archived_at", tenant_uuid)
                    if row is None:
                        raise WriteError("not_found", 404)
                    result = {"operationId": str(operation_id), "kind": "system-tenant-archive", "status": "SUCCEEDED", "tenant": {"id": str(row["id"]), "name": row["name"], "archivedAt": int(row["archived_at"].timestamp() * 1000)}}
                    await _finish_operation(connection, operation_id, result, tenant_id)
                    await _audit(connection, principal, key, "TENANT_ARCHIVED", "TENANT", tenant_id, {})
                return result
            except Exception as exc:
                try:
                    replacement_id = await platform.create_tenant(context.platform_token, name=tenant_name)
                    async with _scoped_connection(await database(), principal) as connection:
                        await connection.execute(
                            "UPDATE smart_alarm.tenants SET thingsboard_tenant_id = $2 WHERE id = $1 AND status = 'ACTIVE'",
                            tenant_uuid, replacement_id,
                        )
                except Exception:
                    _LOGGER.exception("failed to compensate ThingsBoard tenant archive %s", platform_tenant_id)
                await _fail_operation(database, principal, operation_id, "local_tenant_archive_failed")
                if isinstance(exc, WriteError):
                    raise
                raise WriteError("local_tenant_archive_failed", 503) from exc
        except (WriteError, ValueError, ThingsBoardError) as exc:
            if isinstance(exc, ThingsBoardError):
                return _write_error(_platform_write_error(exc))
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("not_found", 404))

    @router.post("/api/v1/system/users")
    async def create_system_user(request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "system:users:write")
            context, platform = _platform_context(request, thingsboard)
            if body.get("authority") != "TENANT_ADMIN" or body.get("customerId") is not None:
                raise WriteError("invalid_user_scope")
            raw_tenant = body.get("tenantId")
            if not isinstance(raw_tenant, str):
                raise WriteError("invalid_user_scope")
            tenant_id = UUID(raw_tenant)
            username, email, password, role_key, status = _account_input(
                body, {"TENANT_OWNER", "TENANT_OPERATOR", "TENANT_VIEWER"},
            )
            key = _idempotency(request)
            operation_id: UUID
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(
                    connection, principal, key, "system-user-create", "USER", _account_request_hash(body),
                )
                if replay is not None:
                    return replay
                tenant = await connection.fetchrow(
                    "SELECT thingsboard_tenant_id FROM smart_alarm.tenants WHERE id = $1 AND status = 'ACTIVE'", tenant_id,
                )
                if tenant is None:
                    raise WriteError("tenant_not_found", 404)
                platform_tenant_id = tenant["thingsboard_tenant_id"]
                if platform_tenant_id is None:
                    raise WriteError("tenant_identity_mapping_required", 409)
                role_id = await connection.fetchval(
                    "SELECT id FROM smart_alarm.product_roles WHERE role_key = $1 AND authority = 'TENANT_ADMIN' AND status = 'ACTIVE'",
                    role_key,
                )
                if role_id is None:
                    raise WriteError("product_role_unavailable", 503)
                if await connection.fetchval("SELECT 1 FROM smart_alarm.users WHERE username = $1 AND status <> 'ARCHIVED'", username) == 1:
                    raise WriteError("user_already_exists", 409)
            try:
                platform_user = await platform.provision_user(
                    context.platform_token, username=username, email=email, authority="TENANT_ADMIN",
                    tenant_id=platform_tenant_id, customer_id=None, password=password, enabled=status == "ACTIVE",
                )
            except ThingsBoardError as exc:
                await _fail_operation(database, principal, operation_id, exc.code)
                raise _platform_write_error(exc) from exc
            try:
                async with _scoped_connection(await database(), principal) as connection:
                    row = await connection.fetchrow(
                        "INSERT INTO smart_alarm.users (oidc_subject, thingsboard_user_id, username, email, authority, tenant_id, status) VALUES ($1, $2, $3, $4, 'TENANT_ADMIN', $5, $6) RETURNING id, username, email, authority, tenant_id, customer_id, status",
                        f"thingsboard:{platform_user.user_id}", platform_user.user_id, username, email, tenant_id, status,
                    )
                    await connection.execute(
                        "INSERT INTO smart_alarm.role_assignments (user_id, role_id, tenant_id, customer_id, granted_by) VALUES ($1, $2, $3, NULL, $4)",
                        row["id"], role_id, tenant_id, principal.local_user_id,
                    )
                    public = {"id": str(row["id"]), "username": row["username"], "email": row["email"], "authority": row["authority"], "status": row["status"], "tenantId": str(row["tenant_id"])}
                    result = {"operationId": str(operation_id), "kind": "system-user-create", "status": "SUCCEEDED", "user": public}
                    await _finish_operation(connection, operation_id, result, str(row["id"]))
                    await _audit(connection, principal, key, "TENANT_ADMIN_CREATED", "USER", str(row["id"]), {"username": username, "tenantId": str(tenant_id), "productRole": role_key})
            except Exception as exc:
                try:
                    await platform.delete_user(context.platform_token, platform_user.user_id, missing_ok=True)
                except ThingsBoardError:
                    pass
                await _fail_operation(database, principal, operation_id, "local_identity_persist_failed")
                if isinstance(exc, WriteError):
                    raise
                raise WriteError("local_identity_persist_failed", 503) from exc
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_user_scope"))

    @router.patch("/api/v1/system/users/{user_id}")
    async def update_system_user(user_id: str, request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "system:users:write")
            context, platform = _platform_context(request, thingsboard)
            user_uuid, key = UUID(user_id), _idempotency(request)
            status = body.get("status")
            if status not in {"ACTIVE", "SUSPENDED"}:
                raise WriteError("invalid_user_status")
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "system-user-update", "USER", _body_hash({"userId": user_id, **body}))
                if replay is not None:
                    return replay
                current = await connection.fetchrow(
                    "SELECT thingsboard_user_id, status FROM smart_alarm.users WHERE id = $1 AND authority = 'TENANT_ADMIN' AND status <> 'ARCHIVED'", user_uuid,
                )
                if current is None:
                    raise WriteError("not_found", 404)
                platform_user_id = current["thingsboard_user_id"]
                if platform_user_id is None:
                    raise WriteError("identity_mapping_required", 409)
                previous_status = current["status"]
            try:
                await platform.set_user_enabled(context.platform_token, platform_user_id, status == "ACTIVE")
            except ThingsBoardError as exc:
                await _fail_operation(database, principal, operation_id, exc.code)
                raise _platform_write_error(exc) from exc
            try:
                async with _scoped_connection(await database(), principal) as connection:
                    row = await connection.fetchrow("UPDATE smart_alarm.users SET status = $2, identity_version = identity_version + 1, updated_at = clock_timestamp() WHERE id = $1 AND authority = 'TENANT_ADMIN' AND status <> 'ARCHIVED' RETURNING id, username, email, authority, tenant_id, customer_id, status", user_uuid, status)
                    if row is None:
                        raise WriteError("not_found", 404)
                    await connection.execute("UPDATE smart_alarm.http_sessions SET revoked_at = clock_timestamp() WHERE user_id = $1 AND revoked_at IS NULL", user_uuid)
                    public = {"id": str(row["id"]), "username": row["username"], "email": row["email"], "authority": row["authority"], "status": row["status"], "tenantId": str(row["tenant_id"])}
                    result = {"operationId": str(operation_id), "kind": "system-user-update", "status": "SUCCEEDED", "user": public}
                    await _finish_operation(connection, operation_id, result, user_id)
                    await _audit(connection, principal, key, "TENANT_ADMIN_STATUS_UPDATED", "USER", user_id, {"status": status})
            except Exception as exc:
                try:
                    await platform.set_user_enabled(context.platform_token, platform_user_id, previous_status == "ACTIVE")
                except ThingsBoardError:
                    pass
                await _fail_operation(database, principal, operation_id, "local_identity_update_failed")
                if isinstance(exc, WriteError):
                    raise
                raise WriteError("local_identity_update_failed", 503) from exc
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("not_found", 404))

    @router.post("/api/v1/system/users/{user_id}/archive")
    async def archive_system_user(user_id: str, request: Request):
        try:
            principal = await _guard(request, sessions, database, "system:users:write")
            context, platform = _platform_context(request, thingsboard)
            user_uuid, key = UUID(user_id), _idempotency(request)
            if user_uuid == principal.local_user_id:
                raise WriteError("cannot_archive_self", 409)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "system-user-archive", "USER", _body_hash({"userId": user_id}))
                if replay is not None:
                    return replay
                platform_user_id = await connection.fetchval("SELECT thingsboard_user_id FROM smart_alarm.users WHERE id = $1 AND authority = 'TENANT_ADMIN' AND status <> 'ARCHIVED'", user_uuid)
                if platform_user_id is None:
                    raise WriteError("not_found", 404)
            try:
                await platform.delete_user(context.platform_token, platform_user_id)
            except ThingsBoardError as exc:
                await _fail_operation(database, principal, operation_id, exc.code)
                raise _platform_write_error(exc) from exc
            async with _scoped_connection(await database(), principal) as connection:
                row = await connection.fetchrow("UPDATE smart_alarm.users SET status = 'ARCHIVED', archived_at = clock_timestamp(), identity_version = identity_version + 1, updated_at = clock_timestamp() WHERE id = $1 AND authority = 'TENANT_ADMIN' AND status <> 'ARCHIVED' RETURNING id, username, email, authority, tenant_id, customer_id, archived_at", user_uuid)
                if row is None:
                    raise WriteError("not_found", 404)
                await connection.execute("UPDATE smart_alarm.role_assignments SET status = 'REVOKED', revoked_at = clock_timestamp(), version = version + 1 WHERE user_id = $1 AND status = 'ACTIVE'", user_uuid)
                await connection.execute("UPDATE smart_alarm.http_sessions SET revoked_at = clock_timestamp() WHERE user_id = $1 AND revoked_at IS NULL", user_uuid)
                public = {"id": str(row["id"]), "username": row["username"], "email": row["email"], "authority": row["authority"], "status": "REMOVED", "archivedAt": int(row["archived_at"].timestamp() * 1000), "tenantId": str(row["tenant_id"])}
                result = {"operationId": str(operation_id), "kind": "system-user-archive", "status": "SUCCEEDED", "user": public}
                await _finish_operation(connection, operation_id, result, user_id)
                await _audit(connection, principal, key, "TENANT_ADMIN_ARCHIVED", "USER", user_id, {})
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("not_found", 404))

    async def assign_product_role(request: Request, body: dict[str, object], user_id: str, operation_type: str) -> dict[str, object]:
        principal = await _guard(request, sessions, database, "system:roles:write")
        user_uuid, key = UUID(user_id), _idempotency(request)
        authority, role_key = body.get("authority"), body.get("productRole")
        if not isinstance(authority, str) or not isinstance(role_key, str):
            raise WriteError("invalid_role_assignment")
        async with _scoped_connection(await database(), principal) as connection:
            operation_id, replay = await _begin_operation(connection, principal, key, operation_type, "ROLE_ASSIGNMENT", _body_hash({"userId": user_id, **body}))
            if replay is not None:
                return replay
            user = await connection.fetchrow("SELECT id, authority, tenant_id, customer_id, status FROM smart_alarm.users WHERE id = $1 AND status <> 'ARCHIVED'", user_uuid)
            role = await connection.fetchrow("SELECT id, role_key, authority FROM smart_alarm.product_roles WHERE role_key = $1 AND status = 'ACTIVE'", role_key)
            if user is None or role is None:
                raise WriteError("not_found", 404)
            if user["authority"] != authority or role["authority"] != authority:
                raise WriteError("role_authority_mismatch", 409)
            await connection.execute("UPDATE smart_alarm.role_assignments SET status = 'REVOKED', revoked_at = clock_timestamp(), version = version + 1 WHERE user_id = $1 AND status = 'ACTIVE'", user_uuid)
            await connection.execute("INSERT INTO smart_alarm.role_assignments (user_id, role_id, tenant_id, customer_id, granted_by) VALUES ($1, $2, $3, $4, $5)", user_uuid, role["id"], user["tenant_id"], user["customer_id"], principal.local_user_id)
            await connection.execute("UPDATE smart_alarm.users SET identity_version = identity_version + 1, updated_at = clock_timestamp() WHERE id = $1", user_uuid)
            result = {"operationId": str(operation_id), "kind": operation_type, "status": "SUCCEEDED", "assignment": {"userId": user_id, "authority": authority, "productRole": role_key}}
            await _finish_operation(connection, operation_id, result, user_id)
            await _audit(connection, principal, key, "PRODUCT_ROLE_ASSIGNED", "ROLE_ASSIGNMENT", user_id, {"productRole": role_key})
        return result

    @router.post("/api/v1/system/role-assignments")
    async def create_role_assignment(request: Request, body: dict[str, object]):
        try:
            user_id = body.get("userId")
            if not isinstance(user_id, str):
                raise WriteError("invalid_role_assignment")
            return await assign_product_role(request, body, user_id, "system-role-create")
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_role_assignment"))

    @router.patch("/api/v1/system/role-assignments/{user_id}")
    async def update_role_assignment(user_id: str, request: Request, body: dict[str, object]):
        try:
            return await assign_product_role(request, body, user_id, "system-role-update")
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_role_assignment"))

    @router.post("/api/v1/system/role-assignments/{user_id}/archive")
    async def archive_role_assignment(user_id: str, request: Request):
        try:
            principal = await _guard(request, sessions, database, "system:roles:write")
            user_uuid, key = UUID(user_id), _idempotency(request)
            if user_uuid == principal.local_user_id:
                raise WriteError("cannot_revoke_self", 409)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "system-role-archive", "ROLE_ASSIGNMENT", _body_hash({"userId": user_id}))
                if replay is not None:
                    return replay
                row = await connection.fetchrow("UPDATE smart_alarm.role_assignments ra SET status = 'REVOKED', revoked_at = clock_timestamp(), version = version + 1 FROM smart_alarm.users u, smart_alarm.product_roles pr WHERE ra.user_id = $1 AND ra.status = 'ACTIVE' AND u.id = ra.user_id AND pr.id = ra.role_id RETURNING u.authority, pr.role_key, ra.revoked_at", user_uuid)
                if row is None:
                    raise WriteError("not_found", 404)
                await connection.execute("UPDATE smart_alarm.users SET identity_version = identity_version + 1, updated_at = clock_timestamp() WHERE id = $1", user_uuid)
                result = {"operationId": str(operation_id), "kind": "system-role-archive", "status": "SUCCEEDED", "assignment": {"userId": user_id, "authority": row["authority"], "productRole": row["role_key"], "revokedAt": int(row["revoked_at"].timestamp() * 1000)}}
                await _finish_operation(connection, operation_id, result, user_id)
                await _audit(connection, principal, key, "PRODUCT_ROLE_REVOKED", "ROLE_ASSIGNMENT", user_id, {})
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("not_found", 404))

    @router.post("/api/v1/customers")
    async def create_customer(request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "customers:write")
            if principal.internal_tenant_id is None:
                raise WriteError("tenant_scope_required", 403)
            context, platform = _platform_context(request, thingsboard)
            if context.principal.platform_tenant_id is None:
                raise WriteError("tenant_identity_mapping_required", 409)
            name = _name(body, 255)
            key = _idempotency(request)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "customer-create", "CUSTOMER", _body_hash(body))
                if replay is not None:
                    return replay
                if await connection.fetchval(
                    "SELECT 1 FROM smart_alarm.customers WHERE tenant_id = $1 AND lower(name) = lower($2) AND status = 'ACTIVE'",
                    principal.internal_tenant_id, name,
                ) == 1:
                    raise WriteError("customer_already_exists", 409)
            try:
                platform_customer_id = await platform.create_customer(context.platform_token, name=name)
            except ThingsBoardError as exc:
                await _fail_operation(database, principal, operation_id, exc.code)
                raise _platform_write_error(exc) from exc
            try:
                async with _scoped_connection(await database(), principal) as connection:
                    row = await connection.fetchrow("INSERT INTO smart_alarm.customers (tenant_id, thingsboard_customer_id, name) VALUES ($1, $2, $3) RETURNING id, name", principal.internal_tenant_id, platform_customer_id, name)
                    result = {"operationId": str(operation_id), "kind": "customer-create", "status": "SUCCEEDED", "customer": {"id": str(row["id"]), "name": row["name"], "deviceCount": 0, "assetCount": 0}}
                    await _finish_operation(connection, operation_id, result, str(row["id"]))
                    await _audit(connection, principal, key, "CUSTOMER_CREATED", "CUSTOMER", str(row["id"]), {"name": name, "thingsboardCustomerId": str(platform_customer_id)})
                return result
            except Exception as exc:
                try:
                    await platform.delete_customer(context.platform_token, platform_customer_id, missing_ok=True)
                except ThingsBoardError:
                    _LOGGER.exception("failed to compensate ThingsBoard customer %s", platform_customer_id)
                await _fail_operation(database, principal, operation_id, "local_customer_persist_failed")
                if isinstance(exc, WriteError):
                    raise
                raise WriteError("local_customer_persist_failed", 503) from exc
        except (WriteError, ThingsBoardError) as exc:
            if isinstance(exc, ThingsBoardError):
                return _write_error(_platform_write_error(exc))
            return _write_error(exc)

    @router.patch("/api/v1/customers/{customer_id}")
    async def update_customer(customer_id: str, request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "customers:write")
            if principal.internal_tenant_id is None:
                raise WriteError("tenant_scope_required", 403)
            context, platform = _platform_context(request, thingsboard)
            name = _name(body, 255)
            key = _idempotency(request)
            customer_uuid = UUID(customer_id)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "customer-update", "CUSTOMER", _body_hash({"customerId": customer_id, **body}))
                if replay is not None:
                    return replay
                current = await connection.fetchrow("SELECT thingsboard_customer_id, name FROM smart_alarm.customers WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'", principal.internal_tenant_id, customer_uuid)
                if current is None:
                    raise WriteError("not_found", 404)
                platform_customer_id, previous_name = current["thingsboard_customer_id"], current["name"]
                if platform_customer_id is None:
                    raise WriteError("customer_identity_mapping_required", 409)
            try:
                await platform.update_customer(context.platform_token, platform_customer_id, name=name)
            except ThingsBoardError as exc:
                await _fail_operation(database, principal, operation_id, exc.code)
                raise _platform_write_error(exc) from exc
            try:
                async with _scoped_connection(await database(), principal) as connection:
                    row = await connection.fetchrow("UPDATE smart_alarm.customers SET name = $3, version = version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE' RETURNING id, name", principal.internal_tenant_id, customer_uuid, name)
                    if row is None:
                        raise WriteError("not_found", 404)
                    result = {"operationId": str(operation_id), "kind": "customer-update", "status": "SUCCEEDED", "customer": {"id": str(row["id"]), "name": row["name"], "deviceCount": 0, "assetCount": 0}}
                    await _finish_operation(connection, operation_id, result, customer_id)
                    await _audit(connection, principal, key, "CUSTOMER_UPDATED", "CUSTOMER", customer_id, {"name": name})
                return result
            except Exception as exc:
                try:
                    await platform.update_customer(context.platform_token, platform_customer_id, name=previous_name)
                except ThingsBoardError:
                    _LOGGER.exception("failed to compensate ThingsBoard customer rename %s", platform_customer_id)
                await _fail_operation(database, principal, operation_id, "local_customer_update_failed")
                if isinstance(exc, WriteError):
                    raise
                raise WriteError("local_customer_update_failed", 503) from exc
        except (WriteError, ValueError, ThingsBoardError) as exc:
            if isinstance(exc, ThingsBoardError):
                return _write_error(_platform_write_error(exc))
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("not_found", 404))

    @router.post("/api/v1/customers/{customer_id}/archive")
    async def archive_customer(customer_id: str, request: Request):
        try:
            principal = await _guard(request, sessions, database, "customers:write")
            context, platform = _platform_context(request, thingsboard)
            customer_uuid = UUID(customer_id)
            key = _idempotency(request)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "customer-archive", "CUSTOMER", _body_hash({"customerId": customer_id}))
                if replay is not None:
                    return replay
                current = await connection.fetchrow("SELECT thingsboard_customer_id, name FROM smart_alarm.customers WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'", principal.internal_tenant_id, customer_uuid)
                if current is None:
                    raise WriteError("not_found", 404)
                active_resources = await connection.fetchval(
                    """
                    SELECT
                        (SELECT count(*) FROM smart_alarm.devices WHERE tenant_id = $1 AND customer_id = $2 AND lifecycle_state <> 'RETIRED') +
                        (SELECT count(*) FROM smart_alarm.users WHERE tenant_id = $1 AND customer_id = $2 AND status <> 'ARCHIVED') +
                        (SELECT count(*) FROM smart_alarm.assets WHERE tenant_id = $1 AND customer_id = $2 AND status = 'ACTIVE')
                    """,
                    principal.internal_tenant_id, customer_uuid,
                )
                if active_resources:
                    raise WriteError("customer_has_resources", 409)
                platform_customer_id, customer_name = current["thingsboard_customer_id"], current["name"]
                if platform_customer_id is None:
                    raise WriteError("customer_identity_mapping_required", 409)
            try:
                await platform.delete_customer(context.platform_token, platform_customer_id)
            except ThingsBoardError as exc:
                await _fail_operation(database, principal, operation_id, exc.code)
                raise _platform_write_error(exc) from exc
            try:
                async with _scoped_connection(await database(), principal) as connection:
                    row = await connection.fetchrow("UPDATE smart_alarm.customers SET status = 'ARCHIVED', archived_at = clock_timestamp(), version = version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE' RETURNING id, name, archived_at", principal.internal_tenant_id, customer_uuid)
                    if row is None:
                        raise WriteError("not_found", 404)
                    result = {"operationId": str(operation_id), "kind": "customer-archive", "status": "SUCCEEDED", "customer": {"id": str(row["id"]), "name": row["name"], "deviceCount": 0, "assetCount": 0}}
                    await _finish_operation(connection, operation_id, result, customer_id)
                    await _audit(connection, principal, key, "CUSTOMER_ARCHIVED", "CUSTOMER", customer_id, {})
                return result
            except Exception as exc:
                try:
                    replacement_id = await platform.create_customer(context.platform_token, name=customer_name)
                    async with _scoped_connection(await database(), principal) as connection:
                        await connection.execute(
                            "UPDATE smart_alarm.customers SET thingsboard_customer_id = $3 WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'",
                            principal.internal_tenant_id, customer_uuid, replacement_id,
                        )
                except Exception:
                    _LOGGER.exception("failed to compensate ThingsBoard customer archive %s", platform_customer_id)
                await _fail_operation(database, principal, operation_id, "local_customer_archive_failed")
                if isinstance(exc, WriteError):
                    raise
                raise WriteError("local_customer_archive_failed", 503) from exc
        except (WriteError, ValueError, ThingsBoardError) as exc:
            if isinstance(exc, ThingsBoardError):
                return _write_error(_platform_write_error(exc))
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("not_found", 404))

    @router.post("/api/v1/customers/{customer_id}/members")
    async def create_customer_member(customer_id: str, request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "customers:members:write")
            if principal.internal_tenant_id is None:
                raise WriteError("tenant_scope_required", 403)
            context, platform = _platform_context(request, thingsboard)
            if context.principal.platform_tenant_id is None:
                raise WriteError("tenant_identity_mapping_required", 409)
            customer_uuid = UUID(customer_id)
            username, email, password, role_key, status = _account_input(
                body, {"CUSTOMER_OPERATOR", "CUSTOMER_VIEWER"},
            )
            key = _idempotency(request)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(
                    connection, principal, key, "customer-member-create", "USER",
                    _account_request_hash({"customerId": customer_id, **body}),
                )
                if replay is not None:
                    return replay
                customer = await connection.fetchrow(
                    "SELECT thingsboard_customer_id FROM smart_alarm.customers WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'",
                    principal.internal_tenant_id, customer_uuid,
                )
                if customer is None:
                    raise WriteError("not_found", 404)
                platform_customer_id = customer["thingsboard_customer_id"]
                if platform_customer_id is None:
                    raise WriteError("customer_identity_mapping_required", 409)
                if await connection.fetchval("SELECT 1 FROM smart_alarm.users WHERE username = $1 AND status <> 'ARCHIVED'", username) == 1:
                    raise WriteError("member_already_exists", 409)
                role_id = await connection.fetchval(
                    "SELECT id FROM smart_alarm.product_roles WHERE role_key = $1 AND authority = 'CUSTOMER_USER' AND status = 'ACTIVE'", role_key,
                )
                if role_id is None:
                    raise WriteError("product_role_unavailable", 503)
            try:
                platform_user = await platform.provision_user(
                    context.platform_token, username=username, email=email, authority="CUSTOMER_USER",
                    tenant_id=context.principal.platform_tenant_id, customer_id=platform_customer_id,
                    password=password, enabled=status == "ACTIVE",
                )
            except ThingsBoardError as exc:
                await _fail_operation(database, principal, operation_id, exc.code)
                raise _platform_write_error(exc) from exc
            try:
                async with _scoped_connection(await database(), principal) as connection:
                    user = await connection.fetchrow(
                        "INSERT INTO smart_alarm.users (oidc_subject, thingsboard_user_id, username, email, authority, tenant_id, customer_id, status) VALUES ($1, $2, $3, $4, 'CUSTOMER_USER', $5, $6, $7) RETURNING id, username, email, status",
                        f"thingsboard:{platform_user.user_id}", platform_user.user_id, username, email,
                        principal.internal_tenant_id, customer_uuid, status,
                    )
                    await connection.execute("INSERT INTO smart_alarm.role_assignments (user_id, role_id, tenant_id, customer_id, granted_by) VALUES ($1, $2, $3, $4, $5)", user["id"], role_id, principal.internal_tenant_id, customer_uuid, principal.local_user_id)
                    result = {"operationId": str(operation_id), "kind": "customer-member-create", "status": "SUCCEEDED", "customerId": customer_id, "member": {"id": str(user["id"]), "username": user["username"], "email": user["email"], "status": user["status"]}}
                    await _finish_operation(connection, operation_id, result, str(user["id"]))
                    await _audit(connection, principal, key, "CUSTOMER_MEMBER_CREATED", "USER", str(user["id"]), {"customerId": customer_id, "username": username, "productRole": role_key})
            except Exception as exc:
                try:
                    await platform.delete_user(context.platform_token, platform_user.user_id, missing_ok=True)
                except ThingsBoardError:
                    pass
                await _fail_operation(database, principal, operation_id, "local_identity_persist_failed")
                if isinstance(exc, WriteError):
                    raise
                raise WriteError("local_identity_persist_failed", 503) from exc
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("not_found", 404))

    @router.patch("/api/v1/customers/{customer_id}/members/{member_id}")
    async def update_customer_member(customer_id: str, member_id: str, request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "customers:members:write")
            customer_uuid, member_uuid = UUID(customer_id), UUID(member_id)
            status = body.get("status")
            if status not in {"ACTIVE", "SUSPENDED"}:
                raise WriteError("invalid_member_status")
            key = _idempotency(request)
            context, platform = _platform_context(request, thingsboard)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "customer-member-update", "USER", _body_hash({"customerId": customer_id, "memberId": member_id, **body}))
                if replay is not None:
                    return replay
                current = await connection.fetchrow("SELECT thingsboard_user_id, status FROM smart_alarm.users WHERE tenant_id = $1 AND customer_id = $2 AND id = $3 AND authority = 'CUSTOMER_USER' AND status <> 'ARCHIVED'", principal.internal_tenant_id, customer_uuid, member_uuid)
                if current is None:
                    raise WriteError("not_found", 404)
                platform_user_id, previous_status = current["thingsboard_user_id"], current["status"]
                if platform_user_id is None:
                    raise WriteError("identity_mapping_required", 409)
            try:
                await platform.set_user_enabled(context.platform_token, platform_user_id, status == "ACTIVE")
            except ThingsBoardError as exc:
                await _fail_operation(database, principal, operation_id, exc.code)
                raise _platform_write_error(exc) from exc
            try:
                async with _scoped_connection(await database(), principal) as connection:
                    row = await connection.fetchrow("UPDATE smart_alarm.users SET status = $4, identity_version = identity_version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND customer_id = $2 AND id = $3 AND authority = 'CUSTOMER_USER' AND status <> 'ARCHIVED' RETURNING id, username, email, status", principal.internal_tenant_id, customer_uuid, member_uuid, status)
                    if row is None:
                        raise WriteError("not_found", 404)
                    await connection.execute("UPDATE smart_alarm.http_sessions SET revoked_at = clock_timestamp() WHERE user_id = $1 AND revoked_at IS NULL", member_uuid)
                    result = {"operationId": str(operation_id), "kind": "customer-member-update", "status": "SUCCEEDED", "customerId": customer_id, "member": {"id": str(row["id"]), "username": row["username"], "email": row["email"], "status": row["status"]}}
                    await _finish_operation(connection, operation_id, result, member_id)
                    await _audit(connection, principal, key, "CUSTOMER_MEMBER_UPDATED", "USER", member_id, {"customerId": customer_id, "status": status})
            except Exception as exc:
                try:
                    await platform.set_user_enabled(context.platform_token, platform_user_id, previous_status == "ACTIVE")
                except ThingsBoardError:
                    pass
                await _fail_operation(database, principal, operation_id, "local_identity_update_failed")
                if isinstance(exc, WriteError):
                    raise
                raise WriteError("local_identity_update_failed", 503) from exc
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("not_found", 404))

    @router.post("/api/v1/customers/{customer_id}/members/{member_id}/archive")
    async def archive_customer_member(customer_id: str, member_id: str, request: Request):
        try:
            principal = await _guard(request, sessions, database, "customers:members:write")
            customer_uuid, member_uuid = UUID(customer_id), UUID(member_id)
            key = _idempotency(request)
            context, platform = _platform_context(request, thingsboard)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "customer-member-archive", "USER", _body_hash({"customerId": customer_id, "memberId": member_id}))
                if replay is not None:
                    return replay
                platform_user_id = await connection.fetchval("SELECT thingsboard_user_id FROM smart_alarm.users WHERE tenant_id = $1 AND customer_id = $2 AND id = $3 AND authority = 'CUSTOMER_USER' AND status <> 'ARCHIVED'", principal.internal_tenant_id, customer_uuid, member_uuid)
                if platform_user_id is None:
                    raise WriteError("not_found", 404)
            try:
                await platform.delete_user(context.platform_token, platform_user_id)
            except ThingsBoardError as exc:
                await _fail_operation(database, principal, operation_id, exc.code)
                raise _platform_write_error(exc) from exc
            async with _scoped_connection(await database(), principal) as connection:
                row = await connection.fetchrow("UPDATE smart_alarm.users SET status = 'ARCHIVED', archived_at = clock_timestamp(), identity_version = identity_version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND customer_id = $2 AND id = $3 AND authority = 'CUSTOMER_USER' AND status <> 'ARCHIVED' RETURNING id, username, email, archived_at", principal.internal_tenant_id, customer_uuid, member_uuid)
                if row is None:
                    raise WriteError("not_found", 404)
                await connection.execute("UPDATE smart_alarm.role_assignments SET status = 'REVOKED', revoked_at = clock_timestamp(), version = version + 1 WHERE user_id = $1 AND status = 'ACTIVE'", member_uuid)
                await connection.execute("UPDATE smart_alarm.http_sessions SET revoked_at = clock_timestamp() WHERE user_id = $1 AND revoked_at IS NULL", member_uuid)
                result = {"operationId": str(operation_id), "kind": "customer-member-archive", "status": "SUCCEEDED", "customerId": customer_id, "member": {"id": str(row["id"]), "username": row["username"], "email": row["email"], "status": "REMOVED", "archivedAt": int(row["archived_at"].timestamp() * 1000)}}
                await _finish_operation(connection, operation_id, result, member_id)
                await _audit(connection, principal, key, "CUSTOMER_MEMBER_ARCHIVED", "USER", member_id, {"customerId": customer_id})
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("not_found", 404))

    @router.post("/api/v1/assets")
    async def create_asset(request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "assets:write")
            if principal.internal_tenant_id is None:
                raise WriteError("tenant_scope_required", 403)
            name, asset_type = _name(body), body.get("type")
            if not isinstance(asset_type, str) or not asset_type or len(asset_type) > 64:
                raise WriteError("invalid_asset_type")
            customer_id = body.get("customerId")
            parent_id = body.get("parentAssetId")
            customer_uuid = UUID(customer_id) if isinstance(customer_id, str) else principal.internal_customer_id
            parent_uuid = UUID(parent_id) if isinstance(parent_id, str) else None
            if principal.internal_customer_id is not None and customer_uuid != principal.internal_customer_id:
                raise WriteError("scope_mismatch", 404)
            key = _idempotency(request)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "asset-create", "ASSET", _body_hash(body))
                if replay is not None:
                    return replay
                if customer_uuid is not None and await connection.fetchval("SELECT 1 FROM smart_alarm.customers WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'", principal.internal_tenant_id, customer_uuid) != 1:
                    raise WriteError("customer_not_found", 404)
                if parent_uuid is not None:
                    parent = await connection.fetchrow("SELECT customer_id FROM smart_alarm.assets WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'", principal.internal_tenant_id, parent_uuid)
                    if parent is None:
                        raise WriteError("parent_asset_not_found", 404)
                    if parent["customer_id"] != customer_uuid:
                        raise WriteError("parent_asset_scope_mismatch", 404)
                row = await connection.fetchrow("INSERT INTO smart_alarm.assets (tenant_id, customer_id, parent_asset_id, name, asset_type, platform_sync_status) VALUES ($1, $2, $3, $4, $5, 'PENDING_CREATE') RETURNING id, name, asset_type, customer_id", principal.internal_tenant_id, customer_uuid, parent_uuid, name, asset_type)
                if parent_uuid is not None:
                    await connection.execute(
                        """
                        INSERT INTO smart_alarm.entity_relations (tenant_id, from_type, from_id, to_type, to_id, relation_type, status)
                        VALUES ($1, 'ASSET', $2, 'ASSET', $3, 'Contains', 'PENDING_CREATE')
                        """,
                        principal.internal_tenant_id, parent_uuid, row["id"],
                    )
                result = {"operationId": str(operation_id), "kind": "asset-create", "status": "QUEUED", "asset": {"id": str(row["id"]), "name": row["name"], "type": row["asset_type"], "customerId": str(row["customer_id"]) if row["customer_id"] else None, "deviceCount": 0}}
                await _queue_operation(connection, operation_id, result, str(row["id"]))
                await _outbox(connection, principal.internal_tenant_id, "ASSET", str(row["id"]), ASSET_SYNC_EVENT, {"operationId": str(operation_id)})
                await _audit(connection, principal, key, "ASSET_CREATED", "ASSET", str(row["id"]), {"name": name}, "ACCEPTED")
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))

    @router.patch("/api/v1/assets/{asset_id}")
    async def update_asset(asset_id: str, request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "assets:write")
            tenant_id, session_customer = _tenant_scope(principal)
            asset_uuid, key = UUID(asset_id), _idempotency(request)
            async with _scoped_connection(await database(), principal) as connection:
                current = await connection.fetchrow("SELECT id, name, asset_type, customer_id, parent_asset_id, platform_sync_status, thingsboard_asset_id FROM smart_alarm.assets WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE' AND ($3::uuid IS NULL OR customer_id = $3)", tenant_id, asset_uuid, session_customer)
                if current is None:
                    raise WriteError("not_found", 404)
                if current["platform_sync_status"].startswith("PENDING_"):
                    raise WriteError("asset_platform_sync_in_progress", 409)
                name, asset_type = body.get("name", current["name"]), body.get("type", current["asset_type"])
                raw_customer, raw_parent = body.get("customerId", current["customer_id"]), body.get("parentAssetId", current["parent_asset_id"])
                customer_id = UUID(raw_customer) if isinstance(raw_customer, str) else raw_customer
                parent_id = UUID(raw_parent) if isinstance(raw_parent, str) else raw_parent
                if not isinstance(name, str) or not name or name != name.strip() or not isinstance(asset_type, str) or not asset_type or len(asset_type) > 64 or parent_id == asset_uuid:
                    raise WriteError("invalid_asset")
                if session_customer is not None and customer_id != session_customer:
                    raise WriteError("scope_mismatch", 404)
                if parent_id is not None:
                    parent = await connection.fetchrow("SELECT customer_id FROM smart_alarm.assets WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'", tenant_id, parent_id)
                    if parent is None or parent["customer_id"] != customer_id:
                        raise WriteError("parent_asset_scope_mismatch", 404)
                    if await connection.fetchval("WITH RECURSIVE descendants AS (SELECT id FROM smart_alarm.assets WHERE tenant_id = $1 AND parent_asset_id = $2 UNION ALL SELECT a.id FROM smart_alarm.assets a JOIN descendants d ON a.parent_asset_id = d.id WHERE a.tenant_id = $1) SELECT 1 FROM descendants WHERE id = $3 LIMIT 1", tenant_id, asset_uuid, parent_id) == 1:
                        raise WriteError("asset_cycle", 409)
                operation_id, replay = await _begin_operation(connection, principal, key, "asset-update", "ASSET", _body_hash({"assetId": asset_id, **body}))
                if replay is not None:
                    return replay
                next_sync = "PENDING_UPDATE" if current["thingsboard_asset_id"] is not None else "PENDING_CREATE"
                row = await connection.fetchrow("UPDATE smart_alarm.assets SET name = $3, asset_type = $4, customer_id = $5, parent_asset_id = $6, platform_sync_status = $7, platform_error_code = NULL, version = version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE' RETURNING id, name, asset_type, customer_id", tenant_id, asset_uuid, name, asset_type, customer_id, parent_id, next_sync)
                if current["parent_asset_id"] != parent_id:
                    if current["parent_asset_id"] is not None:
                        await connection.execute("UPDATE smart_alarm.entity_relations SET status = 'PENDING_DELETE', updated_at = clock_timestamp(), version = version + 1 WHERE tenant_id = $1 AND from_id = $2 AND to_type = 'ASSET' AND to_id = $3 AND relation_type = 'Contains'", tenant_id, current["parent_asset_id"], asset_uuid)
                    if parent_id is not None:
                        await connection.execute(
                            """
                            INSERT INTO smart_alarm.entity_relations (tenant_id, from_type, from_id, to_type, to_id, relation_type, status)
                            VALUES ($1, 'ASSET', $2, 'ASSET', $3, 'Contains', 'PENDING_CREATE')
                            ON CONFLICT (tenant_id, from_type, from_id, to_type, to_id, relation_type)
                            DO UPDATE SET status = 'PENDING_CREATE', updated_at = clock_timestamp(), version = smart_alarm.entity_relations.version + 1
                            """,
                            tenant_id, parent_id, asset_uuid,
                        )
                result = {"operationId": str(operation_id), "kind": "asset-update", "status": "QUEUED", "asset": {"id": str(row["id"]), "name": row["name"], "type": row["asset_type"], "customerId": str(row["customer_id"]) if row["customer_id"] else None, "deviceCount": 0}}
                await _queue_operation(connection, operation_id, result, asset_id)
                await _outbox(connection, tenant_id, "ASSET", asset_id, ASSET_SYNC_EVENT, {"operationId": str(operation_id)})
                await _audit(connection, principal, key, "ASSET_UPDATED", "ASSET", asset_id, {"name": name}, "ACCEPTED")
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))

    @router.post("/api/v1/assets/{asset_id}/archive")
    async def archive_asset(asset_id: str, request: Request):
        try:
            principal = await _guard(request, sessions, database, "assets:write")
            tenant_id, session_customer = _tenant_scope(principal)
            asset_uuid, key = UUID(asset_id), _idempotency(request)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "asset-archive", "ASSET", _body_hash({"assetId": asset_id}))
                if replay is not None:
                    return replay
                current = await connection.fetchrow("SELECT platform_sync_status, thingsboard_asset_id FROM smart_alarm.assets WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE' AND ($3::uuid IS NULL OR customer_id = $3)", tenant_id, asset_uuid, session_customer)
                if current is None:
                    raise WriteError("not_found", 404)
                if current["platform_sync_status"].startswith("PENDING_"):
                    raise WriteError("asset_platform_sync_in_progress", 409)
                if await connection.fetchval("SELECT 1 FROM smart_alarm.assets WHERE tenant_id = $1 AND parent_asset_id = $2 AND status = 'ACTIVE' LIMIT 1", tenant_id, asset_uuid) == 1 or await connection.fetchval("SELECT 1 FROM smart_alarm.devices WHERE tenant_id = $1 AND asset_id = $2 AND lifecycle_state <> 'RETIRED' LIMIT 1", tenant_id, asset_uuid) == 1:
                    raise WriteError("asset_has_resources", 409)
                next_sync = "PENDING_DELETE" if current["thingsboard_asset_id"] is not None else "SYNCED"
                row = await connection.fetchrow("UPDATE smart_alarm.assets SET status = 'ARCHIVED', archived_at = clock_timestamp(), platform_sync_status = $3, version = version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE' AND ($4::uuid IS NULL OR customer_id = $4) RETURNING id, name, asset_type, customer_id", tenant_id, asset_uuid, next_sync, session_customer)
                if row is None:
                    raise WriteError("not_found", 404)
                await connection.execute("UPDATE smart_alarm.entity_relations SET status = 'PENDING_DELETE', updated_at = clock_timestamp(), version = version + 1 WHERE tenant_id = $1 AND to_type = 'ASSET' AND to_id = $2 AND status = 'ACTIVE'", tenant_id, asset_uuid)
                result = {"operationId": str(operation_id), "kind": "asset-archive", "status": "QUEUED", "asset": {"id": str(row["id"]), "name": row["name"], "type": row["asset_type"], "customerId": str(row["customer_id"]) if row["customer_id"] else None, "deviceCount": 0}}
                await _queue_operation(connection, operation_id, result, asset_id)
                if next_sync == "PENDING_DELETE":
                    await _outbox(connection, tenant_id, "ASSET", asset_id, ASSET_SYNC_EVENT, {"operationId": str(operation_id)})
                else:
                    await connection.execute("DELETE FROM smart_alarm.entity_relations WHERE tenant_id = $1 AND to_type = 'ASSET' AND to_id = $2 AND status = 'PENDING_DELETE'", tenant_id, asset_uuid)
                    await _finish_operation(connection, operation_id, {**result, "status": "SUCCEEDED"}, asset_id)
                await _audit(connection, principal, key, "ASSET_ARCHIVED", "ASSET", asset_id, {}, "ACCEPTED")
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("not_found", 404))

    @router.post("/api/v1/device-profiles")
    async def create_device_profile(request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "device-profiles:write")
            tenant_id, _ = _tenant_scope(principal)
            name = _name(body)
            profile_type, transport = body.get("type"), body.get("transportType")
            if not isinstance(profile_type, str) or not profile_type or len(profile_type) > 64 or transport not in {"DEFAULT", "MQTT"}:
                raise WriteError("invalid_device_profile")
            is_default = body.get("isDefault", False)
            if not isinstance(is_default, bool):
                raise WriteError("invalid_device_profile")
            key = _idempotency(request)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "device-profile-create", "DEVICE_PROFILE", _body_hash(body))
                if replay is not None:
                    return replay
                if is_default:
                    await connection.execute("UPDATE smart_alarm.device_profiles SET is_default = false, version = version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND is_default AND status = 'ACTIVE'", tenant_id)
                row = await connection.fetchrow("INSERT INTO smart_alarm.device_profiles (tenant_id, name, profile_type, transport_type, is_default, platform_sync_status) VALUES ($1, $2, $3, $4, $5, 'PENDING_CREATE') RETURNING id, name, profile_type, transport_type, is_default", tenant_id, name, profile_type, transport, is_default)
                result = {"operationId": str(operation_id), "kind": "device-profile-create", "status": "QUEUED", "profile": {"id": str(row["id"]), "name": row["name"], "type": profile_type, "transportType": transport, "isDefault": row["is_default"]}}
                await _queue_operation(connection, operation_id, result, str(row["id"]))
                await _outbox(connection, tenant_id, "DEVICE_PROFILE", str(row["id"]), PROFILE_SYNC_EVENT, {"operationId": str(operation_id)})
                await _audit(connection, principal, key, "DEVICE_PROFILE_CREATED", "DEVICE_PROFILE", str(row["id"]), {"name": name}, "ACCEPTED")
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))

    @router.patch("/api/v1/device-profiles/{profile_id}")
    async def update_device_profile(profile_id: str, request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "device-profiles:write")
            tenant_id, _ = _tenant_scope(principal)
            profile_uuid = UUID(profile_id)
            key = _idempotency(request)
            async with _scoped_connection(await database(), principal) as connection:
                current = await connection.fetchrow("SELECT id, name, profile_type, transport_type, is_default, platform_sync_status, thingsboard_profile_id FROM smart_alarm.device_profiles WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'", tenant_id, profile_uuid)
                if current is None:
                    raise WriteError("not_found", 404)
                if current["platform_sync_status"].startswith("PENDING_"):
                    raise WriteError("device_profile_platform_sync_in_progress", 409)
                name = body.get("name", current["name"])
                profile_type, transport = body.get("type", current["profile_type"]), body.get("transportType", current["transport_type"])
                is_default = body.get("isDefault", current["is_default"])
                if not isinstance(name, str) or not name or name != name.strip() or not isinstance(profile_type, str) or not profile_type or len(profile_type) > 64 or transport not in {"DEFAULT", "MQTT"} or not isinstance(is_default, bool):
                    raise WriteError("invalid_device_profile")
                if current["is_default"] and not is_default:
                    raise WriteError("default_device_profile_required", 409)
                operation_id, replay = await _begin_operation(connection, principal, key, "device-profile-update", "DEVICE_PROFILE", _body_hash({"profileId": profile_id, **body}))
                if replay is not None:
                    return replay
                if is_default:
                    await connection.execute("UPDATE smart_alarm.device_profiles SET is_default = false, version = version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id <> $2 AND is_default AND status = 'ACTIVE'", tenant_id, profile_uuid)
                next_sync = "PENDING_UPDATE" if current["thingsboard_profile_id"] is not None else "PENDING_CREATE"
                row = await connection.fetchrow("UPDATE smart_alarm.device_profiles SET name = $3, profile_type = $4, transport_type = $5, is_default = $6, platform_sync_status = $7, platform_error_code = NULL, version = version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE' RETURNING id, name, profile_type, transport_type, is_default", tenant_id, profile_uuid, name, profile_type, transport, is_default, next_sync)
                result = {"operationId": str(operation_id), "kind": "device-profile-update", "status": "QUEUED", "profile": {"id": str(row["id"]), "name": row["name"], "type": profile_type, "transportType": transport, "isDefault": row["is_default"]}}
                await _queue_operation(connection, operation_id, result, profile_id)
                await _outbox(connection, tenant_id, "DEVICE_PROFILE", profile_id, PROFILE_SYNC_EVENT, {"operationId": str(operation_id)})
                await _audit(connection, principal, key, "DEVICE_PROFILE_UPDATED", "DEVICE_PROFILE", profile_id, {"name": name}, "ACCEPTED")
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("not_found", 404))

    @router.post("/api/v1/device-profiles/{profile_id}/archive")
    async def archive_device_profile(profile_id: str, request: Request):
        try:
            principal = await _guard(request, sessions, database, "device-profiles:write")
            tenant_id, _ = _tenant_scope(principal)
            profile_uuid = UUID(profile_id)
            key = _idempotency(request)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "device-profile-archive", "DEVICE_PROFILE", _body_hash({"profileId": profile_id}))
                if replay is not None:
                    return replay
                current = await connection.fetchrow("SELECT name, profile_type, transport_type, is_default, platform_sync_status, thingsboard_profile_id FROM smart_alarm.device_profiles WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'", tenant_id, profile_uuid)
                if current is None:
                    raise WriteError("not_found", 404)
                if current["platform_sync_status"].startswith("PENDING_"):
                    raise WriteError("device_profile_platform_sync_in_progress", 409)
                if current["is_default"]:
                    raise WriteError("default_device_profile_required", 409)
                if await connection.fetchval("SELECT 1 FROM smart_alarm.devices WHERE tenant_id = $1 AND device_profile_id = $2 AND lifecycle_state <> 'RETIRED'", tenant_id, profile_uuid) == 1:
                    raise WriteError("profile_in_use", 409)
                next_sync = "PENDING_DELETE" if current["thingsboard_profile_id"] is not None else "SYNCED"
                row = await connection.fetchrow("UPDATE smart_alarm.device_profiles SET status = 'ARCHIVED', archived_at = clock_timestamp(), platform_sync_status = $3, version = version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE' RETURNING id, name, profile_type, transport_type", tenant_id, profile_uuid, next_sync)
                if row is None:
                    raise WriteError("not_found", 404)
                result = {"operationId": str(operation_id), "kind": "device-profile-archive", "status": "QUEUED", "profile": {"id": str(row["id"]), "name": row["name"], "type": row["profile_type"], "transportType": row["transport_type"], "isDefault": False}}
                await _queue_operation(connection, operation_id, result, profile_id)
                if next_sync == "PENDING_DELETE":
                    await _outbox(connection, tenant_id, "DEVICE_PROFILE", profile_id, PROFILE_SYNC_EVENT, {"operationId": str(operation_id)})
                else:
                    await _finish_operation(connection, operation_id, {**result, "status": "SUCCEEDED"}, profile_id)
                await _audit(connection, principal, key, "DEVICE_PROFILE_ARCHIVED", "DEVICE_PROFILE", profile_id, {}, "ACCEPTED")
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("not_found", 404))

    @router.post("/api/v1/entity-groups")
    async def create_entity_group(request: Request, body: dict[str, object]):
        try:
            principal = await _guard(request, sessions, database, "entity-groups:write")
            tenant_id, session_customer = _tenant_scope(principal)
            name, entity_type = _name(body, 128), body.get("entityType")
            if entity_type not in {"DEVICE", "ASSET"}:
                raise WriteError("invalid_entity_type")
            raw_customer = body.get("customerId")
            customer_id = UUID(raw_customer) if isinstance(raw_customer, str) else session_customer
            if session_customer is not None and customer_id != session_customer:
                raise WriteError("scope_mismatch", 404)
            key = _idempotency(request)
            async with _scoped_connection(await database(), principal) as connection:
                operation_id, replay = await _begin_operation(connection, principal, key, "entity-group-create", "ENTITY_GROUP", _body_hash(body))
                if replay is not None:
                    return replay
                if customer_id is not None and await connection.fetchval("SELECT 1 FROM smart_alarm.customers WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE'", tenant_id, customer_id) != 1:
                    raise WriteError("customer_not_found", 404)
                row = await connection.fetchrow("INSERT INTO smart_alarm.entity_groups (tenant_id, customer_id, name, entity_type) VALUES ($1, $2, $3, $4) RETURNING id, name, entity_type, customer_id", tenant_id, customer_id, name, entity_type)
                result = {"operationId": str(operation_id), "kind": "entity-group-create", "status": "SUCCEEDED", "group": {"id": str(row["id"]), "name": row["name"], "entityType": row["entity_type"], "customerId": str(row["customer_id"]) if row["customer_id"] else None, "memberIds": [], "memberCount": 0}}
                await _finish_operation(connection, operation_id, result, str(row["id"]))
                await _audit(connection, principal, key, "ENTITY_GROUP_CREATED", "ENTITY_GROUP", str(row["id"]), {"name": name})
            return result
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))

    async def group_write(request: Request, group_id: str, operation: str, body: dict[str, object]) -> dict[str, object]:
        principal = await _guard(request, sessions, database, "entity-groups:write")
        tenant_id, customer_scope = _tenant_scope(principal)
        group_uuid, key = UUID(group_id), _idempotency(request)
        async with _scoped_connection(await database(), principal) as connection:
            row = await connection.fetchrow("SELECT id, name, entity_type, customer_id, status, archived_at FROM smart_alarm.entity_groups WHERE tenant_id = $1 AND id = $2 AND ($3::uuid IS NULL OR customer_id = $3)", tenant_id, group_uuid, customer_scope)
            if row is None:
                raise WriteError("not_found", 404)
            operation_id, replay = await _begin_operation(connection, principal, key, f"entity-group-{operation}", "ENTITY_GROUP", _body_hash({"groupId": group_id, **body}))
            if replay is not None:
                return replay
            if operation == "update":
                name = _name(body, 128)
                row = await connection.fetchrow("UPDATE smart_alarm.entity_groups SET name = $3, version = version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE' RETURNING id, name, entity_type, customer_id, status, archived_at", tenant_id, group_uuid, name)
            elif operation == "archive":
                row = await connection.fetchrow("UPDATE smart_alarm.entity_groups SET status = 'ARCHIVED', archived_at = clock_timestamp(), version = version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE' RETURNING id, name, entity_type, customer_id, status, archived_at", tenant_id, group_uuid)
            elif operation == "restore":
                row = await connection.fetchrow("UPDATE smart_alarm.entity_groups SET status = 'ACTIVE', archived_at = NULL, version = version + 1, updated_at = clock_timestamp() WHERE tenant_id = $1 AND id = $2 AND status = 'ARCHIVED' RETURNING id, name, entity_type, customer_id, status, archived_at", tenant_id, group_uuid)
            else:
                raw_ids = body.get("entityIds")
                if not isinstance(raw_ids, list) or len(raw_ids) > 100 or any(not isinstance(item, str) for item in raw_ids) or len(set(raw_ids)) != len(raw_ids):
                    raise WriteError("invalid_group_members")
                entity_ids = [UUID(item) for item in raw_ids]
                table = "devices" if row["entity_type"] == "DEVICE" else "assets"
                id_column = "device_uid" if table == "devices" else "id"
                valid = await connection.fetch(f"SELECT {id_column} AS id FROM smart_alarm.{table} WHERE tenant_id = $1 AND {id_column} = ANY($2::uuid[]) AND " + ("lifecycle_state <> 'RETIRED'" if table == "devices" else "status = 'ACTIVE'"), tenant_id, entity_ids)
                if len(valid) != len(entity_ids):
                    raise WriteError("group_member_not_found", 404)
                await connection.execute("DELETE FROM smart_alarm.entity_group_members WHERE tenant_id = $1 AND group_id = $2", tenant_id, group_uuid)
                for entity_id in entity_ids:
                    await connection.execute("INSERT INTO smart_alarm.entity_group_members (tenant_id, group_id, entity_type, entity_id, added_by) VALUES ($1, $2, $3, $4, $5)", tenant_id, group_uuid, row["entity_type"], entity_id, principal.local_user_id)
            if row is None:
                raise WriteError("invalid_group_state", 409)
            members = await connection.fetch("SELECT entity_id FROM smart_alarm.entity_group_members WHERE tenant_id = $1 AND group_id = $2 ORDER BY entity_id", tenant_id, group_uuid)
            group = {"id": str(row["id"]), "name": row["name"], "entityType": row["entity_type"], "customerId": str(row["customer_id"]) if row["customer_id"] else None, "memberIds": [str(member["entity_id"]) for member in members], "memberCount": len(members), **({"archivedAt": int(row["archived_at"].timestamp() * 1000)} if row["archived_at"] else {})}
            result = {"operationId": str(operation_id), "kind": f"entity-group-{operation}", "status": "SUCCEEDED", "group": group}
            await _finish_operation(connection, operation_id, result, group_id)
            await _audit(connection, principal, key, f"ENTITY_GROUP_{operation.upper()}", "ENTITY_GROUP", group_id, {})
        return result

    @router.patch("/api/v1/entity-groups/{group_id}")
    async def update_entity_group(group_id: str, request: Request, body: dict[str, object]):
        try:
            return await group_write(request, group_id, "update", body)
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))

    @router.post("/api/v1/entity-groups/{group_id}/archive")
    async def archive_entity_group(group_id: str, request: Request):
        try:
            return await group_write(request, group_id, "archive", {})
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("not_found", 404))

    @router.post("/api/v1/entity-groups/{group_id}/restore")
    async def restore_entity_group(group_id: str, request: Request):
        try:
            return await group_write(request, group_id, "restore", {})
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("not_found", 404))

    @router.post("/api/v1/entity-groups/{group_id}/members")
    async def replace_entity_group_members(group_id: str, request: Request, body: dict[str, object]):
        try:
            return await group_write(request, group_id, "members", body)
        except (WriteError, ValueError) as exc:
            return _write_error(exc if isinstance(exc, WriteError) else WriteError("invalid_request"))


def mount_write_routes(
    app: Any,
    sessions: SessionService,
    database: Callable[[], Awaitable[Any]],
    thingsboard: ThingsBoardClient | None = None,
) -> None:
    router = APIRouter()
    register_write_routes(router, sessions, database, thingsboard)
    app.include_router(router)
