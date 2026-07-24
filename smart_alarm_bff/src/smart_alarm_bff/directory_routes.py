"""Scoped read-only directory endpoints used by the role portals.

These routes intentionally expose product records, not ThingsBoard database
tables.  Every scope is obtained from the server-side cookie session.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, Callable, Awaitable
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .policy import PolicyError, ProductPrincipal
from .session import SessionContext, SessionError, SessionService


class DirectoryError(RuntimeError):
    def __init__(self, code: str, status_code: int = 403) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


def _page(rows: list[dict[str, object]]) -> dict[str, object]:
    return {
        "data": rows,
        "totalPages": 1 if rows else 0,
        "totalElements": len(rows),
        "hasNext": False,
    }


def _principal(request: Request) -> ProductPrincipal:
    context = getattr(request.state, "session_context", None)
    if not isinstance(context, SessionContext):
        raise DirectoryError("session_required", 401)
    return context.principal


def _require(principal: ProductPrincipal, capability: str) -> None:
    try:
        principal.require(capability)
    except PolicyError as exc:
        raise DirectoryError("capability_required", 403) from exc


async def _load_session(request: Request, sessions: SessionService, database: Callable[[], Awaitable[Any]]) -> None:
    try:
        request.state.session_context = await sessions.resolve(
            await database(), request.cookies.get(sessions.cookie_name),
        )
    except SessionError as exc:
        raise DirectoryError(exc.code, exc.status_code) from exc


def _error(exc: DirectoryError) -> JSONResponse:
    message = "authentication failed" if exc.status_code == 401 else "request is not authorized"
    return JSONResponse(status_code=exc.status_code, content={"error": {"code": exc.code, "message": message}})


def _tenant_args(principal: ProductPrincipal) -> tuple[UUID, UUID | None]:
    if principal.internal_tenant_id is None:
        raise DirectoryError("tenant_scope_required", 403)
    return principal.internal_tenant_id, principal.internal_customer_id


@asynccontextmanager
async def _scoped_connection(pool: Any, principal: ProductPrincipal):
    """Apply the tenant scope for exactly one transaction, then discard it."""
    async with pool.acquire() as connection:
        async with connection.transaction():
            tenant_value = str(principal.internal_tenant_id) if principal.internal_tenant_id else ""
            await connection.execute("SELECT set_config('smart_alarm.tenant_id', $1, true)", tenant_value)
            await connection.execute("SELECT set_config('smart_alarm.system_scope', $1, true)", "true" if principal.internal_tenant_id is None else "false")
            yield connection


def register_directory_routes(router: APIRouter, sessions: SessionService, database: Callable[[], Awaitable[Any]]) -> None:
    async def guard(request: Request) -> ProductPrincipal:
        try:
            await _load_session(request, sessions, database)
            return _principal(request)
        except DirectoryError:
            raise

    @router.get("/api/v1/customers")
    async def list_customers(request: Request):
        try:
            principal = await guard(request)
            _require(principal, "customers:read")
            tenant_id, _ = _tenant_args(principal)
            async with _scoped_connection(await database(), principal) as connection:
                rows = await connection.fetch(
                    """
                    SELECT id, name,
                           (SELECT count(*) FROM smart_alarm.devices d
                            WHERE d.tenant_id = c.tenant_id AND d.customer_id = c.id
                              AND d.lifecycle_state <> 'RETIRED') AS device_count,
                           (SELECT count(*) FROM smart_alarm.assets a
                            WHERE a.tenant_id = c.tenant_id AND a.customer_id = c.id
                              AND a.status = 'ACTIVE') AS asset_count
                    FROM smart_alarm.customers c
                    WHERE tenant_id = $1 AND status = 'ACTIVE'
                    ORDER BY lower(name), id
                    """,
                    tenant_id,
                )
            return _page([{"id": str(row["id"]), "name": row["name"], "deviceCount": int(row["device_count"]), "assetCount": int(row["asset_count"])} for row in rows])
        except DirectoryError as exc:
            return _error(exc)

    @router.get("/api/v1/customers/{customer_id}")
    async def get_customer(customer_id: str, request: Request):
        try:
            principal = await guard(request)
            _require(principal, "customers:read")
            tenant_id, _ = _tenant_args(principal)
            customer_uuid = UUID(customer_id)
            async with _scoped_connection(await database(), principal) as connection:
                row = await connection.fetchrow(
                    """
                    SELECT c.id, c.name,
                           (SELECT count(*) FROM smart_alarm.devices d WHERE d.tenant_id = c.tenant_id AND d.customer_id = c.id AND d.lifecycle_state <> 'RETIRED') AS device_count,
                           (SELECT count(*) FROM smart_alarm.assets a WHERE a.tenant_id = c.tenant_id AND a.customer_id = c.id AND a.status = 'ACTIVE') AS asset_count
                    FROM smart_alarm.customers c
                    WHERE c.tenant_id = $1 AND c.id = $2 AND c.status = 'ACTIVE'
                    """,
                    tenant_id, customer_uuid,
                )
            if row is None or (principal.internal_customer_id is not None and principal.internal_customer_id != customer_uuid):
                raise DirectoryError("not_found", 404)
            return {"id": str(row["id"]), "name": row["name"], "deviceCount": int(row["device_count"]), "assetCount": int(row["asset_count"])}
        except (DirectoryError, ValueError) as exc:
            return _error(exc if isinstance(exc, DirectoryError) else DirectoryError("not_found", 404))

    @router.get("/api/v1/customers/{customer_id}/members")
    async def list_customer_members(customer_id: str, request: Request):
        try:
            principal = await guard(request)
            _require(principal, "customers:members:read")
            tenant_id, _ = _tenant_args(principal)
            customer_uuid = UUID(customer_id)
            if principal.internal_customer_id is not None and principal.internal_customer_id != customer_uuid:
                raise DirectoryError("not_found", 404)
            async with _scoped_connection(await database(), principal) as connection:
                rows = await connection.fetch(
                    "SELECT id, username, email, status FROM smart_alarm.users WHERE tenant_id = $1 AND customer_id = $2 AND status <> 'ARCHIVED' ORDER BY username, id",
                    tenant_id, customer_uuid,
                )
            return {"customerId": customer_id, **_page([{"id": str(row["id"]), "username": row["username"], "email": row["email"], "status": row["status"]} for row in rows])}
        except (DirectoryError, ValueError) as exc:
            return _error(exc if isinstance(exc, DirectoryError) else DirectoryError("not_found", 404))

    @router.get("/api/v1/assets")
    async def list_assets(request: Request):
        try:
            principal = await guard(request)
            _require(principal, "assets:read")
            tenant_id, customer_id = _tenant_args(principal)
            async with _scoped_connection(await database(), principal) as connection:
                rows = await connection.fetch(
                    """
                    SELECT a.id, a.name, a.asset_type, a.customer_id, a.platform_sync_status, a.platform_error_code,
                           (SELECT count(*) FROM smart_alarm.entity_relations r WHERE r.tenant_id = a.tenant_id AND r.from_type = 'ASSET' AND r.from_id = a.id AND r.to_type = 'DEVICE' AND r.status = 'ACTIVE') AS device_count
                    FROM smart_alarm.assets a
                    WHERE a.tenant_id = $1 AND a.status = 'ACTIVE'
                      AND ($2::uuid IS NULL OR a.customer_id = $2)
                    ORDER BY lower(a.name), a.id
                    """,
                    tenant_id, customer_id,
                )
            return _page([{"id": str(row["id"]), "name": row["name"], "type": row["asset_type"], "customerId": str(row["customer_id"]) if row["customer_id"] else None, "deviceCount": int(row["device_count"]), "platformSyncStatus": row["platform_sync_status"], "platformErrorCode": row["platform_error_code"]} for row in rows])
        except DirectoryError as exc:
            return _error(exc)

    @router.get("/api/v1/assets/{asset_id}")
    async def get_asset(asset_id: str, request: Request):
        try:
            principal = await guard(request)
            _require(principal, "assets:read")
            tenant_id, customer_id = _tenant_args(principal)
            asset_uuid = UUID(asset_id)
            async with _scoped_connection(await database(), principal) as connection:
                row = await connection.fetchrow(
                    "SELECT a.id, a.name, a.asset_type, a.customer_id, a.platform_sync_status, a.platform_error_code, (SELECT count(*) FROM smart_alarm.entity_relations r WHERE r.tenant_id = a.tenant_id AND r.from_type = 'ASSET' AND r.from_id = a.id AND r.to_type = 'DEVICE' AND r.status = 'ACTIVE') AS device_count FROM smart_alarm.assets a WHERE a.tenant_id = $1 AND a.id = $2 AND a.status = 'ACTIVE' AND ($3::uuid IS NULL OR a.customer_id = $3)",
                    tenant_id, asset_uuid, customer_id,
                )
            if row is None:
                raise DirectoryError("not_found", 404)
            return {"id": str(row["id"]), "name": row["name"], "type": row["asset_type"], "customerId": str(row["customer_id"]) if row["customer_id"] else None, "deviceCount": int(row["device_count"]), "platformSyncStatus": row["platform_sync_status"], "platformErrorCode": row["platform_error_code"]}
        except (DirectoryError, ValueError) as exc:
            return _error(exc if isinstance(exc, DirectoryError) else DirectoryError("not_found", 404))

    @router.get("/api/v1/assets/{asset_id}/relations")
    async def asset_relations(asset_id: str, request: Request):
        try:
            principal = await guard(request)
            _require(principal, "assets:read")
            tenant_id, customer_id = _tenant_args(principal)
            asset_uuid = UUID(asset_id)
            async with _scoped_connection(await database(), principal) as connection:
                asset = await connection.fetchrow("SELECT id FROM smart_alarm.assets WHERE tenant_id = $1 AND id = $2 AND status = 'ACTIVE' AND ($3::uuid IS NULL OR customer_id = $3)", tenant_id, asset_uuid, customer_id)
                if asset is None:
                    raise DirectoryError("not_found", 404)
                children = await connection.fetch("SELECT id, name, asset_type, customer_id, platform_sync_status, platform_error_code, 0::bigint AS device_count FROM smart_alarm.assets WHERE tenant_id = $1 AND parent_asset_id = $2 AND status = 'ACTIVE' ORDER BY lower(name), id", tenant_id, asset_uuid)
                devices = await connection.fetch("SELECT d.device_uid, d.display_name FROM smart_alarm.entity_relations r JOIN smart_alarm.devices d ON d.tenant_id = r.tenant_id AND d.id = r.to_id WHERE r.tenant_id = $1 AND r.from_id = $2 AND r.from_type = 'ASSET' AND r.to_type = 'DEVICE' AND r.status = 'ACTIVE' AND d.lifecycle_state <> 'RETIRED'", tenant_id, asset_uuid)
            return {"assetId": asset_id, "children": _page([{"id": str(row["id"]), "name": row["name"], "type": row["asset_type"], "customerId": str(row["customer_id"]) if row["customer_id"] else None, "deviceCount": int(row["device_count"]), "platformSyncStatus": row["platform_sync_status"], "platformErrorCode": row["platform_error_code"]} for row in children])["data"], "devices": [{"deviceUid": str(row["device_uid"]), "name": row["display_name"]} for row in devices]}
        except (DirectoryError, ValueError) as exc:
            return _error(exc if isinstance(exc, DirectoryError) else DirectoryError("not_found", 404))

    @router.get("/api/v1/entity-groups")
    async def list_entity_groups(request: Request, includeArchived: bool = False):
        try:
            principal = await guard(request)
            _require(principal, "entity-groups:read")
            tenant_id, customer_id = _tenant_args(principal)
            status = "" if includeArchived else "AND g.status = 'ACTIVE'"
            async with _scoped_connection(await database(), principal) as connection:
                groups = await connection.fetch(f"SELECT g.id, g.name, g.entity_type, g.customer_id, g.status, g.archived_at, count(m.entity_id) AS member_count FROM smart_alarm.entity_groups g LEFT JOIN smart_alarm.entity_group_members m ON m.tenant_id = g.tenant_id AND m.group_id = g.id WHERE g.tenant_id = $1 {status} AND ($2::uuid IS NULL OR g.customer_id = $2) GROUP BY g.id ORDER BY lower(g.name), g.id", tenant_id, customer_id)
                members = await connection.fetch("SELECT group_id, entity_id FROM smart_alarm.entity_group_members WHERE tenant_id = $1", tenant_id)
            by_group: dict[UUID, list[str]] = {}
            for member in members:
                by_group.setdefault(member["group_id"], []).append(str(member["entity_id"]))
            return {"source": "local", **_page([{"id": str(row["id"]), "name": row["name"], "entityType": row["entity_type"], "customerId": str(row["customer_id"]) if row["customer_id"] else None, "memberIds": by_group.get(row["id"], []), "memberCount": int(row["member_count"]), **({"archivedAt": int(row["archived_at"].timestamp() * 1000)} if row["archived_at"] else {})} for row in groups])}
        except DirectoryError as exc:
            return _error(exc)

    @router.get("/api/v1/device-profiles")
    async def list_device_profiles(request: Request):
        try:
            principal = await guard(request)
            _require(principal, "device-profiles:read")
            tenant_id, _ = _tenant_args(principal)
            async with _scoped_connection(await database(), principal) as connection:
                rows = await connection.fetch("SELECT id, name, profile_type AS type, transport_type, is_default, platform_sync_status, platform_error_code FROM smart_alarm.device_profiles WHERE tenant_id = $1 AND status = 'ACTIVE' ORDER BY is_default DESC, lower(name), id", tenant_id)
            data = [{"id": str(row["id"]), "name": row["name"], "type": row["type"], "transportType": row["transport_type"], "isDefault": row["is_default"], "platformSyncStatus": row["platform_sync_status"], "platformErrorCode": row["platform_error_code"]} for row in rows]
            return {"source": "local", **_page(data)}
        except DirectoryError as exc:
            return _error(exc)

    @router.get("/api/v1/device-management/devices")
    async def list_managed_devices(request: Request):
        try:
            principal = await guard(request)
            _require(principal, "devices:read")
            tenant_id, customer_id = _tenant_args(principal)
            async with _scoped_connection(await database(), principal) as connection:
                rows = await connection.fetch(
                    """
                    SELECT d.id, d.device_uid, i.serial_number, d.thingsboard_device_id,
                           d.customer_id, d.asset_id, d.business_group_id, d.device_profile_id,
                           d.technical_name, d.display_name, d.lifecycle_state, d.credential_version,
                           d.retired_at, p.name AS profile_name, c.name AS customer_name
                    FROM smart_alarm.devices d
                    JOIN smart_alarm.device_inventory i ON i.device_uid = d.device_uid
                    JOIN smart_alarm.device_profiles p ON p.tenant_id = d.tenant_id AND p.id = d.device_profile_id
                    LEFT JOIN smart_alarm.customers c ON c.tenant_id = d.tenant_id AND c.id = d.customer_id
                    WHERE d.tenant_id = $1 AND ($2::uuid IS NULL OR d.customer_id = $2)
                    ORDER BY lower(d.display_name), d.id
                    """,
                    tenant_id, customer_id,
                )
            data = [{"id": str(row["id"]), "deviceUid": str(row["device_uid"]), "serialNumber": row["serial_number"], "thingsboardDeviceId": str(row["thingsboard_device_id"]), "customerId": str(row["customer_id"]) if row["customer_id"] else None, "assetId": str(row["asset_id"]) if row["asset_id"] else None, "groupId": str(row["business_group_id"]) if row["business_group_id"] else None, "deviceProfileId": str(row["device_profile_id"]), "deviceProfileName": row["profile_name"], "technicalName": row["technical_name"], "name": row["display_name"], "label": row["display_name"], "type": "smart-alarm", "active": False, "lifecycleState": row["lifecycle_state"], "credentialVersion": int(row["credential_version"]), "customerTitle": row["customer_name"], **({"retiredAt": int(row["retired_at"].timestamp() * 1000)} if row["retired_at"] else {})} for row in rows]
            return _page(data)
        except DirectoryError as exc:
            return _error(exc)

    @router.get("/api/v1/device-management/assignment-options")
    async def assignment_options(request: Request):
        try:
            principal = await guard(request)
            _require(principal, "devices:read")
            tenant_id, customer_id = _tenant_args(principal)
            async with _scoped_connection(await database(), principal) as connection:
                customers = await connection.fetch("SELECT id, name FROM smart_alarm.customers WHERE tenant_id = $1 AND status = 'ACTIVE' ORDER BY lower(name), id", tenant_id)
                assets = await connection.fetch("SELECT id, name, asset_type, customer_id FROM smart_alarm.assets WHERE tenant_id = $1 AND status = 'ACTIVE' AND ($2::uuid IS NULL OR customer_id = $2) ORDER BY lower(name), id", tenant_id, customer_id)
                groups = await connection.fetch("SELECT id, name FROM smart_alarm.business_groups WHERE tenant_id = $1 AND status = 'ACTIVE' AND ($2::uuid IS NULL OR customer_id = $2) ORDER BY lower(name), id", tenant_id, customer_id)
                archived = await connection.fetch("SELECT id, name FROM smart_alarm.business_groups WHERE tenant_id = $1 AND status = 'ARCHIVED' AND ($2::uuid IS NULL OR customer_id = $2) ORDER BY lower(name), id", tenant_id, customer_id)
            return {"customers": [{"id": str(row["id"]), "name": row["name"]} for row in customers if customer_id is None], "assets": [{"id": str(row["id"]), "name": row["name"], "type": row["asset_type"], "customerId": str(row["customer_id"]) if row["customer_id"] else None} for row in assets], "groups": [{"id": str(row["id"]), "name": row["name"]} for row in groups], "archivedGroups": [{"id": str(row["id"]), "name": row["name"]} for row in archived]}
        except DirectoryError as exc:
            return _error(exc)

    @router.get("/api/v1/system/tenants")
    async def system_tenants(request: Request):
        try:
            principal = await guard(request)
            _require(principal, "system:tenants:read")
            async with _scoped_connection(await database(), principal) as connection:
                rows = await connection.fetch("SELECT id, name FROM smart_alarm.tenants WHERE status = 'ACTIVE' ORDER BY lower(name), id")
            return _page([{"id": str(row["id"]), "name": row["name"]} for row in rows])
        except DirectoryError as exc:
            return _error(exc)

    @router.get("/api/v1/system/users")
    async def system_users(request: Request):
        try:
            principal = await guard(request)
            _require(principal, "system:users:read")
            async with _scoped_connection(await database(), principal) as connection:
                rows = await connection.fetch("SELECT id, username, email, authority, tenant_id, customer_id, status FROM smart_alarm.users WHERE authority = 'TENANT_ADMIN' AND status <> 'ARCHIVED' ORDER BY username, id")
            return _page([{"id": str(row["id"]), "username": row["username"], "email": row["email"], "authority": row["authority"], "tenantId": str(row["tenant_id"]) if row["tenant_id"] else None, "customerId": str(row["customer_id"]) if row["customer_id"] else None, "status": row["status"]} for row in rows])
        except DirectoryError as exc:
            return _error(exc)

    @router.get("/api/v1/system/role-assignments")
    async def system_roles(request: Request):
        try:
            principal = await guard(request)
            _require(principal, "system:roles:read")
            async with _scoped_connection(await database(), principal) as connection:
                rows = await connection.fetch("SELECT ra.user_id, u.authority, pr.role_key FROM smart_alarm.role_assignments ra JOIN smart_alarm.users u ON u.id = ra.user_id JOIN smart_alarm.product_roles pr ON pr.id = ra.role_id WHERE ra.status = 'ACTIVE' AND pr.status = 'ACTIVE' ORDER BY ra.user_id")
            return _page([{"userId": str(row["user_id"]), "authority": row["authority"], "productRole": row["role_key"]} for row in rows])
        except DirectoryError as exc:
            return _error(exc)

    @router.get("/api/v1/system/tenants/{tenant_id}/users")
    async def system_tenant_users(tenant_id: str, request: Request):
        try:
            principal = await guard(request)
            _require(principal, "system:users:read")
            tenant_uuid = UUID(tenant_id)
            async with _scoped_connection(await database(), principal) as connection:
                rows = await connection.fetch("SELECT id, username, email FROM smart_alarm.users WHERE tenant_id = $1 AND authority = 'TENANT_ADMIN' AND status <> 'ARCHIVED' ORDER BY username, id", tenant_uuid)
            return {"tenantId": tenant_id, **_page([{"id": str(row["id"]), "username": row["username"], "email": row["email"]} for row in rows])}
        except (DirectoryError, ValueError) as exc:
            return _error(exc if isinstance(exc, DirectoryError) else DirectoryError("not_found", 404))


def mount_directory_routes(app: Any, sessions: SessionService, database: Callable[[], Awaitable[Any]]) -> None:
    router = APIRouter()
    register_directory_routes(router, sessions, database)
    app.include_router(router)
