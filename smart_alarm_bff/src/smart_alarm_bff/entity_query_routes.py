"""Tenant-scoped latest telemetry reads through the browser BFF session."""

from __future__ import annotations

from typing import Any, Awaitable, Callable
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .directory_routes import _scoped_connection
from .policy import PolicyError, ProductPrincipal
from .session import SessionContext, SessionError, SessionService
from .thingsboard import ThingsBoardClient, ThingsBoardError


TIME_SERIES_KEYS = frozenset({
    "latitude", "longitude", "gpsValid", "fusedValid", "gpsSatellites",
    "gpsFixQuality", "gpsHdop", "gpsAltitude", "groundSpeed", "positionQuality",
    "deviceState", "collisionCount", "lastCollisionUptimeMs", "health", "faultBits",
    "batteryLevel", "batteryPercent", "current_fw_title", "current_fw_version",
    "target_fw_title", "target_fw_version", "fw_state", "fw_error",
})
ATTRIBUTE_KEYS = frozenset({"appVersion", "lastActivityTime", "active"})
ALLOWED_KEYS = {"TIME_SERIES": TIME_SERIES_KEYS, "ATTRIBUTE": ATTRIBUTE_KEYS}


class EntityQueryError(RuntimeError):
    def __init__(self, code: str, status_code: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


def _error(exc: EntityQueryError) -> JSONResponse:
    message = "authentication failed" if exc.status_code == 401 else "entity query failed"
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": message}},
    )


def parse_entity_query(body: object) -> tuple[tuple[UUID, ...], tuple[tuple[str, str], ...]]:
    if not isinstance(body, dict) or set(body) != {"deviceIds", "latestValues"}:
        raise EntityQueryError("invalid_entity_query")
    raw_ids = body.get("deviceIds")
    if not isinstance(raw_ids, list) or not 1 <= len(raw_ids) <= 100:
        raise EntityQueryError("invalid_device_ids")
    device_ids: list[UUID] = []
    for value in raw_ids:
        try:
            device_id = UUID(value) if isinstance(value, str) else None
        except ValueError:
            device_id = None
        if device_id is None or device_id in device_ids:
            raise EntityQueryError("invalid_device_ids")
        device_ids.append(device_id)

    raw_latest = body.get("latestValues")
    if not isinstance(raw_latest, list) or len(raw_latest) > 100:
        raise EntityQueryError("invalid_latest_values")
    latest_values: list[tuple[str, str]] = []
    for item in raw_latest:
        if not isinstance(item, dict) or set(item) != {"type", "key"}:
            raise EntityQueryError("invalid_latest_values")
        value_type = item.get("type")
        key = item.get("key")
        if (
            not isinstance(value_type, str)
            or value_type not in ALLOWED_KEYS
            or not isinstance(key, str)
            or key not in ALLOWED_KEYS[value_type]
            or (value_type, key) in latest_values
        ):
            raise EntityQueryError("unsupported_latest_value")
        latest_values.append((value_type, key))
    return tuple(device_ids), tuple(latest_values)


async def _require_visible_devices(
    pool: Any,
    principal: ProductPrincipal,
    device_ids: tuple[UUID, ...],
) -> None:
    if principal.internal_tenant_id is None:
        raise EntityQueryError("tenant_scope_required", 403)
    async with _scoped_connection(pool, principal) as connection:
        rows = await connection.fetch(
            """
            SELECT thingsboard_device_id
            FROM smart_alarm.devices
            WHERE tenant_id = $1
              AND ($2::uuid IS NULL OR customer_id = $2)
              AND thingsboard_device_id = ANY($3::uuid[])
            """,
            principal.internal_tenant_id,
            principal.internal_customer_id,
            list(device_ids),
        )
    visible = {row["thingsboard_device_id"] for row in rows}
    if visible != set(device_ids):
        raise EntityQueryError("entity_query_scope_mismatch", 403)


def _platform_error(exc: ThingsBoardError) -> EntityQueryError:
    if exc.code in {"platform_user_operation_forbidden", "invalid_platform_session"}:
        return EntityQueryError(exc.code, 403)
    return EntityQueryError(exc.code, 503 if exc.retryable else 502)


def register_entity_query_routes(
    router: APIRouter,
    sessions: SessionService,
    database: Callable[[], Awaitable[Any]],
    thingsboard: ThingsBoardClient,
) -> None:
    @router.post("/api/v1/entity-query")
    async def entity_query(request: Request, body: dict[str, object]):
        try:
            pool = await database()
            try:
                context = await sessions.resolve(
                    pool,
                    request.cookies.get(sessions.cookie_name),
                )
                await sessions.require_csrf(
                    pool,
                    request.cookies.get(sessions.cookie_name),
                    request.headers.get("X-CSRF-Token"),
                )
            except SessionError as exc:
                raise EntityQueryError(exc.code, exc.status_code) from exc
            try:
                context.principal.require("devices:read")
            except PolicyError as exc:
                raise EntityQueryError("capability_required", 403) from exc
            device_ids, latest_values = parse_entity_query(body)
            await _require_visible_devices(pool, context.principal, device_ids)
            try:
                return await thingsboard.query_device_latest(
                    context.platform_token,
                    device_ids,
                    latest_values,
                )
            except ThingsBoardError as exc:
                raise _platform_error(exc) from exc
        except EntityQueryError as exc:
            return _error(exc)


def mount_entity_query_routes(
    app: Any,
    sessions: SessionService,
    database: Callable[[], Awaitable[Any]],
    thingsboard: ThingsBoardClient,
) -> None:
    router = APIRouter()
    register_entity_query_routes(router, sessions, database, thingsboard)
    app.include_router(router)
