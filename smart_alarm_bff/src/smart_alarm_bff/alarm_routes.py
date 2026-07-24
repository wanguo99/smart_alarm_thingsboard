"""Tenant/Customer scoped ThingsBoard alarm reads and operator actions."""

from __future__ import annotations

from typing import Any, Awaitable, Callable
from uuid import UUID

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .directory_routes import _scoped_connection
from .policy import PolicyError, ProductPrincipal
from .session import SessionError, SessionService
from .thingsboard import ThingsBoardClient, ThingsBoardError


SEARCH_STATUSES = {"ANY", "ACTIVE", "CLEARED", "ACK", "UNACK"}
SORT_PROPERTIES = {"createdTime", "startTs", "endTs", "type", "ackTs", "clearTs", "severity", "status"}
SORT_ORDERS = {"ASC", "DESC"}


class AlarmRouteError(RuntimeError):
    def __init__(self, code: str, status_code: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


def _error(exc: AlarmRouteError) -> JSONResponse:
    message = "authentication failed" if exc.status_code == 401 else "alarm operation failed"
    return JSONResponse(status_code=exc.status_code, content={"error": {"code": exc.code, "message": message}})


def _platform_error(exc: ThingsBoardError) -> AlarmRouteError:
    if exc.code in {"platform_user_operation_forbidden", "invalid_platform_session"}:
        return AlarmRouteError(exc.code, 403)
    return AlarmRouteError(exc.code, 503 if exc.retryable else 502)


def _parse_page(value: str | None, default: int, maximum: int) -> int:
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise AlarmRouteError("invalid_alarm_pagination") from exc
    if not 0 <= parsed <= maximum:
        raise AlarmRouteError("invalid_alarm_pagination")
    return parsed


async def _visible_device_ids(pool: Any, principal: ProductPrincipal) -> frozenset[UUID]:
    if principal.internal_tenant_id is None:
        raise AlarmRouteError("tenant_scope_required", 403)
    async with _scoped_connection(pool, principal) as connection:
        rows = await connection.fetch(
            """
            SELECT thingsboard_device_id
            FROM smart_alarm.devices
            WHERE tenant_id = $1
              AND lifecycle_state <> 'RETIRED'
              AND ($2::uuid IS NULL OR customer_id = $2)
              AND thingsboard_device_id IS NOT NULL
            """,
            principal.internal_tenant_id,
            principal.internal_customer_id,
        )
    return frozenset(row["thingsboard_device_id"] for row in rows)


def _check_alarm_scope(alarm: dict[str, object], visible: frozenset[UUID]) -> dict[str, object]:
    originator = alarm.get("originator")
    if not isinstance(originator, dict):
        raise AlarmRouteError("invalid_platform_alarm_response", 502)
    try:
        device_id = UUID(originator["id"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AlarmRouteError("invalid_platform_alarm_response", 502) from exc
    if device_id not in visible:
        raise AlarmRouteError("alarm_scope_mismatch", 502)
    return alarm


def register_alarm_routes(
    router: APIRouter,
    sessions: SessionService,
    database: Callable[[], Awaitable[Any]],
    thingsboard: ThingsBoardClient,
) -> None:
    async def context(request: Request):
        try:
            return await sessions.resolve(await database(), request.cookies.get(sessions.cookie_name))
        except SessionError as exc:
            raise AlarmRouteError(exc.code, exc.status_code) from exc

    async def csrf(request: Request) -> None:
        try:
            await sessions.require_csrf(
                await database(), request.cookies.get(sessions.cookie_name), request.headers.get("X-CSRF-Token"),
            )
        except SessionError as exc:
            raise AlarmRouteError(exc.code, exc.status_code) from exc

    @router.get("/api/v1/alarms")
    async def list_alarms(request: Request):
        try:
            session = await context(request)
            try:
                session.principal.require("alarms:read")
            except PolicyError as exc:
                raise AlarmRouteError("capability_required", 403) from exc
            page = _parse_page(request.query_params.get("page"), 0, 10000)
            page_size = _parse_page(request.query_params.get("pageSize"), 50, 100)
            if page_size == 0:
                raise AlarmRouteError("invalid_alarm_pagination")
            search_status = request.query_params.get("searchStatus", "ANY")
            sort_property = request.query_params.get("sortProperty", "createdTime")
            sort_order = request.query_params.get("sortOrder", "DESC")
            if search_status not in SEARCH_STATUSES or sort_property not in SORT_PROPERTIES or sort_order not in SORT_ORDERS:
                raise AlarmRouteError("invalid_alarm_query")
            visible = await _visible_device_ids(await database(), session.principal)
            if not visible:
                return {"data": [], "totalPages": 0, "totalElements": 0, "hasNext": False}
            try:
                result = await thingsboard.list_alarms(
                    session.platform_token, page=page, page_size=page_size,
                    search_status=search_status, sort_property=sort_property, sort_order=sort_order,
                )
            except ThingsBoardError as exc:
                raise _platform_error(exc) from exc
            result["data"] = [_check_alarm_scope(item, visible) for item in result["data"]]  # type: ignore[index]
            return result
        except AlarmRouteError as exc:
            return _error(exc)

    async def alarm_action(request: Request, alarm_id: str, action: str):
        try:
            session = await context(request)
            capability = "alarms:ack" if action == "ack" else "alarms:clear"
            try:
                session.principal.require(capability)
            except PolicyError as exc:
                raise AlarmRouteError("capability_required", 403) from exc
            await csrf(request)
            try:
                parsed_id = UUID(alarm_id)
            except ValueError as exc:
                raise AlarmRouteError("invalid_alarm_id") from exc
            visible = await _visible_device_ids(await database(), session.principal)
            try:
                result = await (thingsboard.acknowledge_alarm(session.platform_token, parsed_id) if action == "ack" else thingsboard.clear_alarm(session.platform_token, parsed_id))
            except ThingsBoardError as exc:
                raise _platform_error(exc) from exc
            return _check_alarm_scope(result, visible)
        except AlarmRouteError as exc:
            return _error(exc)

    @router.get("/api/v1/alarm/{alarm_id}")
    async def get_alarm(request: Request, alarm_id: str):
        try:
            session = await context(request)
            try:
                session.principal.require("alarms:read")
            except PolicyError as exc:
                raise AlarmRouteError("capability_required", 403) from exc
            try:
                parsed_id = UUID(alarm_id)
            except ValueError as exc:
                raise AlarmRouteError("invalid_alarm_id") from exc
            visible = await _visible_device_ids(await database(), session.principal)
            try:
                result = await thingsboard.get_alarm(session.platform_token, parsed_id)
            except ThingsBoardError as exc:
                raise _platform_error(exc) from exc
            return _check_alarm_scope(result, visible)
        except AlarmRouteError as exc:
            return _error(exc)

    @router.post("/api/v1/alarm/{alarm_id}/ack")
    async def acknowledge_alarm(request: Request, alarm_id: str):
        return await alarm_action(request, alarm_id, "ack")

    @router.post("/api/v1/alarm/{alarm_id}/clear")
    async def clear_alarm(request: Request, alarm_id: str):
        return await alarm_action(request, alarm_id, "clear")


def mount_alarm_routes(
    app: Any,
    sessions: SessionService,
    database: Callable[[], Awaitable[Any]],
    thingsboard: ThingsBoardClient,
) -> None:
    router = APIRouter()
    register_alarm_routes(router, sessions, database, thingsboard)
    app.include_router(router)
