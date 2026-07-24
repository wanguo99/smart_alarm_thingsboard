"""Scoped ThingsBoard WebSocket proxy for browser BFF sessions."""

from __future__ import annotations

import asyncio
import json
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from .policy import PolicyError, ProductPrincipal
from .session import SessionError, SessionService


MAX_MESSAGE_BYTES = 1024 * 1024
ALARM_FIELDS = frozenset({
    "createdTime", "startTime", "endTime", "ackTime", "clearTime",
    "originator", "type", "severity", "status", "details",
})
TELEMETRY_KEYS = frozenset({
    "latitude", "longitude", "gpsValid", "fusedValid", "gpsSatellites",
    "gpsFixQuality", "gpsHdop", "gpsAltitude", "groundSpeed",
    "positionQuality", "deviceState", "collisionCount",
    "lastCollisionUptimeMs", "health", "faultBits", "batteryLevel",
    "batteryPercent", "current_fw_title", "current_fw_version",
    "target_fw_title", "target_fw_version", "fw_state", "fw_error",
})


class WebSocketPolicyError(ValueError):
    pass


def thingsboard_websocket_url(base_url: str) -> str:
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("ThingsBoard URL must be an absolute HTTP(S) URL")
    scheme = "wss" if parsed.scheme == "https" else "ws"
    path = f"{parsed.path.rstrip('/')}/api/ws"
    return urlunsplit((scheme, parsed.netloc, path, "", ""))


def _alarm_command(command: dict[str, Any], allowed_device_ids: frozenset[str]) -> dict[str, Any] | None:
    query = command.get("query")
    if not isinstance(query, dict):
        raise WebSocketPolicyError("invalid alarm query")
    entity_filter = query.get("entityFilter")
    page_link = query.get("pageLink")
    alarm_fields = query.get("alarmFields")
    entity_fields = query.get("entityFields")
    latest_values = query.get("latestValues")
    key_filters = query.get("keyFilters")
    if (
        not isinstance(entity_filter, dict)
        or entity_filter.get("type") != "entityType"
        or entity_filter.get("entityType") != "DEVICE"
        or not isinstance(page_link, dict)
        or page_link.get("page") != 0
        or not isinstance(page_link.get("pageSize"), int)
        or not 1 <= page_link["pageSize"] <= 100
        or not isinstance(page_link.get("timeWindow"), int)
        or page_link["timeWindow"] <= 0
        or page_link.get("statusList") != ["ACTIVE"]
        or not isinstance(alarm_fields, list)
        or entity_fields != []
        or latest_values != []
        or key_filters != []
    ):
        raise WebSocketPolicyError("unsupported alarm query")
    fields = {
        item.get("key")
        for item in alarm_fields
        if isinstance(item, dict) and item.get("type") == "ALARM_FIELD" and isinstance(item.get("key"), str)
    }
    if len(fields) != len(alarm_fields) or fields != ALARM_FIELDS:
        raise WebSocketPolicyError("unsupported alarm fields")
    if not allowed_device_ids:
        return None
    return {
        "cmdId": command["cmdId"],
        "type": "ALARM_DATA",
        "query": {
            **query,
            "entityFilter": {
                "type": "entityList",
                "entityType": "DEVICE",
                "entityList": sorted(allowed_device_ids),
            },
        },
    }


def _telemetry_command(command: dict[str, Any], allowed_device_ids: frozenset[str]) -> dict[str, Any]:
    entity_id = command.get("entityId")
    raw_keys = command.get("keys")
    if (
        command.get("entityType") != "DEVICE"
        or not isinstance(entity_id, str)
        or entity_id not in allowed_device_ids
        or not isinstance(raw_keys, str)
        or command.get("unsubscribe") is not False
    ):
        raise WebSocketPolicyError("device subscription is outside the session scope")
    keys = raw_keys.split(",")
    if not keys or len(set(keys)) != len(keys) or not set(keys).issubset(TELEMETRY_KEYS):
        raise WebSocketPolicyError("unsupported telemetry keys")
    return {
        "cmdId": command["cmdId"],
        "type": "TIMESERIES",
        "entityType": "DEVICE",
        "entityId": entity_id,
        "keys": ",".join(keys),
        "unsubscribe": False,
    }


def prepare_subscription(
    payload: object,
    *,
    platform_token: str,
    principal: ProductPrincipal,
    allowed_device_ids: frozenset[str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if not isinstance(payload, dict) or set(payload) != {"authCmd", "cmds"}:
        raise WebSocketPolicyError("invalid subscription envelope")
    auth = payload.get("authCmd")
    commands = payload.get("cmds")
    if (
        not isinstance(auth, dict)
        or set(auth) != {"cmdId", "type"}
        or auth.get("cmdId") != 0
        or auth.get("type") != "AUTH"
        or not isinstance(commands, list)
        or len(commands) > 501
    ):
        raise WebSocketPolicyError("invalid authentication command")
    command_ids: set[int] = set()
    upstream_commands: list[dict[str, Any]] = []
    local_messages: list[dict[str, Any]] = []
    for command in commands:
        if not isinstance(command, dict):
            raise WebSocketPolicyError("subscription command must be an object")
        command_id = command.get("cmdId")
        if not isinstance(command_id, int) or command_id <= 0 or command_id in command_ids:
            raise WebSocketPolicyError("subscription command id is invalid")
        command_ids.add(command_id)
        if command.get("type") == "ALARM_DATA":
            try:
                principal.require("alarms:read")
            except PolicyError as exc:
                raise WebSocketPolicyError("alarm capability is required") from exc
            prepared = _alarm_command(command, allowed_device_ids)
            if prepared is None:
                local_messages.append({
                    "cmdId": command_id,
                    "cmdUpdateType": "ALARM_DATA",
                    "data": {"data": []},
                })
            else:
                upstream_commands.append(prepared)
        elif command.get("type") == "TIMESERIES":
            try:
                principal.require("devices:read")
            except PolicyError as exc:
                raise WebSocketPolicyError("device capability is required") from exc
            upstream_commands.append(_telemetry_command(command, allowed_device_ids))
        else:
            raise WebSocketPolicyError("unsupported subscription type")
    return {
        "authCmd": {"cmdId": 0, "type": "AUTH", "token": platform_token},
        "cmds": upstream_commands,
    }, local_messages


async def _allowed_device_ids(pool: Any, principal: ProductPrincipal) -> frozenset[str]:
    if principal.internal_tenant_id is None:
        return frozenset()
    async with pool.acquire() as connection:
        async with connection.transaction():
            await connection.execute(
                "SELECT set_config('smart_alarm.tenant_id', $1, true)",
                str(principal.internal_tenant_id),
            )
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
    return frozenset(str(row["thingsboard_device_id"]) for row in rows)


async def _relay_client(websocket: WebSocket) -> None:
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            return
        if message.get("text") is not None or message.get("bytes") is not None:
            raise WebSocketPolicyError("subscription mutation is not supported")


async def _relay_upstream(websocket: WebSocket, upstream: Any) -> None:
    async for raw in upstream:
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise WebSocketPolicyError("invalid upstream WebSocket message")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise WebSocketPolicyError("invalid upstream WebSocket message") from exc
        if not isinstance(payload, dict):
            raise WebSocketPolicyError("invalid upstream WebSocket message")
        await websocket.send_text(raw)


def mount_websocket_proxy(
    app: FastAPI,
    sessions: SessionService,
    database: Callable[[], Awaitable[Any]],
    *,
    thingsboard_url: str,
    allowed_origins: tuple[str, ...],
) -> None:
    upstream_url = thingsboard_websocket_url(thingsboard_url)
    origin_allowlist = frozenset(allowed_origins)

    @app.websocket("/api/v1/ws")
    async def websocket_proxy(websocket: WebSocket) -> None:
        if websocket.headers.get("origin") not in origin_allowlist:
            await websocket.close(code=4403, reason="origin not allowed")
            return
        try:
            pool = await database()
            context = await sessions.resolve(pool, websocket.cookies.get(sessions.cookie_name))
            allowed_device_ids = await _allowed_device_ids(pool, context.principal)
        except SessionError:
            await websocket.close(code=4401, reason="authentication failed")
            return
        await websocket.accept()
        try:
            raw = await asyncio.wait_for(websocket.receive_text(), timeout=10)
            if len(raw.encode("utf-8")) > MAX_MESSAGE_BYTES:
                raise WebSocketPolicyError("subscription message is too large")
            prepared, local_messages = prepare_subscription(
                json.loads(raw),
                platform_token=context.platform_token,
                principal=context.principal,
                allowed_device_ids=allowed_device_ids,
            )
            async with connect(
                upstream_url,
                compression=None,
                open_timeout=5,
                close_timeout=2,
                max_size=MAX_MESSAGE_BYTES,
                ping_interval=20,
                ping_timeout=20,
            ) as upstream:
                await upstream.send(json.dumps(prepared, separators=(",", ":")))
                for message in local_messages:
                    await websocket.send_json(message)
                client_task = asyncio.create_task(_relay_client(websocket))
                upstream_task = asyncio.create_task(_relay_upstream(websocket, upstream))
                done, pending = await asyncio.wait(
                    {client_task, upstream_task}, return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                for task in done:
                    task.result()
        except (asyncio.TimeoutError, json.JSONDecodeError, WebSocketPolicyError):
            await websocket.close(code=4400, reason="invalid subscription")
        except (ConnectionClosed, WebSocketDisconnect):
            return
        except Exception:
            await websocket.close(code=1011, reason="upstream unavailable")
