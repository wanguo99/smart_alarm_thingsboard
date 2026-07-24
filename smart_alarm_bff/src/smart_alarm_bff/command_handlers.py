"""Durable ThingsBoard persistent-RPC outbox handlers."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime
import hashlib
import json
from typing import Any, AsyncIterator, Awaitable, Callable
from uuid import UUID

from .secret_provider import MountedSecretProvider, SecretReferenceError
from .thingsboard_admin import PlatformAdminError, ServiceIdentity, ThingsBoardAdminClient
from .worker import DeliveryError, OutboxEvent


COMMAND_SUBMIT_EVENT = "device.command.submit.requested"
COMMAND_RECONCILE_EVENT = "device.command.reconcile.requested"
COMMAND_CANCEL_EVENT = "device.command.cancel.requested"
COMMAND_POLICIES: dict[str, dict[str, object]] = {
    "ping": {"risk": "LOW", "retries": 1, "expirationSeconds": 300},
    "health": {"risk": "LOW", "retries": 1, "expirationSeconds": 300},
    "clearFaults": {"risk": "MEDIUM", "retries": 0, "expirationSeconds": 300},
    "reboot": {"risk": "HIGH", "retries": 0, "expirationSeconds": 300},
}
PENDING_PLATFORM_STATUSES = frozenset({"QUEUED", "SENT", "DELIVERED"})
CANCELLATION_WARNING = (
    "future platform delivery is stopped, but the device may already have received or executed the command"
)


class CommandHandlerError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def _uuid(value: object, code: str) -> UUID:
    try:
        return UUID(str(value))
    except (TypeError, ValueError, AttributeError) as exc:
        raise CommandHandlerError(code, retryable=False) from exc


class DeviceCommandHandlers:
    def __init__(
        self,
        database: Callable[[], Awaitable[Any]],
        worker_id: str,
        secrets_provider: MountedSecretProvider,
        thingsboard: ThingsBoardAdminClient,
        max_attempts: int = 8,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        self._database = database
        self._worker_id = worker_id
        self._secrets = secrets_provider
        self._thingsboard = thingsboard
        self._max_attempts = max_attempts

    def mapping(self) -> dict[str, Callable[[OutboxEvent], Awaitable[None]]]:
        return {
            COMMAND_SUBMIT_EVENT: self.submit,
            COMMAND_RECONCILE_EVENT: self.reconcile,
            COMMAND_CANCEL_EVENT: self.cancel,
        }

    @asynccontextmanager
    async def _system_transaction(self) -> AsyncIterator[Any]:
        pool = await self._database()
        async with pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SELECT set_config('smart_alarm.system_scope', 'true', true)")
                yield connection

    @asynccontextmanager
    async def _fenced_transaction(self, event: OutboxEvent) -> AsyncIterator[Any]:
        async with self._system_transaction() as connection:
            fenced = await connection.fetchval(
                """
                SELECT 1 FROM smart_alarm.outbox_events
                WHERE id = $1 AND status = 'LEASED' AND lease_owner = $2
                  AND lease_token = $3 AND lease_expires_at > clock_timestamp()
                FOR UPDATE
                """,
                event.event_id, self._worker_id, event.lease_token,
            )
            if fenced != 1:
                raise DeliveryError("worker_lease_lost", retryable=True)
            yield connection

    async def _load(self, event: OutboxEvent, expected_type: str) -> dict[str, Any]:
        if event.tenant_id is None or event.aggregate_type != "DEVICE" or event.event_type != expected_type:
            raise CommandHandlerError("invalid_command_event", retryable=False)
        operation_id = _uuid(event.payload.get("operationId"), "invalid_command_event")
        device_id = _uuid(event.aggregate_id, "invalid_command_event")
        async with self._system_transaction() as connection:
            row = await connection.fetchrow(
                """
                SELECT o.*, d.id AS device_id, d.device_uid, d.thingsboard_device_id,
                       d.lifecycle_state, d.customer_id AS device_customer_id,
                       t.thingsboard_tenant_id, t.service_identity_secret_ref,
                       u.thingsboard_user_id AS actor_platform_user_id
                FROM smart_alarm.outbox_events e
                JOIN smart_alarm.operations o ON o.id = $4 AND o.tenant_id = e.tenant_id
                JOIN smart_alarm.devices d ON d.tenant_id = o.tenant_id
                    AND d.id = $5 AND d.device_uid::text = o.resource_id
                JOIN smart_alarm.tenants t ON t.id = o.tenant_id AND t.status = 'ACTIVE'
                JOIN smart_alarm.users u ON u.id = o.actor_user_id
                WHERE e.id = $1 AND e.status = 'LEASED' AND e.lease_owner = $2
                  AND e.lease_token = $3 AND e.lease_expires_at > clock_timestamp()
                  AND e.tenant_id = $6 AND e.aggregate_type = 'DEVICE'
                  AND e.aggregate_id = $5::text AND e.event_type = $7
                """,
                event.event_id, self._worker_id, event.lease_token, operation_id,
                device_id, event.tenant_id, expected_type,
            )
        if row is None:
            raise DeliveryError("worker_lease_lost", retryable=True)
        return dict(row)

    async def _session(self, context: dict[str, Any]):
        if context["thingsboard_tenant_id"] is None or not context["service_identity_secret_ref"]:
            raise CommandHandlerError("tenant_service_identity_missing", retryable=False)
        identity = ServiceIdentity.from_json(self._secrets.read(context["service_identity_secret_ref"]))
        return await self._thingsboard.login(identity, context["thingsboard_tenant_id"])

    @staticmethod
    async def _schedule(
        connection: Any,
        context: dict[str, Any],
        event_type: str,
        delay_seconds: int,
    ) -> None:
        await connection.execute(
            """
            INSERT INTO smart_alarm.outbox_events (
                tenant_id, aggregate_type, aggregate_id, event_type, payload, next_attempt_at
            )
            SELECT $1, 'DEVICE', $2, $3, $4::jsonb,
                   clock_timestamp() + make_interval(secs => $5)
            WHERE NOT EXISTS (
                SELECT 1 FROM smart_alarm.outbox_events pending
                WHERE pending.tenant_id = $1 AND pending.aggregate_type = 'DEVICE'
                  AND pending.aggregate_id = $2 AND pending.event_type = $3
                  AND pending.payload->>'operationId' = $6
                  AND pending.status IN ('PENDING', 'LEASED')
            )
            """,
            context["tenant_id"], str(context["device_id"]), event_type,
            {"operationId": str(context["id"]), "deviceUid": str(context["device_uid"])},
            delay_seconds, str(context["id"]),
        )

    @staticmethod
    async def _audit(
        connection: Any,
        context: dict[str, Any],
        action: str,
        outcome: str,
        detail: dict[str, object],
    ) -> None:
        tenant_id = context["tenant_id"]
        await connection.execute("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", str(tenant_id))
        previous = await connection.fetchval(
            "SELECT event_hash FROM smart_alarm.audit_events WHERE tenant_id = $1 ORDER BY id DESC LIMIT 1",
            tenant_id,
        )
        canonical = json.dumps({
            "tenantId": str(tenant_id),
            "customerId": str(context["customer_id"]) if context["customer_id"] else None,
            "actorUserId": str(context["actor_user_id"]),
            "requestId": context["idempotency_key"],
            "action": action,
            "resourceType": "DEVICE",
            "resourceId": str(context["device_uid"]),
            "outcome": outcome,
            "detail": detail,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        event_hash = hashlib.sha256((bytes(previous) if previous else b"") + canonical).digest()
        await connection.execute(
            """
            INSERT INTO smart_alarm.audit_events (
                tenant_id, customer_id, actor_user_id, request_id, action,
                resource_type, resource_id, outcome, detail, previous_hash, event_hash
            ) VALUES ($1, $2, $3, $4, $5, 'DEVICE', $6, $7, $8::jsonb, $9, $10)
            """,
            tenant_id, context["customer_id"], context["actor_user_id"],
            context["idempotency_key"][:128], action, str(context["device_uid"]),
            outcome, detail, previous, event_hash,
        )

    @staticmethod
    def _expired(context: dict[str, Any]) -> bool:
        expires_at = context["command_expires_at"]
        return not isinstance(expires_at, datetime) or expires_at <= datetime.now(UTC)

    async def submit(self, event: OutboxEvent) -> None:
        context = await self._load(event, COMMAND_SUBMIT_EVENT)
        if context["operation_type"] != "device-command" or context["state"] not in {
            "PENDING", "QUEUED", "OUTCOME_UNKNOWN",
        }:
            return
        try:
            await self._submit(event, context)
        except (PlatformAdminError, CommandHandlerError, SecretReferenceError) as exc:
            retryable = not isinstance(exc, CommandHandlerError) or exc.retryable
            if isinstance(exc, PlatformAdminError):
                retryable = exc.retryable
            exhausted = event.attempts >= self._max_attempts
            if retryable and not exhausted:
                raise DeliveryError(getattr(exc, "code", "command_submission_unavailable"), retryable=True) from exc
            code = getattr(exc, "code", "command_submission_unavailable")
            if retryable:
                await self._submission_unknown(event, context, code)
            else:
                await self._finish_failure(event, context, code, "DEVICE_COMMAND_FAILED")
            raise DeliveryError(code, retryable=False) from exc

    async def _submit(self, event: OutboxEvent, context: dict[str, Any]) -> None:
        if context["lifecycle_state"] != "ACTIVE" or context["thingsboard_device_id"] is None:
            raise CommandHandlerError("device_not_commandable", retryable=False)
        result = dict(context["result"])
        command = result.get("command")
        policy = COMMAND_POLICIES.get(str(command))
        if policy is None or context["command_expires_at"] is None:
            raise CommandHandlerError("invalid_command_operation", retryable=False)
        session = await self._session(context)
        platform: dict[str, object] | None = None
        if context["platform_rpc_id"] is not None:
            platform = await self._thingsboard.persistent_rpc(
                session.token,
                rpc_id=context["platform_rpc_id"],
                device_id=context["thingsboard_device_id"],
                command=str(command),
                operation_id=context["id"],
            )
        else:
            platform = await self._thingsboard.find_persistent_rpc(
                session.token,
                device_id=context["thingsboard_device_id"],
                command=str(command),
                operation_id=context["id"],
            )
            if platform is None:
                expiration_ms = int(context["command_expires_at"].timestamp() * 1000)
                platform = await self._thingsboard.submit_persistent_rpc(
                    session.token,
                    device_id=context["thingsboard_device_id"],
                    command=str(command),
                    operation_id=context["id"],
                    expiration_time=expiration_ms,
                    retries=int(policy["retries"]),
                )
        rpc_id = _uuid(platform["rpcId"], "invalid_persistent_rpc_response")
        async with self._fenced_transaction(event) as connection:
            updated = await connection.fetchval(
                """
                UPDATE smart_alarm.operations
                SET state = 'QUEUED', platform_rpc_id = $2,
                    result = result || $3::jsonb, error_code = NULL,
                    updated_at = clock_timestamp(), version = version + 1
                WHERE id = $1 AND state IN ('PENDING', 'QUEUED', 'OUTCOME_UNKNOWN')
                RETURNING 1
                """,
                context["id"], rpc_id, platform,
            )
            if updated == 1:
                context["platform_rpc_id"] = rpc_id
                await self._schedule(connection, context, COMMAND_RECONCILE_EVENT, 1)
                await self._audit(connection, context, "DEVICE_COMMAND_QUEUED", "ACCEPTED", {
                    "command": command,
                    "rpcId": str(rpc_id),
                    "expirationTime": platform["expirationTime"],
                })

    async def _submission_unknown(self, event: OutboxEvent, context: dict[str, Any], code: str) -> None:
        async with self._fenced_transaction(event) as connection:
            updated = await connection.fetchval(
                """
                UPDATE smart_alarm.operations
                SET state = 'OUTCOME_UNKNOWN', error_code = NULL,
                    result = result || jsonb_build_object('platformStatus', 'SUBMISSION_UNKNOWN'),
                    updated_at = clock_timestamp(), version = version + 1
                WHERE id = $1 AND state IN ('PENDING', 'QUEUED')
                RETURNING 1
                """,
                context["id"],
            )
            if updated == 1:
                await self._schedule(connection, context, COMMAND_RECONCILE_EVENT, 2)
                await self._audit(connection, context, "DEVICE_COMMAND_SUBMISSION_UNKNOWN", "OUTCOME_UNKNOWN", {
                    "command": context["result"].get("command"), "errorCode": code,
                })

    async def reconcile(self, event: OutboxEvent) -> None:
        context = await self._load(event, COMMAND_RECONCILE_EVENT)
        if context["operation_type"] != "device-command" or context["state"] not in {
            "PENDING", "QUEUED", "OUTCOME_UNKNOWN",
        }:
            return
        result = dict(context["result"])
        command = str(result.get("command"))
        if command not in COMMAND_POLICIES or context["thingsboard_device_id"] is None:
            await self._finish_failure(event, context, "invalid_command_operation", "DEVICE_COMMAND_FAILED")
            return
        try:
            session = await self._session(context)
            if context["platform_rpc_id"] is None:
                platform = await self._thingsboard.find_persistent_rpc(
                    session.token,
                    device_id=context["thingsboard_device_id"],
                    command=command,
                    operation_id=context["id"],
                )
                if platform is None:
                    if self._expired(context):
                        await self._finish_failure(
                            event, context, "command_outcome_unknown", "DEVICE_COMMAND_FAILED",
                        )
                    else:
                        async with self._fenced_transaction(event) as connection:
                            await connection.execute(
                                """
                                UPDATE smart_alarm.operations
                                SET state = 'OUTCOME_UNKNOWN',
                                    result = result || jsonb_build_object('platformStatus', 'SUBMISSION_UNKNOWN'),
                                    updated_at = clock_timestamp(), version = version + 1
                                WHERE id = $1 AND state IN ('PENDING', 'QUEUED', 'OUTCOME_UNKNOWN')
                                """,
                                context["id"],
                            )
                            await self._schedule(connection, context, COMMAND_RECONCILE_EVENT, 3)
                    return
            else:
                platform = await self._thingsboard.persistent_rpc(
                    session.token,
                    rpc_id=context["platform_rpc_id"],
                    device_id=context["thingsboard_device_id"],
                    command=command,
                    operation_id=context["id"],
                )
        except (PlatformAdminError, CommandHandlerError, SecretReferenceError) as exc:
            if self._expired(context):
                await self._finish_failure(event, context, "command_outcome_unknown", "DEVICE_COMMAND_FAILED")
                return
            retryable = not isinstance(exc, CommandHandlerError) or exc.retryable
            if isinstance(exc, PlatformAdminError):
                retryable = exc.retryable
            if retryable and event.attempts < self._max_attempts:
                raise DeliveryError(
                    getattr(exc, "code", "command_reconciliation_unavailable"), retryable=True,
                ) from exc
            code = "command_outcome_unknown" if retryable else getattr(
                exc, "code", "command_reconciliation_unavailable",
            )
            await self._finish_failure(event, context, code, "DEVICE_COMMAND_FAILED")
            raise DeliveryError(code, retryable=False) from exc

        status = str(platform["platformStatus"])
        if status in PENDING_PLATFORM_STATUSES:
            async with self._fenced_transaction(event) as connection:
                await connection.execute(
                    """
                    UPDATE smart_alarm.operations
                    SET state = 'QUEUED', platform_rpc_id = $2,
                        result = result || $3::jsonb, updated_at = clock_timestamp(),
                        version = version + 1
                    WHERE id = $1 AND state IN ('PENDING', 'QUEUED', 'OUTCOME_UNKNOWN')
                    """,
                    context["id"], _uuid(platform["rpcId"], "invalid_persistent_rpc_response"), platform,
                )
                context["platform_rpc_id"] = _uuid(platform["rpcId"], "invalid_persistent_rpc_response")
                await self._schedule(connection, context, COMMAND_RECONCILE_EVENT, 2)
            return
        if status == "SUCCESSFUL":
            await self._finish_success(event, context, platform)
            return
        code = f"thingsboard_rpc_{status.lower()}"
        await self._finish_failure(event, context, code, "DEVICE_COMMAND_FAILED", platform)

    async def _finish_success(
        self, event: OutboxEvent, context: dict[str, Any], platform: dict[str, object],
    ) -> None:
        async with self._fenced_transaction(event) as connection:
            completed = datetime.now(UTC)
            duration_ms = max(0, int((completed - context["created_at"]).total_seconds() * 1000))
            result = {**dict(context["result"]), **platform, "durationMs": duration_ms}
            updated = await connection.fetchval(
                """
                UPDATE smart_alarm.operations
                SET state = 'SUCCEEDED', platform_rpc_id = $2, result = $3::jsonb,
                    error_code = NULL, finished_at = $4, updated_at = $4,
                    version = version + 1
                WHERE id = $1 AND state IN ('PENDING', 'QUEUED', 'OUTCOME_UNKNOWN')
                RETURNING 1
                """,
                context["id"], _uuid(platform["rpcId"], "invalid_persistent_rpc_response"),
                result, completed,
            )
            if updated == 1:
                await self._audit(connection, context, "DEVICE_COMMAND_SUCCEEDED", "SUCCEEDED", {
                    "command": result["command"], "rpcId": result["rpcId"], "durationMs": duration_ms,
                })

    async def _finish_failure(
        self,
        event: OutboxEvent,
        context: dict[str, Any],
        code: str,
        action: str,
        platform: dict[str, object] | None = None,
    ) -> None:
        async with self._fenced_transaction(event) as connection:
            completed = datetime.now(UTC)
            duration_ms = max(0, int((completed - context["created_at"]).total_seconds() * 1000))
            result = {
                **dict(context["result"]),
                **(platform or {}),
                "durationMs": duration_ms,
                "error": {"code": code},
            }
            updated = await connection.fetchval(
                """
                UPDATE smart_alarm.operations
                SET state = 'FAILED', result = $2::jsonb, error_code = $3,
                    finished_at = $4, updated_at = $4, version = version + 1
                WHERE id = $1 AND state IN ('PENDING', 'QUEUED', 'OUTCOME_UNKNOWN')
                RETURNING 1
                """,
                context["id"], result, code, completed,
            )
            if updated == 1:
                await self._notification(connection, context, "COMMAND_FAILED", {"errorCode": code})
                await self._audit(connection, context, action, "FAILED", {
                    "command": result.get("command"), "errorCode": code,
                })

    @staticmethod
    async def _notification(
        connection: Any, context: dict[str, Any], kind: str, payload: dict[str, object],
    ) -> None:
        await connection.execute(
            """
            INSERT INTO smart_alarm.notification_events (
                tenant_id, customer_id, source_operation_id, event_type, severity, payload
            ) VALUES ($1, $2, $3, $4, 'WARNING', $5::jsonb)
            ON CONFLICT (tenant_id, event_type, source_operation_id) DO NOTHING
            """,
            context["tenant_id"], context["customer_id"], context["id"], kind,
            {"deviceUid": str(context["device_uid"]), "operationId": str(context["id"]), **payload},
        )

    async def cancel(self, event: OutboxEvent) -> None:
        context = await self._load(event, COMMAND_CANCEL_EVENT)
        if context["operation_type"] != "device-command-cancel" or context["state"] not in {
            "PENDING", "QUEUED", "OUTCOME_UNKNOWN",
        }:
            return
        result = dict(context["result"])
        source_id = _uuid(result.get("commandOperationId"), "invalid_command_cancel_operation")
        async with self._system_transaction() as connection:
            source = await connection.fetchrow(
                """
                SELECT * FROM smart_alarm.operations
                WHERE id = $1 AND tenant_id = $2 AND operation_type = 'device-command'
                  AND resource_id = $3
                """,
                source_id, context["tenant_id"], str(context["device_uid"]),
            )
        if source is None:
            await self._finish_failure(event, context, "command_operation_not_found", "DEVICE_COMMAND_CANCEL_FAILED")
            return
        source = dict(source)
        if source["state"] not in {"PENDING", "QUEUED", "OUTCOME_UNKNOWN"} or source["platform_rpc_id"] is None:
            await self._finish_failure(event, context, "command_not_cancellable", "DEVICE_COMMAND_CANCEL_FAILED")
            return
        try:
            session = await self._session(context)
            platform = await self._thingsboard.persistent_rpc(
                session.token,
                rpc_id=source["platform_rpc_id"],
                device_id=context["thingsboard_device_id"],
                command=str(source["result"].get("command")),
                operation_id=source["id"],
            )
            if platform["platformStatus"] not in PENDING_PLATFORM_STATUSES:
                raise CommandHandlerError("command_not_cancellable", retryable=False)
            await self._thingsboard.cancel_persistent_rpc(session.token, source["platform_rpc_id"])
        except (PlatformAdminError, CommandHandlerError, SecretReferenceError) as exc:
            retryable = not isinstance(exc, CommandHandlerError) or exc.retryable
            if isinstance(exc, PlatformAdminError):
                retryable = exc.retryable
            exhausted = event.attempts >= self._max_attempts
            if retryable and not exhausted:
                raise DeliveryError(getattr(exc, "code", "command_cancel_unavailable"), retryable=True) from exc
            code = "command_cancel_outcome_unknown" if retryable else getattr(exc, "code", "command_not_cancellable")
            await self._finish_failure(event, context, code, "DEVICE_COMMAND_CANCEL_FAILED")
            if code == "command_cancel_outcome_unknown":
                async with self._fenced_transaction(event) as connection:
                    await self._notification(
                        connection, context, "COMMAND_CANCEL_REVIEW_REQUIRED",
                        {"commandOperationId": str(source_id), "rpcId": str(source["platform_rpc_id"])},
                    )
            raise DeliveryError(code, retryable=False) from exc

        async with self._fenced_transaction(event) as connection:
            completed = datetime.now(UTC)
            source_result = {
                **dict(source["result"]),
                "platformStatus": "CANCELLED",
                "cancelledAt": int(completed.timestamp() * 1000),
                "cancelOperationId": str(context["id"]),
                "cancellationWarning": CANCELLATION_WARNING,
            }
            changed = await connection.fetchval(
                """
                UPDATE smart_alarm.operations
                SET state = 'CANCELLED', result = $2::jsonb, error_code = NULL,
                    finished_at = $3, updated_at = $3, version = version + 1
                WHERE id = $1 AND state IN ('PENDING', 'QUEUED', 'OUTCOME_UNKNOWN')
                RETURNING 1
                """,
                source_id, source_result, completed,
            )
            if changed != 1:
                raise DeliveryError("command_cancel_race", retryable=False)
            cancel_result = {
                **result,
                "command": source["result"].get("command"),
                "rpcId": str(source["platform_rpc_id"]),
                "platformStatus": "CANCELLED",
                "warning": CANCELLATION_WARNING,
            }
            await connection.execute(
                """
                UPDATE smart_alarm.operations
                SET state = 'SUCCEEDED', result = $2::jsonb, error_code = NULL,
                    finished_at = $3, updated_at = $3, version = version + 1
                WHERE id = $1 AND state IN ('PENDING', 'QUEUED', 'OUTCOME_UNKNOWN')
                """,
                context["id"], cancel_result, completed,
            )
            await self._audit(connection, context, "DEVICE_COMMAND_CANCELLED", "SUCCEEDED", {
                "commandOperationId": str(source_id),
                "rpcId": str(source["platform_rpc_id"]),
                "warning": CANCELLATION_WARNING,
            })
