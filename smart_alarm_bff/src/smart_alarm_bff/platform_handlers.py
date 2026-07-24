"""Fenced ThingsBoard side effects for product Asset and Device Profile writes."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Awaitable, Callable
from uuid import UUID

from .secret_provider import MountedSecretProvider, SecretReferenceError
from .thingsboard_admin import PlatformAdminError, ServiceIdentity, ThingsBoardAdminClient
from .worker import DeliveryError, OutboxEvent


ASSET_SYNC_EVENT = "asset.platform.sync.requested"
PROFILE_SYNC_EVENT = "device-profile.platform.sync.requested"


class PlatformSyncError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def _uuid(value: object, code: str) -> UUID:
    if not isinstance(value, str):
        raise PlatformSyncError(code, retryable=False)
    try:
        return UUID(value)
    except ValueError as exc:
        raise PlatformSyncError(code, retryable=False) from exc


class PlatformEntityHandlers:
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
        return {ASSET_SYNC_EVENT: self.asset, PROFILE_SYNC_EVENT: self.profile}

    async def asset(self, event: OutboxEvent) -> None:
        await self._run(event, "asset", self._sync_asset)

    async def profile(self, event: OutboxEvent) -> None:
        await self._run(event, "profile", self._sync_profile)

    async def _run(
        self,
        event: OutboxEvent,
        entity: str,
        handler: Callable[[OutboxEvent], Awaitable[None]],
    ) -> None:
        try:
            await handler(event)
        except DeliveryError:
            raise
        except PlatformAdminError as exc:
            exhausted = exc.retryable and event.attempts >= self._max_attempts
            if not exc.retryable or exhausted:
                await self._mark_failed(event, entity, exc.code)
            raise DeliveryError(exc.code, retryable=exc.retryable and not exhausted) from exc
        except PlatformSyncError as exc:
            exhausted = exc.retryable and event.attempts >= self._max_attempts
            if not exc.retryable or exhausted:
                await self._mark_failed(event, entity, exc.code)
            raise DeliveryError(exc.code, retryable=exc.retryable and not exhausted) from exc
        except SecretReferenceError as exc:
            exhausted = event.attempts >= self._max_attempts
            if exhausted:
                await self._mark_failed(event, entity, "platform_secret_unavailable")
            raise DeliveryError("platform_secret_unavailable", retryable=not exhausted) from exc

    def _identity(self, event: OutboxEvent, aggregate_type: str) -> tuple[UUID, UUID]:
        if event.tenant_id is None or event.aggregate_type != aggregate_type:
            raise PlatformSyncError("invalid_platform_sync_event", retryable=False)
        operation_id = _uuid(event.payload.get("operationId"), "invalid_platform_sync_event")
        aggregate_id = _uuid(event.aggregate_id, "invalid_platform_sync_event")
        return operation_id, aggregate_id

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

    async def _session(self, context: dict[str, Any]):
        if context["thingsboard_tenant_id"] is None or not context["service_identity_secret_ref"]:
            raise PlatformSyncError("tenant_service_identity_missing", retryable=False)
        identity = ServiceIdentity.from_json(self._secrets.read(context["service_identity_secret_ref"]))
        return await self._thingsboard.login(identity, context["thingsboard_tenant_id"])

    async def _load_asset(self, event: OutboxEvent) -> dict[str, Any]:
        operation_id, asset_id = self._identity(event, "ASSET")
        async with self._system_transaction() as connection:
            row = await connection.fetchrow(
                """
                SELECT a.*, t.thingsboard_tenant_id, t.service_identity_secret_ref,
                       c.thingsboard_customer_id,
                       parent.thingsboard_asset_id AS parent_thingsboard_asset_id,
                       o.state AS operation_state, o.operation_type
                FROM smart_alarm.outbox_events e
                JOIN smart_alarm.assets a ON a.tenant_id = e.tenant_id AND a.id = $4
                JOIN smart_alarm.tenants t ON t.id = a.tenant_id AND t.status = 'ACTIVE'
                LEFT JOIN smart_alarm.customers c ON c.tenant_id = a.tenant_id AND c.id = a.customer_id
                LEFT JOIN smart_alarm.assets parent ON parent.tenant_id = a.tenant_id AND parent.id = a.parent_asset_id
                JOIN smart_alarm.operations o ON o.id = $5 AND o.tenant_id = a.tenant_id
                WHERE e.id = $1 AND e.status = 'LEASED' AND e.lease_owner = $2
                  AND e.lease_token = $3 AND e.lease_expires_at > clock_timestamp()
                  AND e.event_type = $6 AND e.aggregate_type = 'ASSET'
                  AND e.aggregate_id = $4::text AND e.tenant_id = $7
                """,
                event.event_id, self._worker_id, event.lease_token, asset_id,
                operation_id, event.event_type, event.tenant_id,
            )
            if row is None:
                raise DeliveryError("worker_lease_lost", retryable=True)
            relations = await connection.fetch(
                """
                SELECT r.id, r.status, r.from_id, parent.thingsboard_asset_id AS from_thingsboard_asset_id,
                       parent.platform_sync_status AS from_platform_sync_status
                FROM smart_alarm.entity_relations r
                JOIN smart_alarm.assets parent ON parent.tenant_id = r.tenant_id AND parent.id = r.from_id
                WHERE r.tenant_id = $1 AND r.to_type = 'ASSET' AND r.to_id = $2
                  AND r.relation_type = 'Contains'
                ORDER BY r.created_at, r.id
                """,
                event.tenant_id, asset_id,
            )
        context = dict(row)
        context["operation_id"] = operation_id
        context["relations"] = [dict(item) for item in relations]
        return context

    async def _load_profile(self, event: OutboxEvent) -> dict[str, Any]:
        operation_id, profile_id = self._identity(event, "DEVICE_PROFILE")
        async with self._system_transaction() as connection:
            row = await connection.fetchrow(
                """
                SELECT p.*, t.thingsboard_tenant_id, t.service_identity_secret_ref,
                       o.state AS operation_state, o.operation_type
                FROM smart_alarm.outbox_events e
                JOIN smart_alarm.device_profiles p ON p.tenant_id = e.tenant_id AND p.id = $4
                JOIN smart_alarm.tenants t ON t.id = p.tenant_id AND t.status = 'ACTIVE'
                JOIN smart_alarm.operations o ON o.id = $5 AND o.tenant_id = p.tenant_id
                WHERE e.id = $1 AND e.status = 'LEASED' AND e.lease_owner = $2
                  AND e.lease_token = $3 AND e.lease_expires_at > clock_timestamp()
                  AND e.event_type = $6 AND e.aggregate_type = 'DEVICE_PROFILE'
                  AND e.aggregate_id = $4::text AND e.tenant_id = $7
                """,
                event.event_id, self._worker_id, event.lease_token, profile_id,
                operation_id, event.event_type, event.tenant_id,
            )
        if row is None:
            raise DeliveryError("worker_lease_lost", retryable=True)
        return {**dict(row), "operation_id": operation_id}

    async def _sync_asset(self, event: OutboxEvent) -> None:
        context = await self._load_asset(event)
        if context["operation_state"] == "SUCCEEDED":
            return
        session = await self._session(context)
        platform_id = context["thingsboard_asset_id"]
        if context["operation_type"] == "asset-archive":
            if platform_id is not None:
                await self._thingsboard.delete_asset(session.token, platform_id)
        else:
            technical_name = f"stc-asset-{context['id']}"
            if platform_id is None:
                asset = await self._thingsboard.create_asset(
                    session.token, name=technical_name, label=context["name"],
                    asset_type=context["asset_type"], asset_uid=context["id"],
                    customer_id=context["thingsboard_customer_id"],
                )
                platform_id = asset["uuid"]
            else:
                asset = await self._thingsboard.update_asset(
                    session.token, platform_id, name=technical_name, label=context["name"],
                    asset_type=context["asset_type"], asset_uid=context["id"],
                )
                current_customer = self._thingsboard.asset_customer_id(asset)
                desired_customer = context["thingsboard_customer_id"]
                if current_customer != desired_customer:
                    if desired_customer is None:
                        await self._thingsboard.unassign_asset(session.token, platform_id)
                    else:
                        await self._thingsboard.assign_asset(session.token, desired_customer, platform_id)
            for relation in context["relations"]:
                parent_id = relation["from_thingsboard_asset_id"]
                if parent_id is None:
                    raise PlatformSyncError(
                        "thingsboard_parent_asset_mapping_missing",
                        retryable=relation["from_platform_sync_status"].startswith("PENDING_"),
                    )
                if relation["status"] == "PENDING_DELETE":
                    await self._thingsboard.delete_asset_relation(session.token, parent_id, platform_id)
                elif relation["status"] == "PENDING_CREATE":
                    await self._thingsboard.save_asset_relation(session.token, parent_id, platform_id)

        async with self._fenced_transaction(event) as connection:
            await connection.execute(
                """
                DELETE FROM smart_alarm.entity_relations
                WHERE tenant_id = $1 AND to_type = 'ASSET' AND to_id = $2
                  AND relation_type = 'Contains' AND status = 'PENDING_DELETE'
                """,
                event.tenant_id, context["id"],
            )
            await connection.execute(
                """
                UPDATE smart_alarm.entity_relations
                SET status = 'ACTIVE', thingsboard_synced_at = clock_timestamp(),
                    updated_at = clock_timestamp(), version = version + 1
                WHERE tenant_id = $1 AND to_type = 'ASSET' AND to_id = $2
                  AND relation_type = 'Contains' AND status = 'PENDING_CREATE'
                """,
                event.tenant_id, context["id"],
            )
            await connection.execute(
                """
                UPDATE smart_alarm.assets
                SET thingsboard_asset_id = COALESCE($3, thingsboard_asset_id),
                    platform_sync_status = 'SYNCED', platform_error_code = NULL,
                    platform_synced_at = clock_timestamp(), updated_at = clock_timestamp(),
                    version = version + 1
                WHERE tenant_id = $1 AND id = $2
                """,
                event.tenant_id, context["id"], platform_id,
            )
            result = {
                "operationId": str(context["operation_id"]),
                "kind": context["operation_type"].removeprefix("asset-"),
                "status": "SUCCEEDED",
                "asset": {"id": str(context["id"]), "name": context["name"], "type": context["asset_type"],
                           "customerId": str(context["customer_id"]) if context["customer_id"] else None,
                           "deviceCount": 0},
            }
            await connection.execute(
                """
                UPDATE smart_alarm.operations
                SET state = 'SUCCEEDED', result = $2::jsonb, error_code = NULL,
                    finished_at = clock_timestamp(), updated_at = clock_timestamp(), version = version + 1
                WHERE id = $1 AND state = 'QUEUED'
                """,
                context["operation_id"], result,
            )

    async def _sync_profile(self, event: OutboxEvent) -> None:
        context = await self._load_profile(event)
        if context["operation_state"] == "SUCCEEDED":
            return
        session = await self._session(context)
        platform_id = context["thingsboard_profile_id"]
        if context["operation_type"] == "device-profile-archive":
            if platform_id is not None:
                await self._thingsboard.delete_device_profile(session.token, platform_id)
        else:
            if platform_id is None:
                profile = await self._thingsboard.create_device_profile(
                    session.token, name=context["name"], profile_type=context["profile_type"],
                    transport_type=context["transport_type"], profile_uid=context["id"], is_default=False,
                )
                platform_id = profile["uuid"]
            else:
                await self._thingsboard.update_device_profile(
                    session.token, platform_id, name=context["name"], profile_type=context["profile_type"],
                    transport_type=context["transport_type"], profile_uid=context["id"], is_default=context["is_default"],
                )
            if context["is_default"]:
                await self._thingsboard.set_default_device_profile(session.token, platform_id, context["id"])

        async with self._fenced_transaction(event) as connection:
            await connection.execute(
                """
                UPDATE smart_alarm.device_profiles
                SET thingsboard_profile_id = COALESCE($3, thingsboard_profile_id),
                    platform_sync_status = 'SYNCED', platform_error_code = NULL,
                    platform_synced_at = clock_timestamp(), updated_at = clock_timestamp(),
                    version = version + 1
                WHERE tenant_id = $1 AND id = $2
                """,
                event.tenant_id, context["id"], platform_id,
            )
            result = {
                "operationId": str(context["operation_id"]),
                "kind": context["operation_type"].removeprefix("device-profile-"),
                "status": "SUCCEEDED",
                "profile": {"id": str(context["id"]), "name": context["name"], "type": context["profile_type"],
                             "transportType": context["transport_type"], "isDefault": context["is_default"]},
            }
            await connection.execute(
                """
                UPDATE smart_alarm.operations
                SET state = 'SUCCEEDED', result = $2::jsonb, error_code = NULL,
                    finished_at = clock_timestamp(), updated_at = clock_timestamp(), version = version + 1
                WHERE id = $1 AND state = 'QUEUED'
                """,
                context["operation_id"], result,
            )

    async def _mark_failed(self, event: OutboxEvent, entity: str, code: str) -> None:
        try:
            operation_id, aggregate_id = self._identity(event, "ASSET" if entity == "asset" else "DEVICE_PROFILE")
        except PlatformSyncError:
            return
        async with self._fenced_transaction(event) as connection:
            if entity == "asset":
                await connection.execute(
                    """
                    UPDATE smart_alarm.assets
                    SET platform_sync_status = 'ERROR', platform_error_code = $3,
                        updated_at = clock_timestamp(), version = version + 1
                    WHERE tenant_id = $1 AND id = $2
                    """,
                    event.tenant_id, aggregate_id, code,
                )
                await connection.execute(
                    """
                    UPDATE smart_alarm.entity_relations
                    SET status = 'ERROR', updated_at = clock_timestamp(), version = version + 1
                    WHERE tenant_id = $1 AND to_type = 'ASSET' AND to_id = $2
                      AND status IN ('PENDING_CREATE', 'PENDING_DELETE')
                    """,
                    event.tenant_id, aggregate_id,
                )
            else:
                await connection.execute(
                    """
                    UPDATE smart_alarm.device_profiles
                    SET platform_sync_status = 'ERROR', platform_error_code = $3,
                        updated_at = clock_timestamp(), version = version + 1
                    WHERE tenant_id = $1 AND id = $2
                    """,
                    event.tenant_id, aggregate_id, code,
                )
            await connection.execute(
                """
                UPDATE smart_alarm.operations
                SET state = 'FAILED', error_code = $2,
                    result = jsonb_set(COALESCE(result, '{}'::jsonb), '{status}', to_jsonb('FAILED'::text), true)
                             || jsonb_build_object('error', jsonb_build_object('code', $2::text)),
                    finished_at = clock_timestamp(), updated_at = clock_timestamp(), version = version + 1
                WHERE id = $1 AND state = 'QUEUED'
                """,
                operation_id, code,
            )
