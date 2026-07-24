"""Fenced ThingsBoard side effects for device lifecycle outbox events."""

from __future__ import annotations

from contextlib import asynccontextmanager
import secrets
from typing import Any, AsyncIterator, Awaitable, Callable
from uuid import UUID

from .device_routes import _device_row, _public_device
from .secret_provider import EncryptedFileSecretStore, MountedSecretProvider, SecretReferenceError
from .thingsboard_admin import PlatformAdminError, ServiceIdentity, ThingsBoardAdminClient
from .worker import DeliveryError, OutboxEvent


ACTIVATION_EVENT = "device.activation.requested"
METADATA_EVENT = "device.metadata.sync.requested"
RETIREMENT_EVENT = "device.retirement.requested"


class LifecycleError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


def _uuid(value: object, code: str) -> UUID:
    if not isinstance(value, str):
        raise LifecycleError(code, retryable=False)
    try:
        return UUID(value)
    except ValueError as exc:
        raise LifecycleError(code, retryable=False) from exc


class DeviceLifecycleHandlers:
    def __init__(
        self,
        database: Callable[[], Awaitable[Any]],
        worker_id: str,
        secrets_provider: MountedSecretProvider,
        device_secrets: EncryptedFileSecretStore,
        thingsboard: ThingsBoardAdminClient,
        max_attempts: int = 8,
        inactivity_timeout_ms: int = 90_000,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be positive")
        if (
            not isinstance(inactivity_timeout_ms, int)
            or isinstance(inactivity_timeout_ms, bool)
            or not 30_000 <= inactivity_timeout_ms <= 3_600_000
        ):
            raise ValueError("inactivity_timeout_ms must be between 30000 and 3600000")
        self._database = database
        self._worker_id = worker_id
        self._secrets = secrets_provider
        self._device_secrets = device_secrets
        self._thingsboard = thingsboard
        self._max_attempts = max_attempts
        self._inactivity_timeout_ms = inactivity_timeout_ms

    def mapping(self) -> dict[str, Callable[[OutboxEvent], Awaitable[None]]]:
        return {
            ACTIVATION_EVENT: self.activation,
            METADATA_EVENT: self.metadata,
            RETIREMENT_EVENT: self.retirement,
        }

    async def activation(self, event: OutboxEvent) -> None:
        await self._run(event, "activation", self._activate)

    async def metadata(self, event: OutboxEvent) -> None:
        await self._run(event, "metadata", self._sync_metadata)

    async def retirement(self, event: OutboxEvent) -> None:
        await self._run(event, "retirement", self._retire)

    async def _run(
        self,
        event: OutboxEvent,
        lifecycle: str,
        handler: Callable[[OutboxEvent], Awaitable[None]],
    ) -> None:
        try:
            await handler(event)
        except DeliveryError:
            raise
        except PlatformAdminError as exc:
            exhausted = exc.retryable and event.attempts >= self._max_attempts
            if not exc.retryable or exhausted:
                await self._mark_failed(event, lifecycle, exc.code)
            raise DeliveryError(exc.code, retryable=exc.retryable and not exhausted) from exc
        except LifecycleError as exc:
            exhausted = exc.retryable and event.attempts >= self._max_attempts
            if not exc.retryable or exhausted:
                await self._mark_failed(event, lifecycle, exc.code)
            raise DeliveryError(exc.code, retryable=exc.retryable and not exhausted) from exc
        except SecretReferenceError as exc:
            exhausted = event.attempts >= self._max_attempts
            if exhausted:
                await self._mark_failed(event, lifecycle, "lifecycle_secret_unavailable")
            raise DeliveryError("lifecycle_secret_unavailable", retryable=not exhausted) from exc

    def _event_identity(self, event: OutboxEvent) -> tuple[UUID, UUID, UUID]:
        if event.tenant_id is None or event.aggregate_type != "DEVICE":
            raise LifecycleError("invalid_lifecycle_event", retryable=False)
        operation_id = _uuid(event.payload.get("operationId"), "invalid_lifecycle_event")
        device_id = _uuid(event.payload.get("deviceId"), "invalid_lifecycle_event")
        device_uid = _uuid(event.payload.get("deviceUid"), "invalid_lifecycle_event")
        if event.aggregate_id != str(device_id):
            raise LifecycleError("invalid_lifecycle_event", retryable=False)
        return operation_id, device_id, device_uid

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
                SELECT 1
                FROM smart_alarm.outbox_events
                WHERE id = $1 AND status = 'LEASED' AND lease_owner = $2
                  AND lease_token = $3 AND lease_expires_at > clock_timestamp()
                FOR UPDATE
                """,
                event.event_id, self._worker_id, event.lease_token,
            )
            if fenced != 1:
                raise DeliveryError("worker_lease_lost", retryable=True)
            yield connection

    async def _load(self, event: OutboxEvent) -> dict[str, Any]:
        operation_id, device_id, device_uid = self._event_identity(event)
        async with self._system_transaction() as connection:
            row = await connection.fetchrow(
                """
                SELECT d.*, t.thingsboard_tenant_id, t.service_identity_secret_ref,
                       p.thingsboard_profile_id,
                       c.thingsboard_customer_id,
                       a.thingsboard_asset_id,
                       o.state AS operation_state,
                       g.status AS grant_status,
                       g.credential_version AS grant_credential_version,
                       g.credential_secret_ref AS grant_credential_secret_ref
                FROM smart_alarm.outbox_events e
                JOIN smart_alarm.devices d
                  ON d.tenant_id = e.tenant_id AND d.id = $4
                JOIN smart_alarm.tenants t ON t.id = d.tenant_id AND t.status = 'ACTIVE'
                JOIN smart_alarm.device_profiles p
                  ON p.tenant_id = d.tenant_id AND p.id = d.device_profile_id
                LEFT JOIN smart_alarm.customers c
                  ON c.tenant_id = d.tenant_id AND c.id = d.customer_id
                LEFT JOIN smart_alarm.assets a
                  ON a.tenant_id = d.tenant_id AND a.id = d.asset_id
                JOIN smart_alarm.operations o ON o.id = $6 AND o.tenant_id = d.tenant_id
                LEFT JOIN LATERAL (
                    SELECT status, credential_version, credential_secret_ref
                    FROM smart_alarm.device_activation_grants
                    WHERE tenant_id = d.tenant_id AND device_id = d.id
                    ORDER BY credential_version DESC
                    LIMIT 1
                ) g ON true
                WHERE e.id = $1 AND e.status = 'LEASED' AND e.lease_owner = $2
                  AND e.lease_token = $3 AND e.lease_expires_at > clock_timestamp()
                  AND e.event_type = $7 AND e.aggregate_type = 'DEVICE'
                  AND e.aggregate_id = $4::text AND e.tenant_id = $5
                  AND d.device_uid = $8
                """,
                event.event_id, self._worker_id, event.lease_token, device_id,
                event.tenant_id, operation_id, event.event_type, device_uid,
            )
            if row is None:
                raise DeliveryError("worker_lease_lost", retryable=True)
            relations = await connection.fetch(
                """
                SELECT r.id, r.status, r.from_id, a.thingsboard_asset_id
                FROM smart_alarm.entity_relations r
                JOIN smart_alarm.assets a
                  ON a.tenant_id = r.tenant_id AND a.id = r.from_id
                WHERE r.tenant_id = $1 AND r.to_type = 'DEVICE' AND r.to_id = $2
                  AND r.relation_type = 'Contains'
                ORDER BY r.created_at, r.id
                """,
                event.tenant_id, device_id,
            )
        context = dict(row)
        context["operation_id"] = operation_id
        context["relations"] = [dict(item) for item in relations]
        return context

    @staticmethod
    def _validate_context(context: dict[str, Any]) -> None:
        if context["thingsboard_tenant_id"] is None or not context["service_identity_secret_ref"]:
            raise LifecycleError("tenant_service_identity_missing", retryable=False)
        if context["thingsboard_profile_id"] is None:
            raise LifecycleError("thingsboard_profile_mapping_missing", retryable=False)
        if context["customer_id"] is not None and context["thingsboard_customer_id"] is None:
            raise LifecycleError("thingsboard_customer_mapping_missing", retryable=False)
        if context["asset_id"] is not None and context["thingsboard_asset_id"] is None:
            raise LifecycleError("thingsboard_asset_mapping_missing", retryable=False)
        for relation in context["relations"]:
            if relation["thingsboard_asset_id"] is None:
                raise LifecycleError("thingsboard_asset_mapping_missing", retryable=False)

    def _service_identity(self, context: dict[str, Any]) -> ServiceIdentity:
        value = self._secrets.read(context["service_identity_secret_ref"])
        return ServiceIdentity.from_json(value)

    async def _session(self, context: dict[str, Any]):
        identity = self._service_identity(context)
        return await self._thingsboard.login(identity, context["thingsboard_tenant_id"])

    async def _sync_customer_assignment(
        self,
        token: str,
        device: dict[str, object],
        desired_customer_id: UUID | None,
    ) -> None:
        current_customer_id = self._thingsboard.device_customer_id(device)
        if current_customer_id == desired_customer_id:
            return
        if desired_customer_id is None:
            await self._thingsboard.unassign_customer(token, device["uuid"])
            return
        await self._thingsboard.assign_customer(token, desired_customer_id, device["uuid"])

    async def _activate(self, event: OutboxEvent) -> None:
        context = await self._load(event)
        if (
            context["lifecycle_state"] == "ACTIVE"
            and context["operation_state"] == "SUCCEEDED"
            and context["grant_status"] == "CONSUMED"
        ):
            return
        self._validate_context(context)
        if context["lifecycle_state"] != "ACTIVATING" or context["operation_state"] != "QUEUED":
            raise LifecycleError("device_activation_state_conflict", retryable=False)
        if context["thingsboard_device_id"] is not None or context["credential_secret_ref"] is not None:
            raise LifecycleError("device_activation_binding_conflict", retryable=False)

        session = await self._session(context)
        relative = (
            f"tenants/{context['tenant_id']}/devices/{context['device_uid']}"
            f"/credentials/v{int(context['credential_version'])}.secret"
        )
        secret_ref, access_token = self._device_secrets.get_or_create(
            relative,
            lambda: secrets.token_urlsafe(32).encode("ascii"),
        )
        platform_device: dict[str, object] | None = None
        try:
            platform_device = await self._thingsboard.create_device(
                session.token,
                name=context["technical_name"],
                label=context["display_name"],
                profile_id=context["thingsboard_profile_id"],
                access_token=access_token.decode("ascii"),
                device_uid=context["device_uid"],
            )
            platform_device_id = platform_device["uuid"]
            await self._thingsboard.set_inactivity_timeout(
                session.token, platform_device_id, self._inactivity_timeout_ms,
            )
            if context["thingsboard_customer_id"] is not None:
                await self._thingsboard.assign_customer(
                    session.token, context["thingsboard_customer_id"], platform_device_id,
                )
            if context["thingsboard_asset_id"] is not None:
                await self._thingsboard.save_relation(
                    session.token, context["thingsboard_asset_id"], platform_device_id,
                )
        except PlatformAdminError as exc:
            if not exc.retryable:
                try:
                    if platform_device is not None:
                        await self._thingsboard.delete_device(session.token, platform_device["uuid"])
                    self._device_secrets.delete(secret_ref)
                except (PlatformAdminError, SecretReferenceError) as compensation_error:
                    raise LifecycleError("activation_compensation_failed", retryable=True) from compensation_error
            raise

        async with self._fenced_transaction(event) as connection:
            updated = await connection.fetchval(
                """
                UPDATE smart_alarm.devices
                SET thingsboard_device_id = $3, credential_secret_ref = $4,
                    updated_at = clock_timestamp(), version = version + 1
                WHERE tenant_id = $1 AND id = $2 AND lifecycle_state = 'ACTIVATING'
                  AND thingsboard_device_id IS NULL AND credential_secret_ref IS NULL
                RETURNING 1
                """,
                context["tenant_id"], context["id"], platform_device["uuid"], secret_ref,
            )
            if updated != 1:
                raise LifecycleError("device_activation_state_conflict", retryable=False)
            await connection.execute(
                """
                INSERT INTO smart_alarm.device_activation_grants (
                    tenant_id, device_id, operation_id, credential_version,
                    credential_secret_ref, expires_at
                ) VALUES ($1, $2, $3, $4, $5, clock_timestamp() + interval '7 days')
                ON CONFLICT (tenant_id, device_id, credential_version) DO NOTHING
                """,
                context["tenant_id"], context["id"], context["operation_id"],
                context["credential_version"], secret_ref,
            )
            grant = await connection.fetchrow(
                """
                SELECT operation_id, credential_secret_ref, status
                FROM smart_alarm.device_activation_grants
                WHERE tenant_id = $1 AND device_id = $2 AND credential_version = $3
                """,
                context["tenant_id"], context["id"], context["credential_version"],
            )
            if (
                grant is None
                or grant["operation_id"] != context["operation_id"]
                or grant["credential_secret_ref"] != secret_ref
                or grant["status"] != "READY"
            ):
                raise LifecycleError("activation_grant_conflict", retryable=False)
            await connection.execute(
                """
                UPDATE smart_alarm.entity_relations
                SET status = 'ACTIVE', thingsboard_synced_at = clock_timestamp(),
                    updated_at = clock_timestamp(), version = version + 1
                WHERE tenant_id = $1 AND to_type = 'DEVICE' AND to_id = $2
                  AND relation_type = 'Contains' AND status = 'PENDING_CREATE'
                """,
                context["tenant_id"], context["id"],
            )

    async def _sync_metadata(self, event: OutboxEvent) -> None:
        context = await self._load(event)
        if context["operation_state"] == "SUCCEEDED":
            return
        self._validate_context(context)
        if context["lifecycle_state"] != "ACTIVE" or context["operation_state"] != "QUEUED":
            raise LifecycleError("device_metadata_state_conflict", retryable=False)
        if context["thingsboard_device_id"] is None or context["credential_secret_ref"] is None:
            raise LifecycleError("device_platform_binding_missing", retryable=False)

        session = await self._session(context)
        device = await self._thingsboard.get_device(session.token, context["thingsboard_device_id"])
        self._thingsboard.verify_device_uid(device, context["device_uid"])
        await self._thingsboard.set_inactivity_timeout(
            session.token, context["thingsboard_device_id"], self._inactivity_timeout_ms,
        )
        await self._thingsboard.update_label(session.token, device, context["display_name"])
        await self._sync_customer_assignment(session.token, device, context["thingsboard_customer_id"])
        for relation in context["relations"]:
            if relation["status"] == "PENDING_DELETE":
                await self._thingsboard.delete_relation(
                    session.token, relation["thingsboard_asset_id"], context["thingsboard_device_id"],
                )
            elif relation["status"] == "PENDING_CREATE":
                await self._thingsboard.save_relation(
                    session.token, relation["thingsboard_asset_id"], context["thingsboard_device_id"],
                )

        async with self._fenced_transaction(event) as connection:
            await connection.execute(
                """
                DELETE FROM smart_alarm.entity_relations
                WHERE tenant_id = $1 AND to_type = 'DEVICE' AND to_id = $2
                  AND relation_type = 'Contains' AND status = 'PENDING_DELETE'
                """,
                context["tenant_id"], context["id"],
            )
            await connection.execute(
                """
                UPDATE smart_alarm.entity_relations
                SET status = 'ACTIVE', thingsboard_synced_at = clock_timestamp(),
                    updated_at = clock_timestamp(), version = version + 1
                WHERE tenant_id = $1 AND to_type = 'DEVICE' AND to_id = $2
                  AND relation_type = 'Contains' AND status = 'PENDING_CREATE'
                """,
                context["tenant_id"], context["id"],
            )
            row = await _device_row(connection, context["tenant_id"], context["device_uid"])
            result = {
                "operationId": str(context["operation_id"]),
                "kind": "update",
                "status": "SUCCEEDED",
                "device": _public_device(row),
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

    async def _retire(self, event: OutboxEvent) -> None:
        context = await self._load(event)
        if context["lifecycle_state"] == "RETIRED" and context["operation_state"] == "SUCCEEDED":
            return
        self._validate_context(context)
        if context["lifecycle_state"] != "RETIRING" or context["operation_state"] != "QUEUED":
            raise LifecycleError("device_retirement_state_conflict", retryable=False)
        if context["thingsboard_device_id"] is None or context["credential_secret_ref"] is None:
            raise LifecycleError("device_platform_binding_missing", retryable=False)

        session = await self._session(context)
        device = await self._thingsboard.get_device(session.token, context["thingsboard_device_id"])
        self._thingsboard.verify_device_uid(device, context["device_uid"])
        credentials = await self._thingsboard.get_credentials(session.token, context["thingsboard_device_id"])
        await self._thingsboard.rotate_credentials(session.token, credentials, secrets.token_urlsafe(48))
        for relation in context["relations"]:
            await self._thingsboard.delete_relation(
                session.token, relation["thingsboard_asset_id"], context["thingsboard_device_id"],
            )
        await self._sync_customer_assignment(session.token, device, None)
        self._device_secrets.delete(context["credential_secret_ref"])

        async with self._fenced_transaction(event) as connection:
            updated = await connection.fetchval(
                """
                UPDATE smart_alarm.devices
                SET lifecycle_state = 'RETIRED', credential_version = credential_version + 1,
                    credential_secret_ref = NULL, retired_at = clock_timestamp(),
                    updated_at = clock_timestamp(), version = version + 1
                WHERE tenant_id = $1 AND id = $2 AND lifecycle_state = 'RETIRING'
                  AND thingsboard_device_id = $3
                RETURNING 1
                """,
                context["tenant_id"], context["id"], context["thingsboard_device_id"],
            )
            if updated != 1:
                raise LifecycleError("device_retirement_state_conflict", retryable=False)
            await connection.execute(
                """
                UPDATE smart_alarm.device_activation_grants
                SET status = 'REVOKED', updated_at = clock_timestamp()
                WHERE tenant_id = $1 AND device_id = $2 AND status <> 'REVOKED'
                """,
                context["tenant_id"], context["id"],
            )
            await connection.execute(
                """
                DELETE FROM smart_alarm.entity_relations
                WHERE tenant_id = $1 AND to_type = 'DEVICE' AND to_id = $2
                  AND relation_type = 'Contains'
                """,
                context["tenant_id"], context["id"],
            )
            row = await _device_row(connection, context["tenant_id"], context["device_uid"])
            result = {
                "operationId": str(context["operation_id"]),
                "kind": "retire",
                "status": "SUCCEEDED",
                "result": {"device": _public_device(row)},
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

    async def _mark_failed(self, event: OutboxEvent, lifecycle: str, code: str) -> None:
        try:
            operation_id, device_id, _ = self._event_identity(event)
        except LifecycleError:
            return
        async with self._fenced_transaction(event) as connection:
            if lifecycle == "activation":
                await connection.execute(
                    """
                    UPDATE smart_alarm.devices
                    SET lifecycle_state = 'ACTIVATION_FAILED', updated_at = clock_timestamp(), version = version + 1
                    WHERE tenant_id = $1 AND id = $2 AND lifecycle_state = 'ACTIVATING'
                    """,
                    event.tenant_id, device_id,
                )
                await connection.execute(
                    """
                    UPDATE smart_alarm.device_activation_grants
                    SET status = 'REVOKED', updated_at = clock_timestamp()
                    WHERE tenant_id = $1 AND device_id = $2 AND status = 'READY'
                    """,
                    event.tenant_id, device_id,
                )
            elif lifecycle == "retirement":
                await connection.execute(
                    """
                    UPDATE smart_alarm.devices
                    SET lifecycle_state = 'RETIREMENT_FAILED', updated_at = clock_timestamp(), version = version + 1
                    WHERE tenant_id = $1 AND id = $2 AND lifecycle_state = 'RETIRING'
                    """,
                    event.tenant_id, device_id,
                )
            else:
                await connection.execute(
                    """
                    UPDATE smart_alarm.entity_relations
                    SET status = 'ERROR', updated_at = clock_timestamp(), version = version + 1
                    WHERE tenant_id = $1 AND to_type = 'DEVICE' AND to_id = $2
                      AND status IN ('PENDING_CREATE', 'PENDING_DELETE')
                    """,
                    event.tenant_id, device_id,
                )
            await connection.execute(
                """
                UPDATE smart_alarm.operations
                SET state = 'FAILED', error_code = $2,
                    result = jsonb_set(result, '{status}', to_jsonb('FAILED'::text), true)
                             || jsonb_build_object('error', jsonb_build_object('code', $2::text)),
                    finished_at = clock_timestamp(), updated_at = clock_timestamp(), version = version + 1
                WHERE id = $1 AND state = 'QUEUED'
                """,
                operation_id, code,
            )
