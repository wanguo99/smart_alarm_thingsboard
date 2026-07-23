"""Device-side one-time activation grant delivery and acknowledgement."""

from __future__ import annotations

from contextlib import asynccontextmanager
import hashlib
import hmac
import re
from typing import Any, AsyncIterator, Awaitable, Callable
from uuid import UUID

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from .device_routes import _device_row, _public_device
from .secret_provider import EncryptedFileSecretStore, SecretReferenceError


_SERIAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{5,63}$")
_CLAIM_MINIMUM = 16
_CLAIM_MAXIMUM = 512


class ActivationRequestError(ValueError):
    def __init__(self, code: str, status_code: int) -> None:
        super().__init__(code)
        self.code = code
        self.status_code = status_code


def _claim_proof(body: dict[str, object], *, acknowledgement: bool) -> tuple[str, bytes, int | None]:
    expected = {"serialNumber", "claimToken", "credentialVersion"} if acknowledgement else {"serialNumber", "claimToken"}
    if set(body) != expected:
        raise ActivationRequestError("invalid_activation_request", 400)
    serial_number = body.get("serialNumber")
    claim_token = body.get("claimToken")
    if not isinstance(serial_number, str) or not _SERIAL.fullmatch(serial_number):
        raise ActivationRequestError("invalid_activation_request", 400)
    if (
        not isinstance(claim_token, str)
        or not _CLAIM_MINIMUM <= len(claim_token) <= _CLAIM_MAXIMUM
        or any(char.isspace() for char in claim_token)
    ):
        raise ActivationRequestError("invalid_activation_request", 400)
    credential_version: int | None = None
    if acknowledgement:
        value = body.get("credentialVersion")
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ActivationRequestError("invalid_activation_request", 400)
        credential_version = value
    return serial_number, hashlib.sha256(claim_token.encode("utf-8")).digest(), credential_version


def _opaque_unavailable() -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={"error": {"code": "activation_not_available", "message": "activation is not available"}},
    )


def _error(error: ActivationRequestError) -> JSONResponse:
    return JSONResponse(
        status_code=error.status_code,
        content={"error": {"code": error.code, "message": "activation request is invalid"}},
    )


@asynccontextmanager
async def _system_connection(pool: Any) -> AsyncIterator[Any]:
    async with pool.acquire() as connection:
        async with connection.transaction():
            await connection.execute("SELECT set_config('smart_alarm.system_scope', 'true', true)")
            yield connection


def _proof_matches(row: Any, serial_number: str, claim_digest: bytes) -> bool:
    return (
        row["serial_number"] == serial_number
        and row["inventory_status"] == "CLAIMED"
        and hmac.compare_digest(bytes(row["claim_token_hash"]), claim_digest)
    )


def register_activation_routes(
    router: APIRouter,
    database: Callable[[], Awaitable[Any]],
    secret_store: EncryptedFileSecretStore,
) -> None:
    @router.post("/api/v1/device-activation/{device_uid}/grants")
    async def get_activation_grant(device_uid: str, body: dict[str, object]):
        try:
            uid = UUID(device_uid)
            serial_number, claim_digest, _ = _claim_proof(body, acknowledgement=False)
        except (ValueError, ActivationRequestError) as exc:
            if isinstance(exc, ActivationRequestError):
                return _error(exc)
            return _opaque_unavailable()

        try:
            async with _system_connection(await database()) as connection:
                row = await connection.fetchrow(
                    """
                    SELECT g.id, g.request_id, g.operation_id, g.credential_version,
                           g.credential_secret_ref, g.status, g.created_at,
                           g.expires_at <= clock_timestamp() AS expired,
                           d.id AS device_id, d.tenant_id, d.device_uid, d.lifecycle_state,
                           i.serial_number, i.claim_token_hash, i.status AS inventory_status
                    FROM smart_alarm.device_activation_grants g
                    JOIN smart_alarm.devices d
                      ON d.tenant_id = g.tenant_id AND d.id = g.device_id
                    JOIN smart_alarm.device_inventory i ON i.device_uid = d.device_uid
                    WHERE d.device_uid = $1
                    ORDER BY g.credential_version DESC
                    LIMIT 1
                    FOR UPDATE OF g
                    """,
                    uid,
                )
                if row is None or not _proof_matches(row, serial_number, claim_digest) or row["expired"]:
                    return _opaque_unavailable()
                if row["status"] == "CONSUMED" and row["lifecycle_state"] == "ACTIVE":
                    return {
                        "schemaVersion": 1,
                        "requestId": str(row["request_id"]),
                        "deviceUid": str(row["device_uid"]),
                        "credentialVersion": int(row["credential_version"]),
                        "status": "ACTIVE",
                    }
                if row["status"] != "READY" or row["lifecycle_state"] != "ACTIVATING":
                    return _opaque_unavailable()
                token = secret_store.read(row["credential_secret_ref"])
                try:
                    access_token = token.decode("ascii")
                except UnicodeDecodeError as exc:
                    raise SecretReferenceError("encrypted device credential is invalid") from exc
                if not access_token or len(access_token) > 512 or any(char.isspace() for char in access_token):
                    raise SecretReferenceError("encrypted device credential is invalid")
                await connection.execute(
                    "UPDATE smart_alarm.device_activation_grants SET delivered_at = COALESCE(delivered_at, clock_timestamp()), updated_at = clock_timestamp() WHERE id = $1",
                    row["id"],
                )
                return {
                    "schemaVersion": 1,
                    "requestId": str(row["request_id"]),
                    "deviceUid": str(row["device_uid"]),
                    "credentialVersion": int(row["credential_version"]),
                    "credentials": {"type": "ACCESS_TOKEN", "value": access_token},
                    "issuedAt": int(row["created_at"].timestamp() * 1000),
                }
        except SecretReferenceError:
            return JSONResponse(
                status_code=503,
                content={"error": {"code": "activation_temporarily_unavailable", "message": "activation is temporarily unavailable"}},
            )

    @router.post("/api/v1/device-activation/{device_uid}/grants/{request_id}/acknowledgements")
    async def acknowledge_activation(device_uid: str, request_id: str, body: dict[str, object]):
        try:
            uid, grant_request_id = UUID(device_uid), UUID(request_id)
            serial_number, claim_digest, credential_version = _claim_proof(body, acknowledgement=True)
        except (ValueError, ActivationRequestError) as exc:
            if isinstance(exc, ActivationRequestError):
                return _error(exc)
            return _opaque_unavailable()

        async with _system_connection(await database()) as connection:
            row = await connection.fetchrow(
                """
                SELECT g.id, g.request_id, g.operation_id, g.credential_version,
                       g.credential_secret_ref, g.status,
                       g.expires_at <= clock_timestamp() AS expired,
                       d.id AS device_id, d.tenant_id, d.device_uid, d.lifecycle_state,
                       d.credential_secret_ref AS device_credential_secret_ref,
                       i.serial_number, i.claim_token_hash, i.status AS inventory_status
                FROM smart_alarm.device_activation_grants g
                JOIN smart_alarm.devices d
                  ON d.tenant_id = g.tenant_id AND d.id = g.device_id
                JOIN smart_alarm.device_inventory i ON i.device_uid = d.device_uid
                WHERE d.device_uid = $1 AND g.request_id = $2
                FOR UPDATE OF g, d
                """,
                uid, grant_request_id,
            )
            if (
                row is None
                or not _proof_matches(row, serial_number, claim_digest)
                or row["expired"]
                or credential_version != int(row["credential_version"])
                or row["credential_secret_ref"] != row["device_credential_secret_ref"]
            ):
                return _opaque_unavailable()
            if row["status"] == "CONSUMED" and row["lifecycle_state"] == "ACTIVE":
                return {
                    "schemaVersion": 1,
                    "requestId": str(row["request_id"]),
                    "deviceUid": str(row["device_uid"]),
                    "credentialVersion": int(row["credential_version"]),
                    "status": "ACTIVE",
                }
            if row["status"] != "READY" or row["lifecycle_state"] != "ACTIVATING":
                return _opaque_unavailable()
            updated = await connection.fetchval(
                """
                UPDATE smart_alarm.devices
                SET lifecycle_state = 'ACTIVE', version = version + 1, updated_at = clock_timestamp()
                WHERE tenant_id = $1 AND id = $2 AND lifecycle_state = 'ACTIVATING'
                  AND credential_version = $3 AND credential_secret_ref = $4
                RETURNING 1
                """,
                row["tenant_id"], row["device_id"], credential_version, row["credential_secret_ref"],
            )
            if updated != 1:
                return _opaque_unavailable()
            await connection.execute(
                """
                UPDATE smart_alarm.device_activation_grants
                SET status = 'CONSUMED', consumed_at = clock_timestamp(), updated_at = clock_timestamp()
                WHERE id = $1 AND status = 'READY'
                """,
                row["id"],
            )
            device = await _device_row(connection, row["tenant_id"], uid)
            result = {
                "operationId": str(row["operation_id"]),
                "kind": "register",
                "status": "SUCCEEDED",
                "result": {"device": _public_device(device)},
            }
            await connection.execute(
                """
                UPDATE smart_alarm.operations
                SET state = 'SUCCEEDED', result = $2::jsonb, error_code = NULL,
                    finished_at = clock_timestamp(), updated_at = clock_timestamp(), version = version + 1
                WHERE id = $1 AND state = 'QUEUED'
                """,
                row["operation_id"], result,
            )
            return {
                "schemaVersion": 1,
                "requestId": str(row["request_id"]),
                "deviceUid": str(row["device_uid"]),
                "credentialVersion": int(row["credential_version"]),
                "status": "ACTIVE",
            }


def mount_activation_routes(
    app: Any,
    database: Callable[[], Awaitable[Any]],
    secret_store: EncryptedFileSecretStore,
) -> None:
    router = APIRouter()
    register_activation_routes(router, database, secret_store)
    app.include_router(router)
