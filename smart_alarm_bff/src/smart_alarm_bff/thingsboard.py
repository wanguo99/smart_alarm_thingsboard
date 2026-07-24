"""Strict user-session validation against official ThingsBoard REST APIs."""

from __future__ import annotations

from dataclasses import dataclass
import logging
import math
import re
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import httpx

from .policy import PolicyError, normalize_uuid


class ThingsBoardError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


_USERNAME_PATTERN = re.compile(r"^(?:[a-z0-9][a-z0-9._@-]{1,62}[a-z0-9]|\+[0-9]{3,63})$")
THINGSBOARD_NULL_UUID = UUID("13814000-1dd2-11b2-8080-808080808080")
_LOGGER = logging.getLogger(__name__)


def normalize_username(value: object) -> str:
    if not isinstance(value, str):
        raise PolicyError("ThingsBoard user username is invalid")
    normalized = value.strip().lower()
    if value != value.strip() or not _USERNAME_PATTERN.fullmatch(normalized):
        raise PolicyError("ThingsBoard user username is invalid")
    return normalized


def normalize_email(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value != value.strip() or value.count("@") != 1 or len(value) > 320:
        raise PolicyError("ThingsBoard user email is invalid")
    return value.lower()


@dataclass(frozen=True, slots=True)
class ThingsBoardUser:
    user_id: UUID
    username: str
    email: str | None
    authority: str
    tenant_id: UUID | None
    customer_id: UUID | None

    @classmethod
    def from_payload(cls, payload: object) -> "ThingsBoardUser":
        if not isinstance(payload, dict):
            raise PolicyError("ThingsBoard user response must be an object")
        allowed = {
            "id", "createdTime", "tenantId", "customerId", "email", "authority", "firstName", "lastName",
            "username", "name", "additionalInfo", "phone", "version", "externalId",
        }
        if set(payload).difference(allowed):
            raise PolicyError("ThingsBoard user response contains unknown fields")
        authority = payload.get("authority")
        if authority not in {"SYS_ADMIN", "TENANT_ADMIN", "CUSTOMER_USER"}:
            raise PolicyError("ThingsBoard user authority is unsupported")
        username = normalize_username(payload.get("username"))
        email = normalize_email(payload.get("email"))
        customer_id = normalize_uuid(payload.get("customerId"), "customerId", required=False)
        null_ids = {UUID(int=0), THINGSBOARD_NULL_UUID}
        if customer_id in null_ids:
            customer_id = None
        tenant_id = normalize_uuid(payload.get("tenantId"), "tenantId", required=False)
        if tenant_id in null_ids:
            tenant_id = None
        if (authority == "CUSTOMER_USER") != (customer_id is not None):
            raise PolicyError("ThingsBoard user customer scope is incompatible with authority")
        if authority != "SYS_ADMIN" and tenant_id is None:
            raise PolicyError("ThingsBoard user tenant scope is required for non-system authority")
        if authority == "SYS_ADMIN" and tenant_id is not None:
            raise PolicyError("ThingsBoard system user must not have tenant scope")
        user_id = normalize_uuid(payload.get("id"), "id")
        assert user_id is not None
        return cls(user_id=user_id, username=username, email=email, authority=authority, tenant_id=tenant_id, customer_id=customer_id)


class ThingsBoardClient:
    def __init__(self, base_url: str, *, verify: str | bool = True, client: httpx.AsyncClient | None = None) -> None:
        self._owned = client is None
        self._client = client or httpx.AsyncClient(
            base_url=base_url, timeout=httpx.Timeout(5), follow_redirects=False, verify=verify,
        )

    async def close(self) -> None:
        if self._owned:
            await self._client.aclose()

    async def login(self, username: str, password: str) -> str:
        normalized_username = normalize_username(username)
        if not isinstance(password, str) or not password or len(password) > 1024 or "\x00" in password:
            raise ThingsBoardError("invalid_platform_credentials", retryable=False)
        response = await self._request(
            "POST",
            "/api/auth/login",
            json={"username": normalized_username, "password": password},
        )
        if response.status_code in {400, 401, 403}:
            raise ThingsBoardError("invalid_platform_credentials", retryable=False)
        if response.status_code != 200:
            raise ThingsBoardError(
                "platform_login_unavailable",
                retryable=response.status_code >= 500 or response.status_code == 429,
            )
        try:
            payload = response.json()
            token = payload.get("token") if isinstance(payload, dict) else None
        except ValueError as exc:
            raise ThingsBoardError("invalid_platform_login_response", retryable=False) from exc
        if not isinstance(token, str) or not token or len(token) > 16_384 or any(char.isspace() for char in token):
            raise ThingsBoardError("invalid_platform_login_response", retryable=False)
        return token

    async def current_user(self, access_token: str) -> ThingsBoardUser:
        if not access_token or len(access_token) > 16_384 or any(char.isspace() for char in access_token):
            raise ThingsBoardError("invalid_platform_token", retryable=False)
        try:
            response = await self._client.get(
                "/api/auth/user",
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise ThingsBoardError("platform_identity_unavailable", retryable=True) from exc
        if response.status_code in {401, 403}:
            raise ThingsBoardError("invalid_platform_session", retryable=False)
        if response.status_code != 200:
            raise ThingsBoardError("platform_identity_unavailable", retryable=response.status_code >= 500)
        try:
            return ThingsBoardUser.from_payload(response.json())
        except (ValueError, PolicyError) as exc:
            raise ThingsBoardError("invalid_platform_identity_response", retryable=False) from exc

    async def query_device_latest(
        self,
        access_token: str,
        device_ids: tuple[UUID, ...],
        latest_values: tuple[tuple[str, str], ...],
    ) -> dict[str, object]:
        if not 1 <= len(device_ids) <= 100 or len(set(device_ids)) != len(device_ids):
            raise ThingsBoardError("invalid_platform_entity_query", retryable=False)
        requested_keys: dict[str, set[str]] = {"TIME_SERIES": set(), "ATTRIBUTE": set()}
        normalized_latest: list[dict[str, str]] = []
        for value_type, key in latest_values:
            if (
                value_type not in requested_keys
                or not key
                or len(key) > 128
                or key != key.strip()
                or key in requested_keys[value_type]
            ):
                raise ThingsBoardError("invalid_platform_entity_query", retryable=False)
            requested_keys[value_type].add(key)
            normalized_latest.append({"type": value_type, "key": key})
        if len(normalized_latest) > 100:
            raise ThingsBoardError("invalid_platform_entity_query", retryable=False)

        response = await self._authorized(
            "POST",
            "/api/entitiesQuery/find",
            access_token,
            json={
                "entityFilter": {
                    "type": "entityList",
                    "entityType": "DEVICE",
                    "entityList": [str(device_id) for device_id in device_ids],
                },
                "pageLink": {"page": 0, "pageSize": len(device_ids)},
                "entityFields": [],
                "latestValues": normalized_latest,
                "keyFilters": [],
            },
        )
        if response.status_code != 200:
            raise ThingsBoardError(
                "platform_entity_query_failed",
                retryable=response.status_code >= 500 or response.status_code == 429,
            )
        try:
            payload = response.json()
        except ValueError as exc:
            raise ThingsBoardError("invalid_platform_entity_query_response", retryable=False) from exc
        return self._normalize_entity_query(payload, device_ids, requested_keys)

    @staticmethod
    def _normalize_entity_query(
        payload: object,
        device_ids: tuple[UUID, ...],
        requested_keys: dict[str, set[str]],
    ) -> dict[str, object]:
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise ThingsBoardError("invalid_platform_entity_query_response", retryable=False)
        data = payload["data"]
        total_pages = payload.get("totalPages")
        total_elements = payload.get("totalElements")
        has_next = payload.get("hasNext")
        if (
            not isinstance(total_pages, int)
            or isinstance(total_pages, bool)
            or total_pages != (1 if data else 0)
            or not isinstance(total_elements, int)
            or isinstance(total_elements, bool)
            or total_elements != len(data)
            or len(data) > len(device_ids)
            or has_next is not False
        ):
            raise ThingsBoardError("invalid_platform_entity_query_response", retryable=False)

        allowed_ids = set(device_ids)
        response_ids: set[UUID] = set()
        normalized_data: list[dict[str, object]] = []
        for row in data:
            entity = row.get("entityId") if isinstance(row, dict) else None
            try:
                entity_id = UUID(entity.get("id")) if isinstance(entity, dict) else None
            except (TypeError, ValueError):
                entity_id = None
            if (
                entity_id is None
                or entity.get("entityType") != "DEVICE"
                or entity_id not in allowed_ids
                or entity_id in response_ids
            ):
                raise ThingsBoardError("invalid_platform_entity_query_response", retryable=False)
            response_ids.add(entity_id)
            latest = row.get("latest", {})
            if latest is None:
                latest = {}
            if not isinstance(latest, dict):
                raise ThingsBoardError("invalid_platform_entity_query_response", retryable=False)
            normalized_by_type: dict[str, dict[str, dict[str, object]]] = {}
            for value_type in ("TIME_SERIES", "ATTRIBUTE"):
                entries = latest.get(value_type)
                if entries is None:
                    continue
                if not isinstance(entries, dict):
                    raise ThingsBoardError("invalid_platform_entity_query_response", retryable=False)
                normalized_entries: dict[str, dict[str, object]] = {}
                for key, candidate in entries.items():
                    if key not in requested_keys[value_type] or not isinstance(candidate, dict):
                        raise ThingsBoardError("invalid_platform_entity_query_response", retryable=False)
                    timestamp = candidate.get("ts")
                    value = candidate.get("value")
                    if (
                        not isinstance(timestamp, int)
                        or isinstance(timestamp, bool)
                        or timestamp < 0
                        or not isinstance(value, (str, int, float, bool))
                        or isinstance(value, float) and not math.isfinite(value)
                    ):
                        raise ThingsBoardError("invalid_platform_entity_query_response", retryable=False)
                    normalized_entries[key] = {"ts": timestamp, "value": value}
                normalized_by_type[value_type] = normalized_entries
            normalized_data.append({
                "entityId": {"id": str(entity_id), "entityType": "DEVICE"},
                "latest": normalized_by_type,
            })
        return {
            "data": normalized_data,
            "totalPages": total_pages,
            "totalElements": total_elements,
            "hasNext": False,
        }

    async def create_tenant(self, access_token: str, *, name: str) -> UUID:
        self._entity_name(name, "tenant")
        response = await self._authorized(
            "POST", "/api/tenant", access_token,
            json={"title": name, "additionalInfo": {}},
        )
        if response.status_code not in {200, 201}:
            raise ThingsBoardError("platform_tenant_create_failed", retryable=response.status_code >= 500 or response.status_code == 429)
        _payload, tenant_id = self._entity_response(response, "TENANT", "invalid_platform_tenant_response")
        return tenant_id

    async def update_tenant(self, access_token: str, tenant_id: UUID, *, name: str) -> None:
        self._entity_name(name, "tenant")
        await self._rename_entity(access_token, "tenant", tenant_id, "TENANT", name)

    async def delete_tenant(self, access_token: str, tenant_id: UUID, *, missing_ok: bool = False) -> None:
        response = await self._authorized("DELETE", f"/api/tenant/{tenant_id}", access_token)
        expected = {200, 404} if missing_ok else {200}
        if response.status_code not in expected:
            raise ThingsBoardError("platform_tenant_delete_failed", retryable=response.status_code >= 500 or response.status_code == 429)

    async def create_customer(self, access_token: str, *, name: str) -> UUID:
        self._entity_name(name, "customer")
        response = await self._authorized(
            "POST", "/api/customer", access_token,
            json={"title": name, "additionalInfo": {}},
        )
        if response.status_code not in {200, 201}:
            raise ThingsBoardError("platform_customer_create_failed", retryable=response.status_code >= 500 or response.status_code == 429)
        _payload, customer_id = self._entity_response(response, "CUSTOMER", "invalid_platform_customer_response")
        return customer_id

    async def update_customer(self, access_token: str, customer_id: UUID, *, name: str) -> None:
        self._entity_name(name, "customer")
        await self._rename_entity(access_token, "customer", customer_id, "CUSTOMER", name)

    async def delete_customer(self, access_token: str, customer_id: UUID, *, missing_ok: bool = False) -> None:
        response = await self._authorized("DELETE", f"/api/customer/{customer_id}", access_token)
        expected = {200, 404} if missing_ok else {200}
        if response.status_code not in expected:
            raise ThingsBoardError("platform_customer_delete_failed", retryable=response.status_code >= 500 or response.status_code == 429)

    async def provision_user(
        self,
        access_token: str,
        *,
        username: str,
        email: str | None,
        authority: str,
        tenant_id: UUID,
        customer_id: UUID | None,
        password: str,
        enabled: bool,
    ) -> ThingsBoardUser:
        payload: dict[str, object] = {
            "username": normalize_username(username),
            "email": normalize_email(email),
            "authority": authority,
            "tenantId": {"id": str(tenant_id), "entityType": "TENANT"},
            "customerId": (
                {"id": str(customer_id), "entityType": "CUSTOMER"}
                if customer_id is not None
                else {"id": str(THINGSBOARD_NULL_UUID), "entityType": "CUSTOMER"}
            ),
            "additionalInfo": {},
        }
        response = await self._authorized(
            "POST", "/api/user", access_token, params={"sendActivationMail": "false"}, json=payload,
        )
        if response.status_code != 200:
            raise ThingsBoardError("platform_user_create_failed", retryable=response.status_code >= 500 or response.status_code == 429)
        try:
            user = ThingsBoardUser.from_payload(response.json())
        except (ValueError, PolicyError) as exc:
            raise ThingsBoardError("invalid_platform_user_response", retryable=False) from exc
        if (
            user.username != payload["username"]
            or user.email != payload["email"]
            or user.authority != authority
            or user.tenant_id != tenant_id
            or user.customer_id != customer_id
        ):
            try:
                await self.delete_user(access_token, user.user_id, missing_ok=True)
            except ThingsBoardError:
                _LOGGER.exception("failed to compensate invalid ThingsBoard user %s", user.user_id)
            raise ThingsBoardError("invalid_platform_user_scope", retryable=False)
        try:
            activation = await self._authorized(
                "GET", f"/api/user/{user.user_id}/activationLink", access_token,
                accept="text/plain",
            )
            if activation.status_code != 200:
                raise ThingsBoardError("platform_activation_link_failed", retryable=activation.status_code >= 500 or activation.status_code == 429)
            token = self._activation_token(activation.text)
            activated = await self._request(
                "POST", "/api/noauth/activate", params={"sendActivationMail": "false"},
                json={"activateToken": token, "password": password},
            )
            if activated.status_code != 200:
                raise ThingsBoardError("platform_user_activation_failed", retryable=activated.status_code >= 500 or activated.status_code == 429)
            if not enabled:
                await self.set_user_enabled(access_token, user.user_id, False)
        except Exception:
            try:
                await self.delete_user(access_token, user.user_id, missing_ok=True)
            except ThingsBoardError:
                _LOGGER.exception("failed to compensate unactivated ThingsBoard user %s", user.user_id)
            raise
        return user

    async def set_user_enabled(self, access_token: str, user_id: UUID, enabled: bool) -> None:
        response = await self._authorized(
            "POST", f"/api/user/{user_id}/userCredentialsEnabled", access_token,
            params={"userCredentialsEnabled": str(enabled).lower()},
        )
        if response.status_code != 200:
            raise ThingsBoardError("platform_user_status_failed", retryable=response.status_code >= 500 or response.status_code == 429)

    async def delete_user(self, access_token: str, user_id: UUID, *, missing_ok: bool = False) -> None:
        response = await self._authorized("DELETE", f"/api/user/{user_id}", access_token)
        expected = {200, 404} if missing_ok else {200}
        if response.status_code not in expected:
            raise ThingsBoardError("platform_user_delete_failed", retryable=response.status_code >= 500 or response.status_code == 429)

    async def _authorized(
        self,
        method: str,
        path: str,
        access_token: str,
        *,
        accept: str = "application/json",
        **kwargs: object,
    ) -> httpx.Response:
        if not access_token or len(access_token) > 16_384 or any(char.isspace() for char in access_token):
            raise ThingsBoardError("invalid_platform_token", retryable=False)
        response = await self._request(
            method, path,
            headers={"Authorization": f"Bearer {access_token}", "Accept": accept},
            **kwargs,
        )
        if response.status_code in {401, 403}:
            raise ThingsBoardError("platform_user_operation_forbidden", retryable=False)
        return response

    async def _rename_entity(
        self,
        access_token: str,
        resource: str,
        entity_id: UUID,
        entity_type: str,
        name: str,
    ) -> None:
        current = await self._authorized("GET", f"/api/{resource}/{entity_id}", access_token)
        if current.status_code != 200:
            raise ThingsBoardError(
                f"platform_{resource}_read_failed",
                retryable=current.status_code >= 500 or current.status_code == 429,
            )
        payload, current_id = self._entity_response(
            current, entity_type, f"invalid_platform_{resource}_response",
        )
        if current_id != entity_id:
            raise ThingsBoardError(f"invalid_platform_{resource}_response", retryable=False)
        payload["title"] = name
        updated = await self._authorized("POST", f"/api/{resource}", access_token, json=payload)
        if updated.status_code != 200:
            raise ThingsBoardError(
                f"platform_{resource}_update_failed",
                retryable=updated.status_code >= 500 or updated.status_code == 429,
            )
        _updated_payload, updated_id = self._entity_response(
            updated, entity_type, f"invalid_platform_{resource}_response",
        )
        if updated_id != entity_id:
            raise ThingsBoardError(f"invalid_platform_{resource}_response", retryable=False)

    @staticmethod
    def _entity_name(value: object, resource: str) -> str:
        if not isinstance(value, str) or not 1 <= len(value.strip()) <= 255 or value != value.strip():
            raise ThingsBoardError(f"invalid_platform_{resource}_name", retryable=False)
        return value

    @staticmethod
    def _entity_response(
        response: httpx.Response,
        expected_type: str,
        error_code: str,
    ) -> tuple[dict[str, object], UUID]:
        try:
            payload = response.json()
            entity = payload.get("id") if isinstance(payload, dict) else None
            raw_id = entity.get("id") if isinstance(entity, dict) else entity
            entity_type = entity.get("entityType") if isinstance(entity, dict) else expected_type
            entity_id = UUID(raw_id) if isinstance(raw_id, str) else None
        except (ValueError, TypeError):
            payload, entity_id, entity_type = None, None, None
        if not isinstance(payload, dict) or entity_id is None or entity_type != expected_type:
            raise ThingsBoardError(error_code, retryable=False)
        return dict(payload), entity_id

    async def _request(self, method: str, path: str, **kwargs: object) -> httpx.Response:
        try:
            return await self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise ThingsBoardError("platform_identity_unavailable", retryable=True) from exc

    @staticmethod
    def _activation_token(link: str) -> str:
        if not link or len(link) > 4096 or link != link.strip():
            raise ThingsBoardError("invalid_platform_activation_link", retryable=False)
        values = parse_qs(urlsplit(link).query, strict_parsing=True).get("activateToken", [])
        if len(values) != 1 or not values[0] or len(values[0]) > 1024 or any(char.isspace() for char in values[0]):
            raise ThingsBoardError("invalid_platform_activation_link", retryable=False)
        return values[0]
