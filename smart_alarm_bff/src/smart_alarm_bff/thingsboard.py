"""Strict user-session validation against official ThingsBoard REST APIs."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

import httpx

from .policy import PolicyError, normalize_uuid


class ThingsBoardError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class ThingsBoardUser:
    user_id: UUID
    email: str
    authority: str
    tenant_id: UUID | None
    customer_id: UUID | None

    @classmethod
    def from_payload(cls, payload: object) -> "ThingsBoardUser":
        if not isinstance(payload, dict):
            raise PolicyError("ThingsBoard user response must be an object")
        allowed = {
            "id", "createdTime", "tenantId", "customerId", "email", "authority", "firstName", "lastName",
            "name", "additionalInfo", "phone", "version", "externalId",
        }
        if set(payload).difference(allowed):
            raise PolicyError("ThingsBoard user response contains unknown fields")
        authority = payload.get("authority")
        if authority not in {"SYS_ADMIN", "TENANT_ADMIN", "CUSTOMER_USER"}:
            raise PolicyError("ThingsBoard user authority is unsupported")
        email = payload.get("email")
        if not isinstance(email, str) or email != email.strip() or email.count("@") != 1 or len(email) > 320:
            raise PolicyError("ThingsBoard user email is invalid")
        email = email.lower()
        customer_id = normalize_uuid(payload.get("customerId"), "customerId", required=False)
        zero = UUID(int=0)
        if customer_id == zero:
            customer_id = None
        tenant_id = normalize_uuid(payload.get("tenantId"), "tenantId", required=False)
        if tenant_id == zero:
            tenant_id = None
        if (authority == "CUSTOMER_USER") != (customer_id is not None):
            raise PolicyError("ThingsBoard user customer scope is incompatible with authority")
        if authority != "SYS_ADMIN" and tenant_id is None:
            raise PolicyError("ThingsBoard user tenant scope is required for non-system authority")
        if authority == "SYS_ADMIN" and tenant_id is not None:
            raise PolicyError("ThingsBoard system user must not have tenant scope")
        user_id = normalize_uuid(payload.get("id"), "id")
        assert user_id is not None
        return cls(user_id=user_id, email=email, authority=authority, tenant_id=tenant_id, customer_id=customer_id)


class ThingsBoardClient:
    def __init__(self, base_url: str, *, verify: str | bool = True) -> None:
        self._client = httpx.AsyncClient(base_url=base_url, timeout=httpx.Timeout(5), follow_redirects=False, verify=verify)

    async def close(self) -> None:
        await self._client.aclose()

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
