"""Strict ThingsBoard 4.3.1.3 tenant-administration REST adapter."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx

from .policy import PolicyError
from .thingsboard import THINGSBOARD_NULL_UUID, ThingsBoardUser, normalize_username


class PlatformAdminError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class ServiceIdentity:
    username: str
    password: str

    @classmethod
    def from_json(cls, value: bytes) -> "ServiceIdentity":
        import json

        try:
            payload = json.loads(value)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PlatformAdminError("invalid_service_identity", retryable=False) from exc
        if not isinstance(payload, dict) or set(payload) != {"schemaVersion", "username", "password"} or payload.get("schemaVersion") != 1:
            raise PlatformAdminError("invalid_service_identity", retryable=False)
        username, password = payload.get("username"), payload.get("password")
        try:
            username = normalize_username(username)
        except PolicyError as exc:
            raise PlatformAdminError("invalid_service_identity", retryable=False)
        if not isinstance(password, str) or not 16 <= len(password) <= 1024:
            raise PlatformAdminError("invalid_service_identity", retryable=False)
        return cls(username=username, password=password)


@dataclass(frozen=True, slots=True)
class PlatformSession:
    token: str
    user: ThingsBoardUser


def _entity_uuid(payload: object) -> UUID:
    if not isinstance(payload, dict) or set(payload).difference({"id", "entityType"}) or not isinstance(payload.get("id"), str):
        raise PlatformAdminError("invalid_platform_response", retryable=False)
    try:
        return UUID(payload["id"])
    except ValueError as exc:
        raise PlatformAdminError("invalid_platform_response", retryable=False) from exc


def _device(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict) or not isinstance(payload.get("name"), str):
        raise PlatformAdminError("invalid_platform_device_response", retryable=False)
    result = dict(payload)
    result["uuid"] = _entity_uuid(payload.get("id"))
    return result


def _asset(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict) or not isinstance(payload.get("name"), str):
        raise PlatformAdminError("invalid_platform_asset_response", retryable=False)
    result = dict(payload)
    result["uuid"] = _entity_uuid(payload.get("id"))
    return result


def _profile(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict) or not isinstance(payload.get("name"), str):
        raise PlatformAdminError("invalid_platform_profile_response", retryable=False)
    result = dict(payload)
    result["uuid"] = _entity_uuid(payload.get("id"))
    return result


class ThingsBoardAdminClient:
    def __init__(self, base_url: str, ca_file: Path | str | bool, *, client: httpx.AsyncClient | None = None) -> None:
        self._owned = client is None
        verify = str(ca_file) if isinstance(ca_file, Path) else ca_file
        self._client = client or httpx.AsyncClient(
            base_url=base_url,
            verify=verify,
            timeout=httpx.Timeout(8),
            follow_redirects=False,
        )

    async def close(self) -> None:
        if self._owned:
            await self._client.aclose()

    async def login(self, identity: ServiceIdentity, expected_tenant_id: UUID) -> PlatformSession:
        response = await self._raw("POST", "/api/auth/login", json={"username": identity.username, "password": identity.password})
        if response.status_code in {401, 403}:
            raise PlatformAdminError("service_identity_rejected", retryable=True)
        self._expect(response, {200}, "service_identity_unavailable")
        try:
            payload = response.json()
        except ValueError as exc:
            raise PlatformAdminError("invalid_service_login_response", retryable=False) from exc
        if not isinstance(payload, dict) or set(payload).difference({"token", "refreshToken"}) or not isinstance(payload.get("token"), str):
            raise PlatformAdminError("invalid_service_login_response", retryable=False)
        token = payload["token"]
        if not token or len(token) > 16384 or any(char.isspace() for char in token):
            raise PlatformAdminError("invalid_service_login_response", retryable=False)
        user_response = await self._authorized("GET", "/api/auth/user", token)
        self._expect(user_response, {200}, "service_identity_unavailable")
        try:
            user = ThingsBoardUser.from_payload(user_response.json())
        except Exception as exc:
            raise PlatformAdminError("invalid_service_identity_scope", retryable=False) from exc
        if user.authority != "TENANT_ADMIN" or user.tenant_id != expected_tenant_id or user.customer_id is not None:
            raise PlatformAdminError("invalid_service_identity_scope", retryable=False)
        return PlatformSession(token=token, user=user)

    async def get_device(self, token: str, device_id: UUID) -> dict[str, object]:
        response = await self._authorized("GET", f"/api/device/{device_id}", token)
        self._expect(response, {200}, "thingsboard_device_read_failed")
        return _device(response.json())

    async def find_device_by_name(self, token: str, name: str) -> dict[str, object] | None:
        response = await self._authorized("GET", "/api/tenant/devices", token, params={"deviceName": name})
        if response.status_code == 404:
            return None
        self._expect(response, {200}, "thingsboard_device_lookup_failed")
        return _device(response.json())

    async def create_device(self, token: str, *, name: str, label: str, profile_id: UUID, access_token: str, device_uid: UUID) -> dict[str, object]:
        payload = {
            "device": {
                "name": name,
                "type": "smart-alarm",
                "label": label,
                "deviceProfileId": {"id": str(profile_id), "entityType": "DEVICE_PROFILE"},
                "additionalInfo": {"smartAlarmDeviceUid": str(device_uid)},
            },
            "credentials": {"credentialsType": "ACCESS_TOKEN", "credentialsId": access_token},
        }
        try:
            response = await self._authorized("POST", "/api/device-with-credentials", token, json=payload)
        except PlatformAdminError as exc:
            if not exc.retryable:
                raise
            existing = await self.find_device_by_name(token, name)
            if existing is not None:
                self._verify_device_uid(existing, device_uid)
                return existing
            raise
        if response.status_code != 200:
            existing = await self.find_device_by_name(token, name)
            if existing is not None:
                self._verify_device_uid(existing, device_uid)
                return existing
        self._expect(response, {200}, "thingsboard_device_create_failed")
        return _device(response.json())

    async def get_credentials(self, token: str, device_id: UUID) -> dict[str, object]:
        response = await self._authorized("GET", f"/api/device/{device_id}/credentials", token)
        self._expect(response, {200}, "thingsboard_credentials_read_failed")
        try:
            payload = response.json()
        except ValueError as exc:
            raise PlatformAdminError("invalid_platform_credentials_response", retryable=False) from exc
        if not isinstance(payload, dict) or payload.get("credentialsType") != "ACCESS_TOKEN" or not isinstance(payload.get("credentialsId"), str):
            raise PlatformAdminError("invalid_platform_credentials_response", retryable=False)
        if _entity_uuid(payload.get("deviceId")) != device_id:
            raise PlatformAdminError("invalid_platform_credentials_response", retryable=False)
        return dict(payload)

    async def rotate_credentials(self, token: str, credentials: dict[str, object], replacement: str) -> None:
        payload = dict(credentials)
        payload["credentialsType"] = "ACCESS_TOKEN"
        payload["credentialsId"] = replacement
        payload["credentialsValue"] = None
        response = await self._authorized("POST", "/api/device/credentials", token, json=payload)
        self._expect(response, {200}, "thingsboard_credential_revoke_failed")

    async def update_label(self, token: str, device: dict[str, object], label: str) -> dict[str, object]:
        payload = {key: value for key, value in device.items() if key != "uuid"}
        payload["label"] = label
        response = await self._authorized("POST", "/api/device", token, json=payload)
        self._expect(response, {200}, "thingsboard_device_update_failed")
        return _device(response.json())

    @staticmethod
    def device_customer_id(device: dict[str, object]) -> UUID | None:
        customer = device.get("customerId")
        if not isinstance(customer, dict) or customer.get("entityType") != "CUSTOMER":
            raise PlatformAdminError("invalid_platform_device_response", retryable=False)
        customer_id = _entity_uuid(customer)
        return None if customer_id in {UUID(int=0), THINGSBOARD_NULL_UUID} else customer_id

    async def assign_customer(self, token: str, customer_id: UUID, device_id: UUID) -> None:
        response = await self._authorized("POST", f"/api/customer/{customer_id}/device/{device_id}", token)
        self._expect(response, {200}, "thingsboard_customer_assignment_failed")

    async def unassign_customer(self, token: str, device_id: UUID) -> None:
        response = await self._authorized("DELETE", f"/api/customer/device/{device_id}", token)
        self._expect(response, {200}, "thingsboard_customer_unassignment_failed")

    async def save_relation(self, token: str, asset_id: UUID, device_id: UUID) -> None:
        response = await self._authorized("POST", "/api/relation", token, json={
            "from": {"id": str(asset_id), "entityType": "ASSET"},
            "to": {"id": str(device_id), "entityType": "DEVICE"},
            "type": "Contains",
            "typeGroup": "COMMON",
        })
        self._expect(response, {200}, "thingsboard_relation_create_failed")

    async def delete_relation(self, token: str, asset_id: UUID, device_id: UUID) -> None:
        response = await self._authorized("DELETE", "/api/relation", token, params={
            "fromId": str(asset_id), "fromType": "ASSET", "relationType": "Contains",
            "relationTypeGroup": "COMMON", "toId": str(device_id), "toType": "DEVICE",
        })
        if response.status_code not in {200, 404}:
            self._expect(response, {200}, "thingsboard_relation_delete_failed")

    async def create_asset(
        self,
        token: str,
        *,
        name: str,
        label: str,
        asset_type: str,
        asset_uid: UUID,
        customer_id: UUID | None,
    ) -> dict[str, object]:
        payload = {
            "name": name,
            "type": asset_type,
            "label": label,
            "additionalInfo": {"smartAlarmAssetUid": str(asset_uid)},
        }
        try:
            response = await self._authorized("POST", "/api/asset", token, json=payload)
        except PlatformAdminError as exc:
            if not exc.retryable:
                raise
            existing = await self.find_asset_by_name(token, name)
            if existing is not None:
                self.verify_asset_uid(existing, asset_uid)
                return existing
            raise
        if response.status_code != 200:
            existing = await self.find_asset_by_name(token, name)
            if existing is not None:
                self.verify_asset_uid(existing, asset_uid)
                return existing
        self._expect(response, {200}, "thingsboard_asset_create_failed")
        result = _asset(response.json())
        self.verify_asset_uid(result, asset_uid)
        if customer_id is not None:
            await self.assign_asset(token, customer_id, result["uuid"])
        return result

    async def find_asset_by_name(self, token: str, name: str) -> dict[str, object] | None:
        response = await self._authorized("GET", "/api/tenant/assets", token, params={"assetName": name})
        if response.status_code == 404:
            return None
        self._expect(response, {200}, "thingsboard_asset_lookup_failed")
        return _asset(response.json())

    async def get_asset(self, token: str, asset_id: UUID) -> dict[str, object]:
        response = await self._authorized("GET", f"/api/asset/{asset_id}", token)
        self._expect(response, {200}, "thingsboard_asset_read_failed")
        return _asset(response.json())

    async def update_asset(
        self,
        token: str,
        asset_id: UUID,
        *,
        name: str,
        label: str,
        asset_type: str,
        asset_uid: UUID,
    ) -> dict[str, object]:
        current = await self.get_asset(token, asset_id)
        self.verify_asset_uid(current, asset_uid)
        payload = {key: value for key, value in current.items() if key != "uuid"}
        payload.update({"name": name, "type": asset_type, "label": label})
        response = await self._authorized("POST", "/api/asset", token, json=payload)
        self._expect(response, {200}, "thingsboard_asset_update_failed")
        result = _asset(response.json())
        self.verify_asset_uid(result, asset_uid)
        return result

    async def assign_asset(self, token: str, customer_id: UUID, asset_id: UUID) -> None:
        response = await self._authorized("POST", f"/api/customer/{customer_id}/asset/{asset_id}", token)
        self._expect(response, {200}, "thingsboard_asset_customer_assignment_failed")

    async def unassign_asset(self, token: str, asset_id: UUID) -> None:
        response = await self._authorized("DELETE", f"/api/customer/asset/{asset_id}", token)
        if response.status_code not in {200, 404}:
            self._expect(response, {200}, "thingsboard_asset_customer_unassignment_failed")

    async def delete_asset(self, token: str, asset_id: UUID) -> None:
        response = await self._authorized("DELETE", f"/api/asset/{asset_id}", token)
        if response.status_code not in {200, 404}:
            self._expect(response, {200}, "thingsboard_asset_delete_failed")

    async def save_asset_relation(self, token: str, from_asset_id: UUID, to_asset_id: UUID) -> None:
        response = await self._authorized("POST", "/api/relation", token, json={
            "from": {"id": str(from_asset_id), "entityType": "ASSET"},
            "to": {"id": str(to_asset_id), "entityType": "ASSET"},
            "type": "Contains",
            "typeGroup": "COMMON",
        })
        self._expect(response, {200}, "thingsboard_asset_relation_create_failed")

    async def delete_asset_relation(self, token: str, from_asset_id: UUID, to_asset_id: UUID) -> None:
        response = await self._authorized("DELETE", "/api/relation", token, params={
            "fromId": str(from_asset_id), "fromType": "ASSET", "relationType": "Contains",
            "relationTypeGroup": "COMMON", "toId": str(to_asset_id), "toType": "ASSET",
        })
        if response.status_code not in {200, 404}:
            self._expect(response, {200}, "thingsboard_asset_relation_delete_failed")

    async def create_device_profile(
        self,
        token: str,
        *,
        name: str,
        profile_type: str,
        transport_type: str,
        profile_uid: UUID,
        is_default: bool,
    ) -> dict[str, object]:
        transport: dict[str, object] = {"type": transport_type}
        if transport_type == "MQTT":
            transport.update({
                "deviceTelemetryTopic": "v1/devices/me/telemetry",
                "deviceAttributesTopic": "v1/devices/me/attributes",
                "deviceAttributesSubscribeTopic": "v1/devices/me/attributes",
                "transportPayloadTypeConfiguration": {"transportPayloadType": "JSON"},
                "sendAckOnValidationException": False,
            })
        payload = {
            "name": name,
            "type": "DEFAULT",
            "transportType": transport_type,
            "description": f"Smart Alarm profile {profile_uid}",
            "default": is_default,
            "profileData": {
                "configuration": {"type": "DEFAULT"},
                "transportConfiguration": transport,
                "provisionConfiguration": {"type": "DISABLED", "provisionDeviceSecret": None},
                "alarms": [],
            },
        }
        response = await self._authorized("POST", "/api/deviceProfile", token, json=payload)
        if response.status_code != 200:
            existing = await self.find_device_profile_by_name(token, name)
            if existing is not None:
                self.verify_profile_uid(existing, profile_uid)
                return existing
        self._expect(response, {200}, "thingsboard_profile_create_failed")
        result = _profile(response.json())
        self.verify_profile_uid(result, profile_uid)
        return result

    async def find_device_profile_by_name(self, token: str, name: str) -> dict[str, object] | None:
        response = await self._authorized("GET", "/api/deviceProfiles", token, params={
            "pageSize": 100, "page": 0, "textSearch": name, "sortProperty": "name", "sortOrder": "ASC",
        })
        self._expect(response, {200}, "thingsboard_profile_lookup_failed")
        try:
            payload = response.json()
            rows = payload["data"] if isinstance(payload, dict) else None
        except (ValueError, KeyError, TypeError) as exc:
            raise PlatformAdminError("invalid_platform_profile_list_response", retryable=False) from exc
        if not isinstance(rows, list):
            raise PlatformAdminError("invalid_platform_profile_list_response", retryable=False)
        for row in rows:
            if isinstance(row, dict) and row.get("name") == name:
                return _profile(row)
        return None

    async def get_device_profile(self, token: str, profile_id: UUID) -> dict[str, object]:
        response = await self._authorized("GET", f"/api/deviceProfile/{profile_id}", token)
        self._expect(response, {200}, "thingsboard_profile_read_failed")
        return _profile(response.json())

    async def update_device_profile(
        self,
        token: str,
        profile_id: UUID,
        *,
        name: str,
        profile_type: str,
        transport_type: str,
        profile_uid: UUID,
        is_default: bool,
    ) -> dict[str, object]:
        current = await self.get_device_profile(token, profile_id)
        self.verify_profile_uid(current, profile_uid)
        payload = {key: value for key, value in current.items() if key != "uuid"}
        payload.update({"name": name, "type": "DEFAULT", "transportType": transport_type, "default": is_default})
        response = await self._authorized("POST", "/api/deviceProfile", token, json=payload)
        self._expect(response, {200}, "thingsboard_profile_update_failed")
        result = _profile(response.json())
        self.verify_profile_uid(result, profile_uid)
        return result

    async def set_default_device_profile(self, token: str, profile_id: UUID, profile_uid: UUID) -> None:
        current = await self.get_device_profile(token, profile_id)
        self.verify_profile_uid(current, profile_uid)
        response = await self._authorized("POST", f"/api/deviceProfile/{profile_id}/default", token)
        self._expect(response, {200}, "thingsboard_profile_default_failed")

    async def delete_device_profile(self, token: str, profile_id: UUID) -> None:
        response = await self._authorized("DELETE", f"/api/deviceProfile/{profile_id}", token)
        if response.status_code not in {200, 404}:
            self._expect(response, {200}, "thingsboard_profile_delete_failed")

    @staticmethod
    def verify_asset_uid(asset: dict[str, object], expected: UUID) -> None:
        additional_info = asset.get("additionalInfo")
        if not isinstance(additional_info, dict) or additional_info.get("smartAlarmAssetUid") != str(expected):
            raise PlatformAdminError("thingsboard_asset_identity_conflict", retryable=False)

    @staticmethod
    def verify_profile_uid(profile: dict[str, object], expected: UUID) -> None:
        description = profile.get("description")
        if description != f"Smart Alarm profile {expected}":
            raise PlatformAdminError("thingsboard_profile_identity_conflict", retryable=False)

    async def delete_device(self, token: str, device_id: UUID) -> None:
        response = await self._authorized("DELETE", f"/api/device/{device_id}", token)
        if response.status_code not in {200, 404}:
            self._expect(response, {200}, "thingsboard_device_delete_failed")

    @staticmethod
    def verify_device_uid(device: dict[str, object], expected: UUID) -> None:
        ThingsBoardAdminClient._verify_device_uid(device, expected)

    @staticmethod
    def _verify_device_uid(device: dict[str, object], expected: UUID) -> None:
        additional_info = device.get("additionalInfo")
        if not isinstance(additional_info, dict) or additional_info.get("smartAlarmDeviceUid") != str(expected):
            raise PlatformAdminError("thingsboard_device_identity_conflict", retryable=False)

    async def _authorized(self, method: str, path: str, token: str, **kwargs: Any) -> httpx.Response:
        response = await self._raw(method, path, headers={"X-Authorization": f"Bearer {token}", "Accept": "application/json"}, **kwargs)
        if response.status_code in {401, 403}:
            raise PlatformAdminError("service_session_rejected", retryable=True)
        return response

    async def _raw(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        try:
            return await self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise PlatformAdminError("thingsboard_unavailable", retryable=True) from exc

    @staticmethod
    def _expect(response: httpx.Response, expected: set[int], code: str) -> None:
        if response.status_code not in expected:
            raise PlatformAdminError(code, retryable=response.status_code >= 500 or response.status_code == 429)
