from __future__ import annotations

import asyncio
import json
import unittest
from uuid import UUID

import httpx

from smart_alarm_bff.thingsboard_admin import PlatformAdminError, ServiceIdentity, ThingsBoardAdminClient


TENANT_ID = UUID("11111111-1111-4111-8111-111111111111")
USER_ID = UUID("22222222-2222-4222-8222-222222222222")
PROFILE_ID = UUID("33333333-3333-4333-8333-333333333333")
DEVICE_UID = UUID("44444444-4444-4444-8444-444444444444")
DEVICE_ID = UUID("55555555-5555-4555-8555-555555555555")
CUSTOMER_ID = UUID("66666666-6666-4666-8666-666666666666")
ASSET_ID = UUID("77777777-7777-4777-8777-777777777777")


def entity(entity_id: UUID, entity_type: str) -> dict[str, str]:
    return {"id": str(entity_id), "entityType": entity_type}


def user_payload(*, authority: str = "TENANT_ADMIN", tenant_id: UUID = TENANT_ID) -> dict[str, object]:
    return {
        "id": entity(USER_ID, "USER"),
        "tenantId": entity(tenant_id, "TENANT"),
        "customerId": entity(UUID(int=0), "CUSTOMER"),
        "email": "service@example.com",
        "authority": authority,
    }


def device_payload(name: str = "stc-device") -> dict[str, object]:
    return {
        "id": entity(DEVICE_ID, "DEVICE"),
        "name": name,
        "label": "Lobby",
        "additionalInfo": {"smartAlarmDeviceUid": str(DEVICE_UID)},
    }


class ThingsBoardAdminClientTest(unittest.TestCase):
    @staticmethod
    def execute_scenario(handler, scenario):  # type: ignore[no-untyped-def]
        async def execute():  # type: ignore[no-untyped-def]
            transport = httpx.MockTransport(handler)
            async with httpx.AsyncClient(base_url="https://tb.example.com", transport=transport) as http:
                client = ThingsBoardAdminClient("https://tb.example.com", "/unused-ca", client=http)
                return await scenario(client)

        return asyncio.run(execute())

    def test_service_login_verifies_tenant_admin_scope(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.url.path == "/api/auth/login":
                self.assertEqual(json.loads(request.content), {
                    "username": "service@example.com",
                    "password": "not-a-real-password",
                })
                return httpx.Response(200, json={"token": "service.jwt", "refreshToken": "refresh.jwt"})
            self.assertEqual(request.headers["X-Authorization"], "Bearer service.jwt")
            return httpx.Response(200, json=user_payload())

        identity = ServiceIdentity.from_json(
            b'{"schemaVersion":1,"username":"service@example.com","password":"not-a-real-password"}'
        )
        session = self.execute_scenario(handler, lambda client: client.login(identity, TENANT_ID))
        self.assertEqual(session.user.tenant_id, TENANT_ID)
        self.assertEqual([request.url.path for request in requests], ["/api/auth/login", "/api/auth/user"])

    def test_service_login_rejects_wrong_authority_or_tenant(self) -> None:
        identity = ServiceIdentity("service@example.com", "not-a-real-password")

        for payload in (user_payload(authority="CUSTOMER_USER"), user_payload(tenant_id=UUID(int=9))):
            def handler(request: httpx.Request, response_payload=payload) -> httpx.Response:  # type: ignore[no-untyped-def]
                if request.url.path == "/api/auth/login":
                    return httpx.Response(200, json={"token": "service.jwt"})
                return httpx.Response(200, json=response_payload)

            with self.subTest(payload=payload), self.assertRaisesRegex(PlatformAdminError, "invalid_service_identity_scope"):
                self.execute_scenario(handler, lambda client: client.login(identity, TENANT_ID))

    def test_create_device_uses_official_payload_and_recovers_duplicate_response(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            self.assertEqual(request.headers["X-Authorization"], "Bearer service.jwt")
            if request.method == "POST":
                payload = json.loads(request.content)
                self.assertEqual(payload, {
                    "device": {
                        "name": "stc-device",
                        "type": "smart-alarm",
                        "label": "Lobby",
                        "deviceProfileId": entity(PROFILE_ID, "DEVICE_PROFILE"),
                        "additionalInfo": {"smartAlarmDeviceUid": str(DEVICE_UID)},
                    },
                    "credentials": {"credentialsType": "ACCESS_TOKEN", "credentialsId": "device-secret-token"},
                })
                # Official 4.3.1.3 reports duplicate device names as HTTP 400.
                return httpx.Response(400, json={"status": 400, "message": "duplicate"})
            self.assertEqual(request.url.params["deviceName"], "stc-device")
            return httpx.Response(200, json=device_payload())

        result = self.execute_scenario(handler, lambda client: client.create_device(
            "service.jwt",
            name="stc-device",
            label="Lobby",
            profile_id=PROFILE_ID,
            access_token="device-secret-token",
            device_uid=DEVICE_UID,
        ))
        self.assertEqual(result["uuid"], DEVICE_ID)
        self.assertEqual([request.url.path for request in requests], [
            "/api/device-with-credentials", "/api/tenant/devices",
        ])

    def test_duplicate_name_bound_to_another_inventory_device_is_rejected(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(400)
            payload = device_payload()
            payload["additionalInfo"] = {"smartAlarmDeviceUid": str(UUID(int=8))}
            return httpx.Response(200, json=payload)

        with self.assertRaisesRegex(PlatformAdminError, "thingsboard_device_identity_conflict"):
            self.execute_scenario(handler, lambda client: client.create_device(
                "service.jwt", name="stc-device", label="Lobby", profile_id=PROFILE_ID,
                access_token="device-secret-token", device_uid=DEVICE_UID,
            ))

    def test_credentials_customer_and_relation_contracts(self) -> None:
        requests: list[httpx.Request] = []
        credentials = {
            "id": entity(UUID(int=10), "DEVICE_CREDENTIALS"),
            "deviceId": entity(DEVICE_ID, "DEVICE"),
            "credentialsType": "ACCESS_TOKEN",
            "credentialsId": "old-device-token",
            "credentialsValue": None,
        }

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.method == "GET":
                return httpx.Response(200, json=credentials)
            return httpx.Response(200, json={})

        async def scenario(client: ThingsBoardAdminClient) -> None:
            saved = await client.get_credentials("service.jwt", DEVICE_ID)
            await client.rotate_credentials("service.jwt", saved, "replacement-device-token")
            await client.assign_customer("service.jwt", CUSTOMER_ID, DEVICE_ID)
            await client.unassign_customer("service.jwt", DEVICE_ID)
            await client.save_relation("service.jwt", ASSET_ID, DEVICE_ID)
            await client.delete_relation("service.jwt", ASSET_ID, DEVICE_ID)

        self.execute_scenario(handler, scenario)
        rotation = json.loads(requests[1].content)
        self.assertEqual(rotation["credentialsId"], "replacement-device-token")
        self.assertIsNone(rotation["credentialsValue"])
        self.assertEqual(requests[2].url.path, f"/api/customer/{CUSTOMER_ID}/device/{DEVICE_ID}")
        self.assertEqual(requests[3].url.path, f"/api/customer/device/{DEVICE_ID}")
        self.assertEqual(json.loads(requests[4].content)["from"], entity(ASSET_ID, "ASSET"))
        self.assertEqual(requests[5].url.params["relationTypeGroup"], "COMMON")

    def test_errors_do_not_expose_passwords_or_tokens(self) -> None:
        password = "extremely-sensitive-password"

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"message": f"rejected {password}"})

        with self.assertRaises(PlatformAdminError) as captured:
            self.execute_scenario(handler, lambda client: client.login(ServiceIdentity("service@example.com", password), TENANT_ID))
        rendered = repr(captured.exception) + str(captured.exception)
        self.assertNotIn(password, rendered)
        self.assertEqual(captured.exception.code, "service_identity_rejected")


if __name__ == "__main__":
    unittest.main()
