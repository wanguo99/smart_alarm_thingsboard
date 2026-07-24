from __future__ import annotations

import asyncio
import unittest
from uuid import UUID

import httpx
from fastapi import APIRouter

from smart_alarm_bff.alarm_routes import _check_alarm_scope, register_alarm_routes
from smart_alarm_bff.thingsboard import ThingsBoardClient, ThingsBoardError


ALARM_ID = UUID("11111111-1111-4111-8111-111111111111")
DEVICE_ID = UUID("22222222-2222-4222-8222-222222222222")
OTHER_DEVICE_ID = UUID("33333333-3333-4333-8333-333333333333")


def alarm_payload() -> dict[str, object]:
    return {
        "id": {"id": str(ALARM_ID), "entityType": "ALARM"},
        "originator": {"id": str(DEVICE_ID), "entityType": "DEVICE"},
        "originatorName": "SAD-001",
        "type": "COLLISION",
        "severity": "CRITICAL",
        "createdTime": 100,
        "startTs": 100,
        "endTs": 0,
        "ackTs": 0,
        "clearTs": 0,
        "status": "ACTIVE_UNACK",
        "details": {"eventId": "sad-event-1"},
    }


class AlarmRouteContractTest(unittest.TestCase):
    def test_routes_are_mounted(self) -> None:
        router = APIRouter()
        register_alarm_routes(router, object(), object(), object())  # type: ignore[arg-type]
        self.assertEqual(
            {route.path for route in router.routes},
            {
                "/api/v1/alarms",
                "/api/v1/alarm/{alarm_id}",
                "/api/v1/alarm/{alarm_id}/ack",
                "/api/v1/alarm/{alarm_id}/clear",
            },
        )

    def test_alarm_scope_rejects_unknown_device(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "alarm_scope_mismatch"):
            _check_alarm_scope(alarm_payload(), frozenset({OTHER_DEVICE_ID}))


class ThingsBoardAlarmClientTest(unittest.TestCase):
    @staticmethod
    def execute(handler, scenario):  # type: ignore[no-untyped-def]
        async def run():  # type: ignore[no-untyped-def]
            transport = httpx.MockTransport(handler)
            async with httpx.AsyncClient(base_url="https://tb.example.com", transport=transport) as http:
                return await scenario(ThingsBoardClient("https://tb.example.com", client=http))

        return asyncio.run(run())

    def test_alarm_read_ack_clear_use_official_paths(self) -> None:
        requests: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.url.path == "/api/alarms":
                self.assertEqual(request.url.params["fetchOriginator"], "true")
                return httpx.Response(200, json={
                    "data": [alarm_payload()], "totalPages": 1, "totalElements": 1, "hasNext": False,
                })
            payload = alarm_payload()
            if request.url.path.endswith("/ack"):
                payload["ackTs"] = 200
                payload["status"] = "ACTIVE_ACK"
            if request.url.path.endswith("/clear"):
                payload["clearTs"] = 300
                payload["status"] = "CLEARED_UNACK"
            return httpx.Response(200, json=payload)

        async def scenario(client: ThingsBoardClient) -> None:
            page = await client.list_alarms(
                "platform.jwt", page=0, page_size=20, search_status="ANY",
                sort_property="createdTime", sort_order="DESC",
            )
            self.assertEqual(page["data"][0]["id"]["id"], str(ALARM_ID))
            self.assertEqual((await client.get_alarm("platform.jwt", ALARM_ID))["status"], "ACTIVE_UNACK")
            self.assertEqual((await client.acknowledge_alarm("platform.jwt", ALARM_ID))["status"], "ACTIVE_ACK")
            self.assertEqual((await client.clear_alarm("platform.jwt", ALARM_ID))["status"], "CLEARED_UNACK")

        self.execute(handler, scenario)
        self.assertEqual([request.url.path for request in requests], [
            "/api/alarms", f"/api/alarm/info/{ALARM_ID}", f"/api/alarm/{ALARM_ID}/ack", f"/api/alarm/{ALARM_ID}/clear",
        ])

    def test_alarm_response_is_strict(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            payload = alarm_payload()
            payload["unexpected"] = True
            return httpx.Response(200, json=payload)

        with self.assertRaisesRegex(ThingsBoardError, "invalid_platform_alarm_response"):
            self.execute(handler, lambda client: client.get_alarm("platform.jwt", ALARM_ID))

    def test_official_alarm_info_metadata_is_accepted_but_not_forwarded(self) -> None:
        def handler(_request: httpx.Request) -> httpx.Response:
            payload = alarm_payload()
            payload.update({
                "acknowledged": False,
                "cleared": False,
                "tenantId": {"id": str(UUID(int=4)), "entityType": "TENANT"},
                "customerId": {"id": str(UUID(int=5)), "entityType": "CUSTOMER"},
                "originatorDisplayName": "SAD-001",
                "originatorLabel": "SAD-001",
                "name": "COLLISION SAD-001",
            })
            return httpx.Response(200, json=payload)

        result = self.execute(handler, lambda client: client.get_alarm("platform.jwt", ALARM_ID))
        self.assertNotIn("tenantId", result)
        self.assertEqual(result["originatorName"], "SAD-001")


if __name__ == "__main__":
    unittest.main()
