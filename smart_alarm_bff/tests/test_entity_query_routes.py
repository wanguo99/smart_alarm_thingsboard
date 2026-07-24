from __future__ import annotations

import asyncio
import json
import unittest
from uuid import UUID

import httpx
from fastapi import APIRouter

from smart_alarm_bff.entity_query_routes import (
    EntityQueryError,
    parse_entity_query,
    register_entity_query_routes,
)
from smart_alarm_bff.thingsboard import ThingsBoardClient, ThingsBoardError


DEVICE_ID = UUID("11111111-1111-4111-8111-111111111111")
OTHER_DEVICE_ID = UUID("22222222-2222-4222-8222-222222222222")


class EntityQueryRouteContractTest(unittest.TestCase):
    def test_route_is_mounted(self) -> None:
        router = APIRouter()
        register_entity_query_routes(router, object(), object(), object())  # type: ignore[arg-type]
        self.assertIn("/api/v1/entity-query", {route.path for route in router.routes})

    def test_request_is_device_only_bounded_and_allowlisted(self) -> None:
        device_ids, latest = parse_entity_query({
            "deviceIds": [str(DEVICE_ID)],
            "latestValues": [
                {"type": "TIME_SERIES", "key": "health"},
                {"type": "ATTRIBUTE", "key": "lastActivityTime"},
            ],
        })
        self.assertEqual(device_ids, (DEVICE_ID,))
        self.assertEqual(latest[0], ("TIME_SERIES", "health"))

        invalid = (
            {"deviceIds": [str(DEVICE_ID), str(DEVICE_ID)], "latestValues": []},
            {"deviceIds": [str(DEVICE_ID)], "latestValues": [{"type": "TIME_SERIES", "key": "secret"}]},
            {"deviceIds": [str(DEVICE_ID)], "latestValues": [{"type": [], "key": "health"}]},
            {"deviceIds": [str(DEVICE_ID)], "latestValues": [], "entityFilter": {}},
        )
        for body in invalid:
            with self.subTest(body=body), self.assertRaises(EntityQueryError):
                parse_entity_query(body)


class ThingsBoardEntityQueryTest(unittest.TestCase):
    @staticmethod
    def execute(handler, scenario):  # type: ignore[no-untyped-def]
        async def run():  # type: ignore[no-untyped-def]
            transport = httpx.MockTransport(handler)
            async with httpx.AsyncClient(base_url="https://tb.example.com", transport=transport) as http:
                return await scenario(ThingsBoardClient("https://tb.example.com", client=http))

        return asyncio.run(run())

    def test_client_owns_query_shape_and_normalizes_response(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual(request.url.path, "/api/entitiesQuery/find")
            payload = json.loads(request.content)
            self.assertEqual(payload["entityFilter"], {
                "type": "entityList",
                "entityType": "DEVICE",
                "entityList": [str(DEVICE_ID)],
            })
            self.assertEqual(payload["keyFilters"], [])
            return httpx.Response(200, json={
                "data": [{
                    "entityId": {"id": str(DEVICE_ID), "entityType": "DEVICE"},
                    "latest": {
                        "TIME_SERIES": {"health": {"ts": 123, "value": "ok"}},
                        "ATTRIBUTE": {"lastActivityTime": {"ts": 124, "value": 124}},
                    },
                }],
                "totalPages": 1,
                "totalElements": 1,
                "hasNext": False,
            })

        result = self.execute(handler, lambda client: client.query_device_latest(
            "platform.jwt",
            (DEVICE_ID,),
            (("TIME_SERIES", "health"), ("ATTRIBUTE", "lastActivityTime")),
        ))
        self.assertEqual(result["data"][0]["entityId"]["id"], str(DEVICE_ID))

    def test_client_rejects_out_of_scope_rows_and_unrequested_keys(self) -> None:
        responses = (
            {
                "data": [{"entityId": {"id": str(OTHER_DEVICE_ID), "entityType": "DEVICE"}, "latest": {}}],
                "totalPages": 1, "totalElements": 1, "hasNext": False,
            },
            {
                "data": [{
                    "entityId": {"id": str(DEVICE_ID), "entityType": "DEVICE"},
                    "latest": {"TIME_SERIES": {"batteryPercent": {"ts": 1, "value": 80}}},
                }],
                "totalPages": 1, "totalElements": 1, "hasNext": False,
            },
        )
        for payload in responses:
            with self.subTest(payload=payload), self.assertRaises(ThingsBoardError):
                self.execute(
                    lambda _request, payload=payload: httpx.Response(200, json=payload),
                    lambda client: client.query_device_latest(
                        "platform.jwt", (DEVICE_ID,), (("TIME_SERIES", "health"),),
                    ),
                )


if __name__ == "__main__":
    unittest.main()
