from __future__ import annotations

import unittest
from uuid import UUID

from smart_alarm_bff.policy import ProductPrincipal
from smart_alarm_bff.websocket_proxy import WebSocketPolicyError, prepare_subscription, thingsboard_websocket_url


DEVICE_ID = "11111111-1111-4111-8111-111111111111"


def principal(*capabilities: str) -> ProductPrincipal:
    return ProductPrincipal(
        local_user_id=UUID("22222222-2222-4222-8222-222222222222"),
        platform_user_id=UUID("33333333-3333-4333-8333-333333333333"),
        authority="TENANT_ADMIN",
        product_role="TENANT_VIEWER",
        internal_tenant_id=UUID("44444444-4444-4444-8444-444444444444"),
        platform_tenant_id=UUID("55555555-5555-4555-8555-555555555555"),
        internal_customer_id=None,
        platform_customer_id=None,
        capabilities=frozenset(capabilities),
        policy_version=1,
        identity_version=1,
    )


def alarm_command() -> dict[str, object]:
    fields = [
        "createdTime", "startTime", "endTime", "ackTime", "clearTime",
        "originator", "type", "severity", "status", "details",
    ]
    return {
        "cmdId": 1,
        "type": "ALARM_DATA",
        "query": {
            "entityFilter": {"type": "entityType", "entityType": "DEVICE"},
            "pageLink": {"page": 0, "pageSize": 100, "timeWindow": 1, "statusList": ["ACTIVE"]},
            "entityFields": [],
            "latestValues": [],
            "keyFilters": [],
            "alarmFields": [{"type": "ALARM_FIELD", "key": key} for key in fields],
        },
    }


class WebSocketProxyTest(unittest.TestCase):
    def test_builds_upstream_url(self) -> None:
        self.assertEqual(thingsboard_websocket_url("http://127.0.0.1:6001"), "ws://127.0.0.1:6001/api/ws")
        self.assertEqual(thingsboard_websocket_url("https://tb.example.com/base"), "wss://tb.example.com/base/api/ws")

    def test_injects_server_token_and_scopes_alarm_query(self) -> None:
        prepared, local = prepare_subscription(
            {"authCmd": {"cmdId": 0, "type": "AUTH"}, "cmds": [alarm_command()]},
            platform_token="platform-token",
            principal=principal("alarms:read"),
            allowed_device_ids=frozenset({DEVICE_ID}),
        )

        self.assertEqual(prepared["authCmd"]["token"], "platform-token")
        self.assertEqual(prepared["cmds"][0]["query"]["entityFilter"], {
            "type": "entityList", "entityType": "DEVICE", "entityList": [DEVICE_ID],
        })
        self.assertEqual(local, [])

    def test_returns_empty_alarm_snapshot_when_scope_has_no_devices(self) -> None:
        prepared, local = prepare_subscription(
            {"authCmd": {"cmdId": 0, "type": "AUTH"}, "cmds": [alarm_command()]},
            platform_token="platform-token",
            principal=principal("alarms:read"),
            allowed_device_ids=frozenset(),
        )

        self.assertEqual(prepared["cmds"], [])
        self.assertEqual(local[0]["data"], {"data": []})

    def test_rejects_browser_token_and_out_of_scope_device(self) -> None:
        with self.assertRaises(WebSocketPolicyError):
            prepare_subscription(
                {"authCmd": {"cmdId": 0, "type": "AUTH", "token": "browser-token"}, "cmds": []},
                platform_token="platform-token",
                principal=principal("devices:read"),
                allowed_device_ids=frozenset({DEVICE_ID}),
            )
        with self.assertRaises(WebSocketPolicyError):
            prepare_subscription(
                {
                    "authCmd": {"cmdId": 0, "type": "AUTH"},
                    "cmds": [{
                        "cmdId": 2, "type": "TIMESERIES", "entityType": "DEVICE",
                        "entityId": "99999999-9999-4999-8999-999999999999",
                        "keys": "latitude", "unsubscribe": False,
                    }],
                },
                platform_token="platform-token",
                principal=principal("devices:read"),
                allowed_device_ids=frozenset({DEVICE_ID}),
            )


if __name__ == "__main__":
    unittest.main()
