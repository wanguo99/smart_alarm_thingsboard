from __future__ import annotations

import unittest
from datetime import UTC, datetime
from uuid import UUID

try:
    from fastapi import APIRouter
    from smart_alarm_bff.device_routes import (
        _operation_status,
        _optional_uuid,
        _public_device,
        _public_operation,
        _retry_response,
        register_device_routes,
    )
    from smart_alarm_bff.write_routes import WriteError
except ModuleNotFoundError as exc:
    _missing_dependency = exc.name
else:
    _missing_dependency = None


@unittest.skipUnless(_missing_dependency is None, f"runtime dependency is not installed: {_missing_dependency}")
class DeviceRouteContractTest(unittest.TestCase):
    def test_device_lifecycle_paths_and_methods_are_mounted(self) -> None:
        router = APIRouter()
        register_device_routes(router, object(), object())  # type: ignore[arg-type]
        routes = {(route.path, frozenset(route.methods or set())) for route in router.routes}
        self.assertIn(("/api/v1/device-management/devices", frozenset({"POST"})), routes)
        self.assertIn(("/api/v1/device-management/devices/{device_uid}", frozenset({"PATCH"})), routes)
        self.assertIn(("/api/v1/device-management/devices/{device_uid}/retirements", frozenset({"POST"})), routes)
        self.assertIn(("/api/v1/device-management/operations", frozenset({"GET"})), routes)
        self.assertIn(("/api/v1/device-management/operations/{operation_id}/retry", frozenset({"POST"})), routes)

    def test_optional_uuid_rejects_non_string_and_invalid_values(self) -> None:
        self.assertIsNone(_optional_uuid(None, "device_uid"))
        with self.assertRaises(WriteError):
            _optional_uuid(123, "device_uid")
        with self.assertRaises(WriteError):
            _optional_uuid("not-a-uuid", "device_uid")

    def test_operation_history_exposes_only_tail_retryability(self) -> None:
        now = datetime(2026, 7, 24, tzinfo=UTC)
        row = {
            "id": UUID("11111111-1111-4111-8111-111111111111"),
            "operation_type": "device-update",
            "idempotency_key": "device-update-request",
            "resource_id": "22222222-2222-4222-8222-222222222222",
            "state": "FAILED",
            "error_code": "thingsboard_relation_create_failed",
            "parent_operation_id": None,
            "retry_operation_id": None,
            "has_newer_operation": False,
            "device_lifecycle_state": "ACTIVE",
            "result": {},
            "platform_rpc_id": None,
            "created_at": now,
            "updated_at": now,
        }
        operation = _public_operation(row)
        self.assertEqual(operation["kind"], "update")
        self.assertEqual(operation["status"], "FAILED")
        self.assertTrue(operation["retryable"])
        self.assertFalse(_public_operation({
            **row,
            "retry_operation_id": UUID("33333333-3333-4333-8333-333333333333"),
        })["retryable"])
        self.assertFalse(_public_operation({**row, "has_newer_operation": True})["retryable"])
        self.assertFalse(_public_operation({**row, "device_lifecycle_state": "RETIRED"})["retryable"])
        self.assertEqual(_operation_status("OUTCOME_UNKNOWN"), "PENDING")

    def test_command_history_exposes_cancellation_and_manual_retry_state(self) -> None:
        now = datetime(2026, 7, 24, tzinfo=UTC)
        command = _public_operation({
            "id": UUID("11111111-1111-4111-8111-111111111111"),
            "operation_type": "device-command",
            "idempotency_key": "command-request",
            "resource_id": "22222222-2222-4222-8222-222222222222",
            "state": "QUEUED",
            "error_code": None,
            "parent_operation_id": None,
            "retry_operation_id": None,
            "has_newer_operation": False,
            "device_lifecycle_state": "ACTIVE",
            "result": {"command": "ping", "platformStatus": "QUEUED"},
            "platform_rpc_id": UUID("33333333-3333-4333-8333-333333333333"),
            "created_at": now,
            "updated_at": now,
        })
        self.assertEqual(command["kind"], "command")
        self.assertTrue(command["cancellable"])

        cancellation = _public_operation({
            "id": UUID("44444444-4444-4444-8444-444444444444"),
            "operation_type": "device-command-cancel",
            "idempotency_key": "cancel-request",
            "resource_id": "22222222-2222-4222-8222-222222222222",
            "state": "FAILED",
            "error_code": "command_cancel_outcome_unknown",
            "parent_operation_id": command["operationId"],
            "retry_operation_id": None,
            "has_newer_operation": False,
            "device_lifecycle_state": "ACTIVE",
            "result": {"warning": "delivery outcome requires review"},
            "platform_rpc_id": None,
            "created_at": now,
            "updated_at": now,
        })
        self.assertEqual(cancellation["kind"], "command-cancel")
        self.assertTrue(cancellation["retryable"])
        self.assertEqual(cancellation["warning"], "delivery outcome requires review")

    def test_retry_response_keeps_queued_work_distinct_from_success(self) -> None:
        operation = {
            "id": UUID("11111111-1111-4111-8111-111111111111"),
            "state": "QUEUED",
            "error_code": None,
        }
        device = {
            "id": UUID("22222222-2222-4222-8222-222222222222"),
            "device_uid": UUID("33333333-3333-4333-8333-333333333333"),
            "serial_number": "SIM-000003",
            "technical_name": "sad-device",
            "display_name": "Lobby",
            "lifecycle_state": "ACTIVE",
            "customer_id": None,
            "asset_id": None,
            "business_group_id": None,
            "device_profile_id": UUID("44444444-4444-4444-8444-444444444444"),
            "profile_name": "Default",
            "credential_version": 1,
            "thingsboard_device_id": UUID("55555555-5555-4555-8555-555555555555"),
            "retired_at": None,
        }
        response = _retry_response(operation, device)
        self.assertEqual(response["status"], "QUEUED")
        self.assertEqual(response["result"]["device"]["deviceUid"], str(device["device_uid"]))
        self.assertFalse(_public_device(device)["active"])


if __name__ == "__main__":
    unittest.main()
