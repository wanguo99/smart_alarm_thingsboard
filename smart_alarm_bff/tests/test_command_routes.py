from __future__ import annotations

from datetime import UTC, datetime
import unittest
from uuid import UUID

from fastapi import APIRouter

from smart_alarm_bff.command_routes import (
    _cancel_response,
    _command_response,
    _public_approval,
    register_command_routes,
)


class CommandRouteContractTest(unittest.TestCase):
    def test_all_command_routes_are_mounted(self) -> None:
        router = APIRouter()
        register_command_routes(router, object(), object())  # type: ignore[arg-type]
        routes = {(route.path, frozenset(route.methods or set())) for route in router.routes}
        expected = {
            ("/api/v1/device-management/devices/{device_uid}/commands", frozenset({"POST"})),
            ("/api/v1/device-management/operations/{operation_id}", frozenset({"GET"})),
            ("/api/v1/device-management/devices/{device_uid}/command-approvals", frozenset({"POST"})),
            ("/api/v1/device-management/command-approvals", frozenset({"GET"})),
            ("/api/v1/device-management/command-approvals/{approval_id}/decision", frozenset({"POST"})),
            ("/api/v1/device-management/command-batches", frozenset({"POST"})),
            ("/api/v1/device-management/command-batches/{batch_id}", frozenset({"GET"})),
            ("/api/v1/device-management/operations/{operation_id}/cancellations", frozenset({"POST"})),
            ("/api/v1/device-management/operations/{cancel_operation_id}/cancellations/retry", frozenset({"POST"})),
        }
        self.assertTrue(expected.issubset(routes))

    def test_command_and_cancellation_responses_preserve_pending_state(self) -> None:
        operation_id = UUID("11111111-1111-4111-8111-111111111111")
        row = {
            "id": operation_id,
            "state": "OUTCOME_UNKNOWN",
            "error_code": None,
            "result": {"command": "ping", "platformStatus": "SUBMISSION_UNKNOWN"},
        }
        self.assertEqual(_command_response(row)["status"], "PENDING")
        cancelled = _cancel_response({
            **row,
            "state": "SUCCEEDED",
            "result": {"commandOperationId": str(operation_id), "platformStatus": "CANCELLED"},
        })
        self.assertEqual(cancelled["kind"], "command-cancel")

    def test_approval_uses_platform_user_ids_and_explicit_timestamps(self) -> None:
        now = datetime(2026, 7, 24, tzinfo=UTC)
        approval = _public_approval({
            "id": UUID("11111111-1111-4111-8111-111111111111"),
            "device_uid": UUID("22222222-2222-4222-8222-222222222222"),
            "command_type": "reboot",
            "reason": "controlled restart",
            "requester_platform_user_id": UUID("33333333-3333-4333-8333-333333333333"),
            "decision_platform_user_id": UUID("44444444-4444-4444-8444-444444444444"),
            "status": "APPROVED",
            "decision_reason": "approved after verification",
            "created_at": now,
            "expires_at": now,
            "decided_at": now,
            "consumed_at": None,
        })
        self.assertEqual(approval["requestedBy"], "33333333-3333-4333-8333-333333333333")
        self.assertEqual(approval["status"], "APPROVED")


if __name__ == "__main__":
    unittest.main()
