from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import unittest
from uuid import UUID

from smart_alarm_bff.command_handlers import (
    COMMAND_CANCEL_EVENT,
    COMMAND_RECONCILE_EVENT,
    COMMAND_SUBMIT_EVENT,
    COMMAND_POLICIES,
    DeviceCommandHandlers,
)
from smart_alarm_bff.thingsboard_admin import PlatformAdminError
from smart_alarm_bff.worker import DeliveryError, OutboxEvent


class FailingThingsBoard:
    def __init__(self, error: PlatformAdminError) -> None:
        self.error = error

    async def persistent_rpc(self, *_: object, **__: object) -> dict[str, object]:
        raise self.error


class ReconcileHarness(DeviceCommandHandlers):
    def __init__(self, thingsboard: FailingThingsBoard, *, max_attempts: int = 8) -> None:
        super().__init__(object(), "worker-1", object(), thingsboard, max_attempts=max_attempts)  # type: ignore[arg-type]
        self.failure: tuple[str, str] | None = None

    async def _load(self, event: OutboxEvent, expected_type: str) -> dict[str, object]:
        return {
            "id": UUID("22222222-2222-4222-8222-222222222222"),
            "operation_type": "device-command",
            "state": "QUEUED",
            "result": {"command": "ping"},
            "thingsboard_device_id": UUID("33333333-3333-4333-8333-333333333333"),
            "platform_rpc_id": UUID("44444444-4444-4444-8444-444444444444"),
            "command_expires_at": datetime.now(UTC) + timedelta(minutes=5),
        }

    async def _session(self, context: dict[str, object]):
        return type("Session", (), {"token": "service.jwt"})()

    async def _finish_failure(
        self,
        event: OutboxEvent,
        context: dict[str, object],
        code: str,
        action: str,
        platform: dict[str, object] | None = None,
    ) -> None:
        self.failure = (code, action)


def reconcile_event(attempts: int) -> OutboxEvent:
    return OutboxEvent(
        event_id=UUID("11111111-1111-4111-8111-111111111111"),
        tenant_id=UUID("55555555-5555-4555-8555-555555555555"),
        aggregate_type="DEVICE",
        aggregate_id="33333333-3333-4333-8333-333333333333",
        event_type=COMMAND_RECONCILE_EVENT,
        payload={"operationId": "22222222-2222-4222-8222-222222222222"},
        attempts=attempts,
        lease_token=1,
    )


class CommandHandlerContractTest(unittest.TestCase):
    @staticmethod
    def handlers(max_attempts: int = 8) -> DeviceCommandHandlers:
        return DeviceCommandHandlers(
            object(), "worker-1", object(), object(), max_attempts=max_attempts,  # type: ignore[arg-type]
        )

    def test_worker_registers_submission_reconciliation_and_cancellation(self) -> None:
        self.assertEqual(set(self.handlers().mapping()), {
            COMMAND_SUBMIT_EVENT,
            COMMAND_RECONCILE_EVENT,
            COMMAND_CANCEL_EVENT,
        })

    def test_command_policy_is_server_owned_and_high_risk_has_no_retry(self) -> None:
        self.assertEqual(set(COMMAND_POLICIES), {"ping", "health", "clearFaults", "reboot"})
        self.assertEqual(COMMAND_POLICIES["reboot"]["risk"], "HIGH")
        self.assertEqual(COMMAND_POLICIES["reboot"]["retries"], 0)
        self.assertEqual(COMMAND_POLICIES["ping"]["retries"], 1)

    def test_handler_rejects_invalid_attempt_limit(self) -> None:
        with self.assertRaisesRegex(ValueError, "max_attempts must be positive"):
            self.handlers(0)

    def test_reconciliation_rejects_invalid_platform_response_without_retrying(self) -> None:
        handlers = ReconcileHarness(
            FailingThingsBoard(PlatformAdminError("invalid_persistent_rpc_response", retryable=False)),
        )
        with self.assertRaises(DeliveryError) as captured:
            asyncio.run(handlers.reconcile(reconcile_event(1)))
        self.assertFalse(captured.exception.retryable)
        self.assertEqual(handlers.failure, ("invalid_persistent_rpc_response", "DEVICE_COMMAND_FAILED"))

    def test_reconciliation_converges_retryable_error_on_last_attempt(self) -> None:
        handlers = ReconcileHarness(
            FailingThingsBoard(PlatformAdminError("thingsboard_unavailable", retryable=True)),
        )
        with self.assertRaises(DeliveryError) as captured:
            asyncio.run(handlers.reconcile(reconcile_event(8)))
        self.assertFalse(captured.exception.retryable)
        self.assertEqual(handlers.failure, ("command_outcome_unknown", "DEVICE_COMMAND_FAILED"))


if __name__ == "__main__":
    unittest.main()
