from __future__ import annotations

import asyncio
from dataclasses import replace
from unittest.mock import AsyncMock
import unittest
from uuid import UUID

from smart_alarm_bff.platform_handlers import (
    ASSET_SYNC_EVENT,
    PROFILE_SYNC_EVENT,
    PlatformEntityHandlers,
    PlatformSyncError,
)
from smart_alarm_bff.thingsboard_admin import PlatformAdminError
from smart_alarm_bff.worker import DeliveryError, OutboxEvent


class PlatformEntityHandlerContractTest(unittest.TestCase):
    @staticmethod
    def event(aggregate_type: str = "ASSET", event_type: str = ASSET_SYNC_EVENT) -> OutboxEvent:
        return OutboxEvent(
            event_id=UUID("11111111-1111-4111-8111-111111111111"),
            tenant_id=UUID("22222222-2222-4222-8222-222222222222"),
            aggregate_type=aggregate_type,
            aggregate_id="33333333-3333-4333-8333-333333333333",
            event_type=event_type,
            payload={"operationId": "44444444-4444-4444-8444-444444444444"},
            attempts=1,
            lease_token=7,
        )

    @staticmethod
    def handlers(max_attempts: int = 8) -> PlatformEntityHandlers:
        return PlatformEntityHandlers(
            object(), "worker-1", object(), object(), max_attempts=max_attempts,  # type: ignore[arg-type]
        )

    def test_registers_only_supported_platform_entity_events(self) -> None:
        self.assertEqual(set(self.handlers().mapping()), {ASSET_SYNC_EVENT, PROFILE_SYNC_EVENT})

    def test_event_identity_requires_expected_aggregate_type(self) -> None:
        operation_id, aggregate_id = self.handlers()._identity(self.event(), "ASSET")
        self.assertEqual(str(operation_id), "44444444-4444-4444-8444-444444444444")
        self.assertEqual(str(aggregate_id), "33333333-3333-4333-8333-333333333333")
        with self.assertRaises(PlatformSyncError):
            self.handlers()._identity(self.event(), "DEVICE_PROFILE")

    def test_exhausted_retry_marks_platform_entity_before_dead_letter(self) -> None:
        async def scenario() -> tuple[DeliveryError, AsyncMock]:
            handlers = self.handlers(max_attempts=3)
            failed = AsyncMock()
            handlers._mark_failed = failed  # type: ignore[method-assign]

            async def implementation(_event: OutboxEvent) -> None:
                raise PlatformAdminError("thingsboard_unavailable", retryable=True)

            try:
                await handlers._run(replace(self.event(), attempts=3), "asset", implementation)
            except DeliveryError as error:
                return error, failed
            raise AssertionError("delivery error was not raised")

        error, failed = asyncio.run(scenario())
        self.assertFalse(error.retryable)
        self.assertEqual(error.code, "thingsboard_unavailable")
        failed.assert_awaited_once()

    def test_handler_rejects_invalid_attempt_limit(self) -> None:
        with self.assertRaisesRegex(ValueError, "max_attempts must be positive"):
            self.handlers(max_attempts=0)


if __name__ == "__main__":
    unittest.main()
