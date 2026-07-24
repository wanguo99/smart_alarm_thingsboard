from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock
import unittest
from uuid import UUID

from smart_alarm_bff.lifecycle_handlers import (
    ACTIVATION_EVENT,
    METADATA_EVENT,
    RETIREMENT_EVENT,
    DeviceLifecycleHandlers,
    LifecycleError,
)
from smart_alarm_bff.thingsboard_admin import PlatformAdminError
from smart_alarm_bff.worker import DeliveryError, OutboxEvent


class LifecycleHandlerContractTest(unittest.TestCase):
    @staticmethod
    def event(event_type: str = ACTIVATION_EVENT) -> OutboxEvent:
        device_id = UUID("33333333-3333-4333-8333-333333333333")
        return OutboxEvent(
            event_id=UUID("11111111-1111-4111-8111-111111111111"),
            tenant_id=UUID("22222222-2222-4222-8222-222222222222"),
            aggregate_type="DEVICE",
            aggregate_id=str(device_id),
            event_type=event_type,
            payload={
                "operationId": "44444444-4444-4444-8444-444444444444",
                "deviceId": str(device_id),
                "deviceUid": "55555555-5555-4555-8555-555555555555",
            },
            attempts=1,
            lease_token=7,
        )

    @staticmethod
    def handlers() -> DeviceLifecycleHandlers:
        return DeviceLifecycleHandlers(object(), "worker-1", object(), object(), object())  # type: ignore[arg-type]

    def test_registers_only_the_three_supported_lifecycle_events(self) -> None:
        self.assertEqual(
            set(self.handlers().mapping()),
            {ACTIVATION_EVENT, METADATA_EVENT, RETIREMENT_EVENT},
        )

    def test_event_identity_requires_matching_immutable_ids(self) -> None:
        handler = self.handlers()
        operation_id, device_id, device_uid = handler._event_identity(self.event())
        self.assertEqual(str(operation_id), "44444444-4444-4444-8444-444444444444")
        self.assertEqual(str(device_id), "33333333-3333-4333-8333-333333333333")
        self.assertEqual(str(device_uid), "55555555-5555-4555-8555-555555555555")

        invalid = replace(self.event(), aggregate_id="another-device")
        with self.assertRaises(LifecycleError):
            handler._event_identity(invalid)

    def test_context_requires_platform_mappings_for_selected_entities(self) -> None:
        base = {
            "thingsboard_tenant_id": UUID("11111111-1111-4111-8111-111111111111"),
            "service_identity_secret_ref": "mounted:tenant.json",
            "thingsboard_profile_id": UUID("22222222-2222-4222-8222-222222222222"),
            "customer_id": None,
            "thingsboard_customer_id": None,
            "asset_id": None,
            "thingsboard_asset_id": None,
            "relations": [],
        }
        DeviceLifecycleHandlers._validate_context(base)
        with self.assertRaisesRegex(LifecycleError, "thingsboard_customer_mapping_missing"):
            DeviceLifecycleHandlers._validate_context({**base, "customer_id": UUID(int=1)})
        with self.assertRaisesRegex(LifecycleError, "thingsboard_asset_mapping_missing"):
            DeviceLifecycleHandlers._validate_context(
                {**base, "relations": [{"thingsboard_asset_id": None}]}
            )

    def test_permanent_platform_error_marks_business_state_before_dead_letter(self) -> None:
        async def scenario() -> tuple[DeliveryError, AsyncMock]:
            handlers = self.handlers()
            failed = AsyncMock()
            handlers._mark_failed = failed  # type: ignore[method-assign]

            async def implementation(_event: OutboxEvent) -> None:
                raise PlatformAdminError("invalid_service_identity_scope", retryable=False)

            try:
                await handlers._run(self.event(), "activation", implementation)
            except DeliveryError as error:
                return error, failed
            raise AssertionError("delivery error was not raised")

        error, failed = asyncio.run(scenario())
        self.assertFalse(error.retryable)
        self.assertEqual(error.code, "invalid_service_identity_scope")
        failed.assert_awaited_once()

    def test_retryable_platform_error_does_not_publish_terminal_state(self) -> None:
        async def scenario() -> tuple[DeliveryError, AsyncMock]:
            handlers = self.handlers()
            failed = AsyncMock()
            handlers._mark_failed = failed  # type: ignore[method-assign]

            async def implementation(_event: OutboxEvent) -> None:
                raise PlatformAdminError("thingsboard_unavailable", retryable=True)

            try:
                await handlers._run(self.event(), "activation", implementation)
            except DeliveryError as error:
                return error, failed
            raise AssertionError("delivery error was not raised")

        error, failed = asyncio.run(scenario())
        self.assertTrue(error.retryable)
        failed.assert_not_awaited()

    def test_last_retryable_attempt_publishes_terminal_business_state(self) -> None:
        async def scenario() -> tuple[DeliveryError, AsyncMock]:
            handlers = DeviceLifecycleHandlers(
                object(), "worker-1", object(), object(), object(), max_attempts=3,  # type: ignore[arg-type]
            )
            failed = AsyncMock()
            handlers._mark_failed = failed  # type: ignore[method-assign]

            async def implementation(_event: OutboxEvent) -> None:
                raise PlatformAdminError("thingsboard_unavailable", retryable=True)

            try:
                await handlers._run(replace(self.event(), attempts=3), "metadata", implementation)
            except DeliveryError as error:
                return error, failed
            raise AssertionError("delivery error was not raised")

        error, failed = asyncio.run(scenario())
        self.assertFalse(error.retryable)
        self.assertEqual(error.code, "thingsboard_unavailable")
        failed.assert_awaited_once()

    def test_handler_rejects_invalid_attempt_limit(self) -> None:
        with self.assertRaisesRegex(ValueError, "max_attempts must be positive"):
            DeviceLifecycleHandlers(
                object(), "worker-1", object(), object(), object(), max_attempts=0,  # type: ignore[arg-type]
            )

    def test_handler_rejects_invalid_device_inactivity_timeout(self) -> None:
        with self.assertRaisesRegex(ValueError, "inactivity_timeout_ms"):
            DeviceLifecycleHandlers(
                object(), "worker-1", object(), object(), object(),  # type: ignore[arg-type]
                inactivity_timeout_ms=1_000,
            )

    def test_customer_sync_skips_unassignment_when_platform_is_already_unassigned(self) -> None:
        async def scenario() -> tuple[AsyncMock, AsyncMock]:
            platform = SimpleNamespace(
                device_customer_id=lambda _device: None,
                unassign_customer=AsyncMock(),
                assign_customer=AsyncMock(),
            )
            handlers = DeviceLifecycleHandlers(
                object(), "worker-1", object(), object(), platform  # type: ignore[arg-type]
            )
            await handlers._sync_customer_assignment(
                "service.jwt",
                {"uuid": UUID("66666666-6666-4666-8666-666666666666")},
                None,
            )
            return platform.unassign_customer, platform.assign_customer

        unassign, assign = asyncio.run(scenario())
        unassign.assert_not_awaited()
        assign.assert_not_awaited()

    def test_customer_sync_only_changes_a_different_platform_assignment(self) -> None:
        async def scenario() -> tuple[AsyncMock, AsyncMock]:
            platform = SimpleNamespace(
                device_customer_id=lambda _device: UUID("77777777-7777-4777-8777-777777777777"),
                unassign_customer=AsyncMock(),
                assign_customer=AsyncMock(),
            )
            handlers = DeviceLifecycleHandlers(
                object(), "worker-1", object(), object(), platform  # type: ignore[arg-type]
            )
            device = {"uuid": UUID("66666666-6666-4666-8666-666666666666")}
            await handlers._sync_customer_assignment("service.jwt", device, None)
            await handlers._sync_customer_assignment(
                "service.jwt", device, UUID("88888888-8888-4888-8888-888888888888")
            )
            return platform.unassign_customer, platform.assign_customer

        unassign, assign = asyncio.run(scenario())
        unassign.assert_awaited_once_with(
            "service.jwt", UUID("66666666-6666-4666-8666-666666666666")
        )
        assign.assert_awaited_once_with(
            "service.jwt",
            UUID("88888888-8888-4888-8888-888888888888"),
            UUID("66666666-6666-4666-8666-666666666666"),
        )


if __name__ == "__main__":
    unittest.main()
