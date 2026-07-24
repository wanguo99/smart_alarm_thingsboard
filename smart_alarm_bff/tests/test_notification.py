from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import unittest
from pathlib import Path
from uuid import UUID

import httpx

from smart_alarm_bff.notification import (
    NotificationEvent,
    NotificationRepository,
    NotificationWorker,
    WebhookNotificationSender,
)
from smart_alarm_bff.worker import DeliveryError
from smart_alarm_bff.worker_config import WorkerSettings


EVENT_ID = UUID("11111111-1111-4111-8111-111111111111")
TENANT_ID = UUID("22222222-2222-4222-8222-222222222222")
CUSTOMER_ID = UUID("33333333-3333-4333-8333-333333333333")
OPERATION_ID = UUID("44444444-4444-4444-8444-444444444444")
SECRET = b"s" * 32


def event(attempts: int = 1) -> NotificationEvent:
    return NotificationEvent(
        event_id=EVENT_ID,
        tenant_id=TENANT_ID,
        customer_id=CUSTOMER_ID,
        source_operation_id=OPERATION_ID,
        event_type="COMMAND_FAILED",
        severity="WARNING",
        payload={"deviceUid": "sad-1", "errorCode": "thingsboard_unavailable"},
        attempts=attempts,
        lease_token=7,
    )


def settings(max_attempts: int = 3) -> WorkerSettings:
    return WorkerSettings(
        environment="test",
        deployment_commit="abcdef1",
        worker_id="worker-1",
        thingsboard_url="https://tb.example.com",
        thingsboard_ca_file=Path("/tb-ca"),
        database_host="postgres.internal",
        database_port=5432,
        database_name="smart_alarm",
        database_user="worker",
        database_password=b"password-password",
        database_ca_file=Path("/ca"),
        database_tls=True,
        secret_root=Path("/secrets"),
        device_secret_root=Path("/device-secrets"),
        device_secret_key=b"k" * 32,
        device_secret_key_version=1,
        device_inactivity_timeout_ms=90_000,
        batch_size=10,
        poll_interval_ms=100,
        lease_seconds=30,
        handler_timeout_seconds=20,
        max_attempts=max_attempts,
        initial_backoff_seconds=2,
        max_backoff_seconds=60,
        metrics_port=9464,
    )


class WebhookNotificationSenderTest(unittest.TestCase):
    def test_posts_canonical_signed_envelope_and_idempotency_key(self) -> None:
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["headers"] = request.headers
            captured["body"] = request.content
            return httpx.Response(204)

        async def scenario() -> None:
            client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
            sender = WebhookNotificationSender("https://hooks.example.com/events", SECRET, 10, client=client)
            await sender.send(event())
            await client.aclose()

        asyncio.run(scenario())
        headers = captured["headers"]
        body = captured["body"]
        assert isinstance(headers, httpx.Headers)
        assert isinstance(body, bytes)
        self.assertEqual(headers["Idempotency-Key"], str(EVENT_ID))
        self.assertEqual(json.loads(body), {
            "schemaVersion": 1,
            "eventId": str(EVENT_ID),
            "tenantId": str(TENANT_ID),
            "customerId": str(CUSTOMER_ID),
            "sourceOperationId": str(OPERATION_ID),
            "eventType": "COMMAND_FAILED",
            "severity": "WARNING",
            "payload": {"deviceUid": "sad-1", "errorCode": "thingsboard_unavailable"},
        })
        timestamp = headers["X-Smart-Alarm-Timestamp"]
        expected = hmac.new(SECRET, timestamp.encode("ascii") + b"." + body, hashlib.sha256).hexdigest()
        self.assertEqual(headers["X-Smart-Alarm-Signature"], f"sha256={expected}")

    def test_retries_transient_responses_and_rejects_permanent_responses(self) -> None:
        async def send(status: int) -> DeliveryError:
            client = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(status)))
            sender = WebhookNotificationSender("https://hooks.example.com/events", SECRET, 10, client=client)
            try:
                await sender.send(event())
            except DeliveryError as exc:
                return exc
            finally:
                await client.aclose()
            raise AssertionError("expected delivery error")

        retryable = asyncio.run(send(503))
        permanent = asyncio.run(send(400))
        self.assertEqual(retryable.code, "notification_remote_retryable")
        self.assertTrue(retryable.retryable)
        self.assertEqual(permanent.code, "notification_remote_rejected")
        self.assertFalse(permanent.retryable)


class NotificationRepositoryTest(unittest.TestCase):
    def test_claim_uses_skip_locked_and_completion_is_fenced(self) -> None:
        class Context:
            def __init__(self, value: object) -> None:
                self.value = value

            async def __aenter__(self) -> object:
                return self.value

            async def __aexit__(self, *_args: object) -> None:
                return None

        class Connection:
            def __init__(self) -> None:
                self.statements: list[str] = []

            def transaction(self) -> Context:
                return Context(self)

            async def execute(self, statement: str, *_args: object) -> None:
                self.statements.append(statement)

            async def fetch(self, statement: str, *_args: object) -> list[dict[str, object]]:
                self.statements.append(statement)
                return [{
                    "id": EVENT_ID,
                    "tenant_id": TENANT_ID,
                    "customer_id": CUSTOMER_ID,
                    "source_operation_id": OPERATION_ID,
                    "event_type": "COMMAND_FAILED",
                    "severity": "WARNING",
                    "payload": {},
                    "delivery_attempts": 1,
                    "lease_token": 8,
                }]

            async def fetchval(self, statement: str, *_args: object) -> int:
                self.statements.append(statement)
                return 1

        class Pool:
            def __init__(self, connection: Connection) -> None:
                self.connection = connection

            def acquire(self) -> Context:
                return Context(self.connection)

        async def scenario() -> list[str]:
            connection = Connection()
            repository = NotificationRepository(Pool(connection))
            claimed = await repository.claim("worker-1", limit=10, lease_seconds=30, max_attempts=8)
            self.assertEqual(claimed[0].lease_token, 8)
            self.assertTrue(await repository.delivered(claimed[0], "worker-1"))
            return connection.statements

        statements = asyncio.run(scenario())
        self.assertTrue(any("FOR UPDATE SKIP LOCKED" in statement for statement in statements))
        self.assertTrue(any("lease_token = $3" in statement for statement in statements))
        self.assertGreaterEqual(sum("smart_alarm.system_scope" in statement for statement in statements), 2)


class NotificationWorkerTest(unittest.TestCase):
    def test_retries_transient_delivery_and_dead_letters_permanent_delivery(self) -> None:
        class Repository:
            def __init__(self) -> None:
                self.calls: list[tuple[str, object]] = []

            async def delivered(self, value: NotificationEvent, owner: str) -> bool:
                self.calls.append(("delivered", (value.lease_token, owner)))
                return True

            async def retry(self, value: NotificationEvent, owner: str, code: str, delay: int) -> bool:
                self.calls.append(("retry", (code, delay, value.lease_token, owner)))
                return True

            async def dead_letter(self, value: NotificationEvent, owner: str, code: str) -> bool:
                self.calls.append(("dead", (code, value.lease_token, owner)))
                return True

        class Sender:
            def __init__(self, error: DeliveryError | None) -> None:
                self.error = error

            async def send(self, _value: NotificationEvent) -> None:
                if self.error:
                    raise self.error

        async def scenario() -> list[tuple[str, object]]:
            repository = Repository()
            await NotificationWorker(settings(), repository, Sender(None)).process(event())  # type: ignore[arg-type]
            await NotificationWorker(settings(), repository, Sender(DeliveryError("temporary_failure"))).process(event())  # type: ignore[arg-type]
            await NotificationWorker(settings(), repository, Sender(DeliveryError("invalid_request", retryable=False))).process(event())  # type: ignore[arg-type]
            return repository.calls

        calls = asyncio.run(scenario())
        self.assertEqual([call[0] for call in calls], ["delivered", "retry", "dead"])
        self.assertEqual(calls[1][1][1], 2)  # type: ignore[index]
