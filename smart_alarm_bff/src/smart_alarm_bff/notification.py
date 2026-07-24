"""Signed webhook notification delivery with PostgreSQL lease fencing."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import json
import time
from typing import Any
from uuid import UUID

import httpx
from prometheus_client import Counter, Gauge, Histogram

from .worker import DeliveryError, retry_delay
from .worker_config import WorkerSettings


NOTIFICATION_CLAIMED = Counter(
    "smart_alarm_worker_notification_claimed_total", "Claimed notification events", ("event_type",),
)
NOTIFICATION_DELIVERIES = Counter(
    "smart_alarm_worker_notification_delivery_total",
    "Notification delivery outcomes",
    ("event_type", "outcome"),
)
NOTIFICATION_LATENCY = Histogram(
    "smart_alarm_worker_notification_delivery_seconds", "Notification delivery latency", ("event_type",),
)
NOTIFICATION_IN_FLIGHT = Gauge(
    "smart_alarm_worker_notification_in_flight", "Notification events currently handled",
)


@dataclass(frozen=True, slots=True)
class NotificationEvent:
    event_id: UUID
    tenant_id: UUID
    customer_id: UUID | None
    source_operation_id: UUID | None
    event_type: str
    severity: str
    payload: dict[str, object]
    attempts: int
    lease_token: int


class WebhookNotificationSender:
    """POSTs a stable, signed event envelope without following redirects."""

    def __init__(
        self,
        url: str,
        secret: bytes,
        timeout_seconds: int,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not url or len(secret) < 32 or not 1 <= timeout_seconds <= 30:
            raise ValueError("invalid webhook notification sender configuration")
        self.url = url
        self._secret = secret
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds), follow_redirects=False,
        )
        self._owns_client = client is None

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def send(self, event: NotificationEvent) -> None:
        envelope = {
            "schemaVersion": 1,
            "eventId": str(event.event_id),
            "tenantId": str(event.tenant_id),
            "customerId": str(event.customer_id) if event.customer_id else None,
            "sourceOperationId": str(event.source_operation_id) if event.source_operation_id else None,
            "eventType": event.event_type,
            "severity": event.severity,
            "payload": event.payload,
        }
        body = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        timestamp = str(int(time.time()))
        signature = hmac.new(
            self._secret, timestamp.encode("ascii") + b"." + body, hashlib.sha256,
        ).hexdigest()
        try:
            response = await self._client.post(
                self.url,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Idempotency-Key": str(event.event_id),
                    "X-Smart-Alarm-Event-Id": str(event.event_id),
                    "X-Smart-Alarm-Timestamp": timestamp,
                    "X-Smart-Alarm-Signature": f"sha256={signature}",
                },
            )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise DeliveryError("notification_transport_unavailable") from exc
        if 200 <= response.status_code < 300:
            return
        if response.status_code == 429 or response.status_code >= 500:
            raise DeliveryError("notification_remote_retryable")
        raise DeliveryError("notification_remote_rejected", retryable=False)


class NotificationRepository:
    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def claim(self, owner: str, *, limit: int, lease_seconds: int, max_attempts: int) -> list[NotificationEvent]:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SELECT set_config('smart_alarm.system_scope', 'true', true)")
                await connection.execute(
                    """
                    UPDATE smart_alarm.notification_events
                    SET delivery_status = 'DEAD_LETTER', lease_owner = NULL, lease_expires_at = NULL,
                        last_error_code = COALESCE(last_error_code, 'worker_attempts_exhausted'),
                        updated_at = clock_timestamp()
                    WHERE delivery_status IN ('PENDING', 'LEASED') AND delivery_attempts >= $1
                      AND (delivery_status = 'PENDING' OR lease_expires_at <= clock_timestamp())
                    """,
                    max_attempts,
                )
                rows = await connection.fetch(
                    """
                    WITH candidates AS (
                        SELECT id
                        FROM smart_alarm.notification_events
                        WHERE delivery_attempts < $4
                          AND ((delivery_status = 'PENDING' AND next_attempt_at <= clock_timestamp())
                               OR (delivery_status = 'LEASED' AND lease_expires_at <= clock_timestamp()))
                        ORDER BY next_attempt_at, created_at, id
                        FOR UPDATE SKIP LOCKED
                        LIMIT $2
                    )
                    UPDATE smart_alarm.notification_events AS event
                    SET delivery_status = 'LEASED', delivery_attempts = event.delivery_attempts + 1,
                        lease_owner = $1,
                        lease_expires_at = clock_timestamp() + make_interval(secs => $3::double precision),
                        lease_token = event.lease_token + 1, last_error_code = NULL,
                        updated_at = clock_timestamp()
                    FROM candidates
                    WHERE event.id = candidates.id
                    RETURNING event.id, event.tenant_id, event.customer_id, event.source_operation_id,
                              event.event_type, event.severity, event.payload,
                              event.delivery_attempts, event.lease_token
                    """,
                    owner, limit, lease_seconds, max_attempts,
                )
        return [
            NotificationEvent(
                event_id=row["id"], tenant_id=row["tenant_id"], customer_id=row["customer_id"],
                source_operation_id=row["source_operation_id"], event_type=row["event_type"],
                severity=row["severity"], payload=row["payload"], attempts=int(row["delivery_attempts"]),
                lease_token=int(row["lease_token"]),
            )
            for row in rows
        ]

    async def delivered(self, event: NotificationEvent, owner: str) -> bool:
        return await self._finish(event, owner, "DELIVERED", None, 0)

    async def retry(self, event: NotificationEvent, owner: str, code: str, delay_seconds: int) -> bool:
        return await self._finish(event, owner, "PENDING", code, delay_seconds)

    async def dead_letter(self, event: NotificationEvent, owner: str, code: str) -> bool:
        return await self._finish(event, owner, "DEAD_LETTER", code, 0)

    async def _finish(
        self, event: NotificationEvent, owner: str, status: str, code: str | None, delay_seconds: int,
    ) -> bool:
        async with self._pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute("SELECT set_config('smart_alarm.system_scope', 'true', true)")
                result = await connection.fetchval(
                    """
                    UPDATE smart_alarm.notification_events
                    SET delivery_status = $4, lease_owner = NULL, lease_expires_at = NULL,
                        next_attempt_at = CASE WHEN $4 = 'PENDING'
                            THEN clock_timestamp() + make_interval(secs => $6::double precision)
                            ELSE next_attempt_at END,
                        last_error_code = $5,
                        delivered_at = CASE WHEN $4 = 'DELIVERED' THEN clock_timestamp() ELSE NULL END,
                        updated_at = clock_timestamp()
                    WHERE id = $1 AND delivery_status = 'LEASED' AND lease_owner = $2 AND lease_token = $3
                      AND lease_expires_at > clock_timestamp()
                    RETURNING 1
                    """,
                    event.event_id, owner, event.lease_token, status, code, delay_seconds,
                )
        return result == 1


class NotificationWorker:
    def __init__(
        self,
        settings: WorkerSettings,
        repository: NotificationRepository,
        sender: WebhookNotificationSender,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._sender = sender

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                events = await self._repository.claim(
                    self._settings.worker_id, limit=self._settings.batch_size,
                    lease_seconds=self._settings.lease_seconds, max_attempts=self._settings.max_attempts,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                await self._wait(stop)
                continue
            if not events:
                await self._wait(stop)
                continue
            results = await asyncio.gather(*(self.process(event) for event in events), return_exceptions=True)
            for result in results:
                if isinstance(result, asyncio.CancelledError):
                    raise result

    async def _wait(self, stop: asyncio.Event) -> None:
        try:
            await asyncio.wait_for(stop.wait(), self._settings.poll_interval_ms / 1000)
        except TimeoutError:
            pass

    async def process(self, event: NotificationEvent) -> None:
        NOTIFICATION_CLAIMED.labels(event.event_type).inc()
        NOTIFICATION_IN_FLIGHT.inc()
        try:
            with NOTIFICATION_LATENCY.labels(event.event_type).time():
                async with asyncio.timeout(self._settings.handler_timeout_seconds):
                    await self._sender.send(event)
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            await self._failed(event, DeliveryError("notification_handler_timeout"))
        except DeliveryError as exc:
            await self._failed(event, exc)
        except Exception as exc:
            code = f"notification_handler_{type(exc).__name__.lower()}"[:64]
            await self._failed(event, DeliveryError(code))
        else:
            fenced = await self._repository.delivered(event, self._settings.worker_id)
            NOTIFICATION_DELIVERIES.labels(event.event_type, "delivered" if fenced else "fenced").inc()
        finally:
            NOTIFICATION_IN_FLIGHT.dec()

    async def _failed(self, event: NotificationEvent, error: DeliveryError) -> None:
        if error.retryable and event.attempts < self._settings.max_attempts:
            delay = retry_delay(event.attempts, self._settings.initial_backoff_seconds, self._settings.max_backoff_seconds)
            fenced = await self._repository.retry(event, self._settings.worker_id, error.code, delay)
            outcome = "retry" if fenced else "fenced"
        else:
            fenced = await self._repository.dead_letter(event, self._settings.worker_id, error.code)
            outcome = "dead_letter" if fenced else "fenced"
        NOTIFICATION_DELIVERIES.labels(event.event_type, outcome).inc()
