"""Independent device lifecycle worker process entry point."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import ssl
from typing import Any

import asyncpg
from prometheus_client import start_http_server

from .config import ConfigError
from .infrastructure import Infrastructure
from .lifecycle_handlers import DeviceLifecycleHandlers
from .platform_handlers import PlatformEntityHandlers
from .secret_provider import EncryptedFileSecretStore, MountedSecretProvider
from .thingsboard_admin import ThingsBoardAdminClient
from .worker import OutboxRepository, OutboxWorker
from .worker_config import WorkerSettings


LOGGER = logging.getLogger("smart_alarm_bff.worker_main")


async def run_worker(settings: WorkerSettings, stop: asyncio.Event | None = None) -> None:
    stop_event = stop or asyncio.Event()
    loop = asyncio.get_running_loop()
    installed_signals: list[signal.Signals] = []
    if stop is None:
        for item in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(item, stop_event.set)
                installed_signals.append(item)
            except NotImplementedError:
                pass

    context = ssl.create_default_context(cafile=str(settings.database_ca_file)) if settings.database_tls else None
    pool: asyncpg.Pool[Any] | None = None
    thingsboard: ThingsBoardAdminClient | None = None
    metrics_server = None
    metrics_thread = None
    try:
        metrics_server, metrics_thread = start_http_server(settings.metrics_port, addr="127.0.0.1")
        pool = await asyncpg.create_pool(
            host=settings.database_host,
            port=settings.database_port,
            database=settings.database_name,
            user=settings.database_user,
            password=settings.database_password.decode("utf-8"),
            ssl=context,
            init=Infrastructure._initialize_database_connection,
            min_size=1,
            max_size=min(20, settings.batch_size + 2),
            command_timeout=10,
            server_settings={
                "application_name": f"smart-alarm-worker:{settings.worker_id}",
                "statement_timeout": "10000",
                "idle_in_transaction_session_timeout": "15000",
            },
        )

        async def database() -> asyncpg.Pool[Any]:
            assert pool is not None
            return pool

        thingsboard = ThingsBoardAdminClient(
            settings.thingsboard_url,
            settings.thingsboard_ca_file if settings.thingsboard_ca_file is not None else True,
        )
        handlers = DeviceLifecycleHandlers(
            database,
            settings.worker_id,
            MountedSecretProvider(settings.secret_root),
            EncryptedFileSecretStore(
                settings.device_secret_root,
                settings.device_secret_key,
                settings.device_secret_key_version,
            ),
            thingsboard,
            settings.max_attempts,
        )
        platform_handlers = PlatformEntityHandlers(
            database,
            settings.worker_id,
            MountedSecretProvider(settings.secret_root),
            thingsboard,
            settings.max_attempts,
        )
        worker = OutboxWorker(
            settings,
            OutboxRepository(pool),
            {**handlers.mapping(), **platform_handlers.mapping()},
        )
        LOGGER.info("worker started", extra={"worker_id": settings.worker_id})
        await worker.run(stop_event)
        LOGGER.info("worker drained", extra={"worker_id": settings.worker_id})
    finally:
        for item in installed_signals:
            loop.remove_signal_handler(item)
        if thingsboard is not None:
            await thingsboard.close()
        if pool is not None:
            await pool.close()
        if metrics_server is not None:
            metrics_server.shutdown()
            metrics_server.server_close()
        if metrics_thread is not None:
            metrics_thread.join(timeout=5)


def run() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format=json.dumps({
            "timestamp": "%(asctime)s",
            "level": "%(levelname)s",
            "logger": "%(name)s",
            "message": "%(message)s",
        }),
    )
    try:
        settings = WorkerSettings.from_env()
        asyncio.run(run_worker(settings))
    except ConfigError as exc:
        raise SystemExit(f"invalid worker configuration: {exc}") from None


if __name__ == "__main__":
    run()
