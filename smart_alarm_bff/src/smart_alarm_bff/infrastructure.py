"""External dependency lifecycle and readiness checks."""

from __future__ import annotations

import asyncio
import ssl
from typing import Any

import asyncpg
import httpx
from redis.asyncio import Redis

from .config import ProductionSettings
from .thingsboard import ThingsBoardClient


class Infrastructure:
    def __init__(self, settings: ProductionSettings) -> None:
        self.settings = settings
        self._database_pool: asyncpg.Pool[Any] | None = None
        self._database_lock = asyncio.Lock()
        self._valkey = Redis(
            host=settings.valkey_host,
            port=settings.valkey_port,
            username=settings.valkey_username,
            password=settings.valkey_password.decode("utf-8"),
            ssl=True,
            ssl_ca_certs=str(settings.valkey_ca_file),
            decode_responses=False,
            socket_connect_timeout=2,
            socket_timeout=2,
            health_check_interval=30,
        )
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(3), follow_redirects=False)
        self.thingsboard = ThingsBoardClient(settings.thingsboard_url, verify=str(settings.thingsboard_ca_file))

    async def close(self) -> None:
        await self._http.aclose()
        await self.thingsboard.close()
        await self._valkey.aclose()
        if self._database_pool is not None:
            await self._database_pool.close()

    async def database(self) -> asyncpg.Pool[Any]:
        if self._database_pool is not None:
            return self._database_pool
        async with self._database_lock:
            if self._database_pool is None:
                context = ssl.create_default_context(cafile=str(self.settings.database_ca_file))
                self._database_pool = await asyncpg.create_pool(
                    host=self.settings.database_host,
                    port=self.settings.database_port,
                    database=self.settings.database_name,
                    user=self.settings.database_user,
                    password=self.settings.database_password.decode("utf-8"),
                    ssl=context,
                    min_size=1,
                    max_size=20,
                    command_timeout=3,
                    server_settings={
                        "application_name": "smart-alarm-bff",
                        "statement_timeout": "3000",
                        "idle_in_transaction_session_timeout": "5000",
                    },
                )
        return self._database_pool

    async def readiness(self) -> dict[str, object]:
        checks = await asyncio.gather(
            self._check_database(),
            self._check_valkey(),
            self._check_http("thingsboard", f"{self.settings.thingsboard_url}/actuator/info"),
            self._check_http("oidc", f"{self.settings.oidc_issuer}/.well-known/openid-configuration"),
        )
        dependencies = {name: status for name, status in checks}
        ready = all(value["ready"] for value in dependencies.values())
        return {"ready": ready, "status": "ready" if ready else "not_ready", "dependencies": dependencies}

    async def _check_database(self) -> tuple[str, dict[str, object]]:
        try:
            pool = await self.database()
            async with pool.acquire() as connection:
                value = await connection.fetchval("SELECT 1")
            return "postgresql", {"ready": value == 1}
        except Exception as exc:  # dependency errors are reported without their secret-bearing detail
            return "postgresql", {"ready": False, "errorType": type(exc).__name__}

    async def _check_valkey(self) -> tuple[str, dict[str, object]]:
        try:
            ready = bool(await self._valkey.ping())
            return "valkey", {"ready": ready}
        except Exception as exc:
            return "valkey", {"ready": False, "errorType": type(exc).__name__}

    async def _check_http(self, name: str, url: str) -> tuple[str, dict[str, object]]:
        try:
            response = await self._http.get(url, headers={"Accept": "application/json"})
            return name, {"ready": response.status_code == 200, "statusCode": response.status_code}
        except Exception as exc:
            return name, {"ready": False, "errorType": type(exc).__name__}
