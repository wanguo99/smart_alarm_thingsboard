"""External dependency lifecycle and readiness checks."""

from __future__ import annotations

import asyncio
import json
import ssl
from typing import Any

import asyncpg
import httpx
from redis.asyncio import Redis

from .config import LocalSettings, ProductionSettings
from .thingsboard import ThingsBoardClient


class Infrastructure:
    def __init__(self, settings: ProductionSettings | LocalSettings) -> None:
        self.settings = settings
        self._database_pool: asyncpg.Pool[Any] | None = None
        self._database_lock = asyncio.Lock()
        valkey_options: dict[str, object] = {
            "host": settings.valkey_host,
            "port": settings.valkey_port,
            "username": settings.valkey_username,
            "password": settings.valkey_password.decode("utf-8") if settings.valkey_password else None,
            "decode_responses": False,
            "socket_connect_timeout": 2,
            "socket_timeout": 2,
            "health_check_interval": 30,
        }
        if settings.valkey_tls:
            valkey_options.update({"ssl": True, "ssl_ca_certs": str(settings.valkey_ca_file)})
        self._valkey = Redis(**valkey_options)
        self._http = httpx.AsyncClient(timeout=httpx.Timeout(3), follow_redirects=False)
        self.thingsboard = ThingsBoardClient(
            settings.thingsboard_url,
            verify=str(settings.thingsboard_ca_file) if settings.thingsboard_ca_file else True,
        )

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
                context = ssl.create_default_context(cafile=str(self.settings.database_ca_file)) if self.settings.database_tls else None
                self._database_pool = await asyncpg.create_pool(
                    host=self.settings.database_host,
                    port=self.settings.database_port,
                    database=self.settings.database_name,
                    user=self.settings.database_user,
                    password=self.settings.database_password.decode("utf-8"),
                    ssl=context,
                    init=self._initialize_database_connection,
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

    @staticmethod
    async def _initialize_database_connection(connection: asyncpg.Connection[Any]) -> None:
        for type_name in ("json", "jsonb"):
            await connection.set_type_codec(
                type_name,
                schema="pg_catalog",
                encoder=json.dumps,
                decoder=json.loads,
                format="text",
            )

    async def readiness(self) -> dict[str, object]:
        pending = [
            self._check_database(),
            self._check_valkey(),
            self._check_http("thingsboard", f"{self.settings.thingsboard_url}/actuator/info"),
        ]
        if self.settings.oidc_readiness:
            pending.append(self._check_http("oidc", f"{self.settings.oidc_issuer}/.well-known/openid-configuration"))
        checks = await asyncio.gather(*pending)
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
