"""Strict configuration for the independently deployed outbox worker."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
from typing import Mapping

from .config import (
    ConfigError,
    _COMMIT_PATTERN,
    _HOST_PATTERN,
    _https_url,
    _loopback_http_origin,
    _port,
    _readable_file,
    _required,
    read_secret,
)


_WORKER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")


def _integer(env: Mapping[str, str], name: str, minimum: int, maximum: int) -> int:
    raw = _required(env, name)
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _directory(env: Mapping[str, str], name: str) -> Path:
    path = Path(_required(env, name)).resolve()
    if not path.is_dir():
        raise ConfigError(f"{name} must reference a directory")
    return path


@dataclass(frozen=True, slots=True)
class WorkerSettings:
    environment: str
    deployment_commit: str
    worker_id: str
    thingsboard_url: str
    thingsboard_ca_file: Path | None
    database_host: str
    database_port: int
    database_name: str
    database_user: str
    database_password: bytes = field(repr=False)
    database_ca_file: Path | None
    database_tls: bool
    secret_root: Path
    device_secret_root: Path
    device_secret_key: bytes = field(repr=False)
    device_secret_key_version: int
    device_inactivity_timeout_ms: int
    batch_size: int
    poll_interval_ms: int
    lease_seconds: int
    handler_timeout_seconds: int
    max_attempts: int
    initial_backoff_seconds: int
    max_backoff_seconds: int
    metrics_port: int

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "WorkerSettings":
        source = os.environ if env is None else env
        environment = _required(source, "SMART_ALARM_ENVIRONMENT")
        local = environment == "local"
        commit = _required(source, "SMART_ALARM_DEPLOYMENT_COMMIT").lower()
        if not _COMMIT_PATTERN.fullmatch(commit):
            raise ConfigError("SMART_ALARM_DEPLOYMENT_COMMIT must be a 7..40 character lowercase Git SHA")
        worker_id = _required(source, "SMART_ALARM_WORKER_ID")
        if not _WORKER_ID.fullmatch(worker_id):
            raise ConfigError("SMART_ALARM_WORKER_ID must be a stable DNS-safe instance identifier")
        database_host = _required(source, "SMART_ALARM_DATABASE_HOST")
        if local:
            if database_host not in {"127.0.0.1", "localhost", "::1"}:
                raise ConfigError("local worker database host must be a loopback address")
        elif not _HOST_PATTERN.fullmatch(database_host):
            raise ConfigError("SMART_ALARM_DATABASE_HOST must be a DNS hostname")
        if not local and _required(source, "SMART_ALARM_DATABASE_SSLMODE") != "verify-full":
            raise ConfigError("SMART_ALARM_DATABASE_SSLMODE must be verify-full")
        lease_seconds = _integer(source, "SMART_ALARM_WORKER_LEASE_SECONDS", 10, 900)
        handler_timeout = _integer(source, "SMART_ALARM_WORKER_HANDLER_TIMEOUT_SECONDS", 1, 899)
        if handler_timeout >= lease_seconds:
            raise ConfigError("SMART_ALARM_WORKER_HANDLER_TIMEOUT_SECONDS must be lower than the lease")
        initial_backoff = _integer(source, "SMART_ALARM_WORKER_INITIAL_BACKOFF_SECONDS", 1, 3600)
        max_backoff = _integer(source, "SMART_ALARM_WORKER_MAX_BACKOFF_SECONDS", 1, 86400)
        if initial_backoff > max_backoff:
            raise ConfigError("worker initial backoff must not exceed maximum backoff")
        device_secret_key = read_secret(source, "SMART_ALARM_DEVICE_SECRET_KEY", minimum_bytes=32)
        if len(device_secret_key) != 32:
            raise ConfigError("SMART_ALARM_DEVICE_SECRET_KEY must contain exactly 32 bytes")
        return cls(
            environment=environment,
            deployment_commit=commit,
            worker_id=worker_id,
            thingsboard_url=(
                _loopback_http_origin(source, "TB_HTTP_URL") if local else _https_url(source, "TB_HTTP_URL")
            ),
            thingsboard_ca_file=None if local else _readable_file(source, "TB_HTTP_CA_FILE"),
            database_host=database_host,
            database_port=_port(source, "SMART_ALARM_DATABASE_PORT"),
            database_name=_required(source, "SMART_ALARM_DATABASE_NAME"),
            database_user=_required(source, "SMART_ALARM_WORKER_DATABASE_USER"),
            database_password=read_secret(
                source, "SMART_ALARM_WORKER_DATABASE_PASSWORD", minimum_bytes=8 if local else 16,
            ),
            database_ca_file=None if local else _readable_file(source, "SMART_ALARM_DATABASE_CA_FILE"),
            database_tls=not local,
            secret_root=_directory(source, "SMART_ALARM_WORKER_SECRET_ROOT"),
            device_secret_root=_directory(source, "SMART_ALARM_DEVICE_SECRET_ROOT"),
            device_secret_key=device_secret_key,
            device_secret_key_version=_integer(source, "SMART_ALARM_DEVICE_SECRET_KEY_VERSION", 1, 2147483647),
            device_inactivity_timeout_ms=_integer(
                source, "SMART_ALARM_DEVICE_INACTIVITY_TIMEOUT_MS", 30_000, 3_600_000,
            ),
            batch_size=_integer(source, "SMART_ALARM_WORKER_BATCH_SIZE", 1, 100),
            poll_interval_ms=_integer(source, "SMART_ALARM_WORKER_POLL_INTERVAL_MS", 100, 60000),
            lease_seconds=lease_seconds,
            handler_timeout_seconds=handler_timeout,
            max_attempts=_integer(source, "SMART_ALARM_WORKER_MAX_ATTEMPTS", 1, 100),
            initial_backoff_seconds=initial_backoff,
            max_backoff_seconds=max_backoff,
            metrics_port=_port(source, "SMART_ALARM_WORKER_METRICS_PORT"),
        )
