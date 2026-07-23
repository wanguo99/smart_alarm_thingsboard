"""Strict production configuration with secret-file support."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import os
import re
from typing import Mapping
from urllib.parse import urlsplit


class ConfigError(ValueError):
    """Configuration is missing or unsafe for production."""


_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{7,40}$")
_HOST_PATTERN = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9.-]+(?<!-)$")
_BUCKET_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is required")
    return value


def _boolean(env: Mapping[str, str], name: str) -> bool:
    value = _required(env, name).lower()
    if value not in {"true", "false"}:
        raise ConfigError(f"{name} must be true or false")
    return value == "true"


def _port(env: Mapping[str, str], name: str) -> int:
    raw = _required(env, name)
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not 1 <= value <= 65535:
        raise ConfigError(f"{name} must be between 1 and 65535")
    return value


def _https_url(env: Mapping[str, str], name: str, *, allow_path: bool = False) -> str:
    value = _required(env, name).rstrip("/")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ConfigError(f"{name} must be an absolute HTTPS URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ConfigError(f"{name} must not contain credentials, query or fragment")
    if not allow_path and parsed.path not in {"", "/"}:
        raise ConfigError(f"{name} must be an origin without a path")
    return value


def _readable_file(env: Mapping[str, str], name: str) -> Path:
    path = Path(_required(env, name))
    if not path.is_file():
        raise ConfigError(f"{name} must reference a readable file")
    try:
        with path.open("rb") as stream:
            stream.read(1)
    except OSError as exc:
        raise ConfigError(f"{name} must reference a readable file") from exc
    return path


def read_secret(env: Mapping[str, str], name: str, *, minimum_bytes: int = 1) -> bytes:
    inline = env.get(name, "")
    file_name = env.get(f"{name}_FILE", "").strip()
    if inline and file_name:
        raise ConfigError(f"set only one of {name} and {name}_FILE")
    if file_name:
        path = Path(file_name)
        try:
            value = path.read_bytes().rstrip(b"\r\n")
        except OSError as exc:
            raise ConfigError(f"{name}_FILE must reference a readable secret file") from exc
    else:
        value = inline.encode("utf-8")
    if len(value) < minimum_bytes:
        raise ConfigError(f"{name} must contain at least {minimum_bytes} bytes")
    return value


def _origins(env: Mapping[str, str], name: str) -> tuple[str, ...]:
    values = tuple(part.strip().rstrip("/") for part in _required(env, name).split(",") if part.strip())
    if not values:
        raise ConfigError(f"{name} must contain at least one origin")
    normalized = tuple(_https_url({name: value}, name) for value in values)
    if len(set(normalized)) != len(normalized):
        raise ConfigError(f"{name} must not contain duplicate origins")
    return normalized


def _secret_https_url(env: Mapping[str, str], name: str) -> bytes:
    value = read_secret(env, name, minimum_bytes=8)
    try:
        parsed = urlsplit(value.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{name} must be a UTF-8 HTTPS URL") from exc
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ConfigError(f"{name} must be an HTTPS URL without embedded credentials or fragment")
    return value


@dataclass(frozen=True, slots=True)
class ProductionSettings:
    environment: str
    deployment_commit: str
    public_origin: str
    thingsboard_url: str
    thingsboard_ca_file: Path
    mqtt_host: str
    mqtt_port: int
    mqtt_ca_file: Path
    database_host: str
    database_port: int
    database_name: str
    database_user: str
    database_password: bytes = field(repr=False)
    database_ca_file: Path
    valkey_host: str
    valkey_port: int
    valkey_username: str
    valkey_password: bytes = field(repr=False)
    valkey_ca_file: Path
    oidc_issuer: str
    oidc_client_id: str
    oidc_client_secret: bytes = field(repr=False)
    session_key: bytes = field(repr=False)
    policy_public_key_file: Path
    allowed_origins: tuple[str, ...]
    s3_endpoint: str
    s3_region: str
    s3_ota_bucket: str
    s3_report_bucket: str
    s3_audit_bucket: str
    s3_access_key: bytes = field(repr=False)
    s3_secret_key: bytes = field(repr=False)
    smtp_host: str
    smtp_port: int
    smtp_username: str
    smtp_password: bytes = field(repr=False)
    notification_from: str
    webhook_url: bytes = field(repr=False)
    otel_exporter_endpoint: str

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ProductionSettings":
        source = os.environ if env is None else env
        environment = _required(source, "SMART_ALARM_ENVIRONMENT")
        commit = _required(source, "SMART_ALARM_DEPLOYMENT_COMMIT").lower()
        if not _COMMIT_PATTERN.fullmatch(commit):
            raise ConfigError("SMART_ALARM_DEPLOYMENT_COMMIT must be a 7..40 character lowercase Git SHA")
        public_origin = _https_url(source, "SMART_ALARM_PUBLIC_ORIGIN")
        mqtt_host = _required(source, "TB_MQTT_HOST")
        if not _HOST_PATTERN.fullmatch(mqtt_host):
            raise ConfigError("TB_MQTT_HOST must be a DNS hostname")
        if not _boolean(source, "TB_MQTT_TLS"):
            raise ConfigError("TB_MQTT_TLS must be true in production")
        if _required(source, "SMART_ALARM_DATABASE_SSLMODE") != "verify-full":
            raise ConfigError("SMART_ALARM_DATABASE_SSLMODE must be verify-full")
        if not _boolean(source, "SMART_ALARM_VALKEY_TLS"):
            raise ConfigError("SMART_ALARM_VALKEY_TLS must be true in production")
        if not _boolean(source, "SMART_ALARM_SMTP_TLS"):
            raise ConfigError("SMART_ALARM_SMTP_TLS must be true in production")
        allowed_origins = _origins(source, "SMART_ALARM_ALLOWED_ORIGINS")
        if public_origin not in allowed_origins:
            raise ConfigError("SMART_ALARM_ALLOWED_ORIGINS must include SMART_ALARM_PUBLIC_ORIGIN")
        buckets = tuple(
            _required(source, name)
            for name in ("SMART_ALARM_S3_OTA_BUCKET", "SMART_ALARM_S3_REPORT_BUCKET", "SMART_ALARM_S3_AUDIT_BUCKET")
        )
        if len(set(buckets)) != len(buckets) or any(not _BUCKET_PATTERN.fullmatch(value) for value in buckets):
            raise ConfigError("S3 bucket names must be valid and distinct")
        notification_from = _required(source, "SMART_ALARM_NOTIFICATION_FROM")
        if notification_from.count("@") != 1 or any(char.isspace() for char in notification_from):
            raise ConfigError("SMART_ALARM_NOTIFICATION_FROM must be a valid mailbox")
        return cls(
            environment=environment,
            deployment_commit=commit,
            public_origin=public_origin,
            thingsboard_url=_https_url(source, "TB_HTTP_URL"),
            thingsboard_ca_file=_readable_file(source, "TB_HTTP_CA_FILE"),
            mqtt_host=mqtt_host,
            mqtt_port=_port(source, "TB_MQTT_PORT"),
            mqtt_ca_file=_readable_file(source, "TB_MQTT_CA_FILE"),
            database_host=_required(source, "SMART_ALARM_DATABASE_HOST"),
            database_port=_port(source, "SMART_ALARM_DATABASE_PORT"),
            database_name=_required(source, "SMART_ALARM_DATABASE_NAME"),
            database_user=_required(source, "SMART_ALARM_DATABASE_USER"),
            database_password=read_secret(source, "SMART_ALARM_DATABASE_PASSWORD", minimum_bytes=16),
            database_ca_file=_readable_file(source, "SMART_ALARM_DATABASE_CA_FILE"),
            valkey_host=_required(source, "SMART_ALARM_VALKEY_HOST"),
            valkey_port=_port(source, "SMART_ALARM_VALKEY_PORT"),
            valkey_username=_required(source, "SMART_ALARM_VALKEY_USERNAME"),
            valkey_password=read_secret(source, "SMART_ALARM_VALKEY_PASSWORD", minimum_bytes=16),
            valkey_ca_file=_readable_file(source, "SMART_ALARM_VALKEY_CA_FILE"),
            oidc_issuer=_https_url(source, "SMART_ALARM_OIDC_ISSUER", allow_path=True),
            oidc_client_id=_required(source, "SMART_ALARM_OIDC_CLIENT_ID"),
            oidc_client_secret=read_secret(source, "SMART_ALARM_OIDC_CLIENT_SECRET", minimum_bytes=16),
            session_key=read_secret(source, "SMART_ALARM_SESSION_KEY", minimum_bytes=32),
            policy_public_key_file=_readable_file(source, "SMART_ALARM_POLICY_PUBLIC_KEY_FILE"),
            allowed_origins=allowed_origins,
            s3_endpoint=_https_url(source, "SMART_ALARM_S3_ENDPOINT"),
            s3_region=_required(source, "SMART_ALARM_S3_REGION"),
            s3_ota_bucket=buckets[0],
            s3_report_bucket=buckets[1],
            s3_audit_bucket=buckets[2],
            s3_access_key=read_secret(source, "SMART_ALARM_S3_ACCESS_KEY", minimum_bytes=8),
            s3_secret_key=read_secret(source, "SMART_ALARM_S3_SECRET_KEY", minimum_bytes=16),
            smtp_host=_required(source, "SMART_ALARM_SMTP_HOST"),
            smtp_port=_port(source, "SMART_ALARM_SMTP_PORT"),
            smtp_username=_required(source, "SMART_ALARM_SMTP_USERNAME"),
            smtp_password=read_secret(source, "SMART_ALARM_SMTP_PASSWORD", minimum_bytes=16),
            notification_from=notification_from,
            webhook_url=_secret_https_url(source, "SMART_ALARM_WEBHOOK_URL"),
            otel_exporter_endpoint=_https_url(source, "SMART_ALARM_OTEL_EXPORTER_ENDPOINT", allow_path=True),
        )

    def public_summary(self) -> dict[str, object]:
        return {
            "environment": self.environment,
            "deploymentCommit": self.deployment_commit,
            "publicOrigin": self.public_origin,
            "thingsboardUrl": self.thingsboard_url,
            "mqtt": {"host": self.mqtt_host, "port": self.mqtt_port, "tls": True},
            "oidcIssuer": self.oidc_issuer,
            "s3Endpoint": self.s3_endpoint,
        }


def run() -> int:
    settings = ProductionSettings.from_env()
    print(f"configuration valid for {settings.environment} at {settings.deployment_commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
