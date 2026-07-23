from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from smart_alarm_bff.config import ConfigError, LocalSettings, ProductionSettings, load_settings, read_secret


class ProductionSettingsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        ca = root / "ca.pem"
        ca.write_text("test-ca", encoding="utf-8")
        public_key = root / "policy.pem"
        public_key.write_text("test-public-key", encoding="utf-8")
        device_secrets = root / "device-secrets"
        device_secrets.mkdir()
        self.env = {
            "SMART_ALARM_ENVIRONMENT": "staging-cn",
            "SMART_ALARM_DEPLOYMENT_COMMIT": "0123456789abcdef",
            "SMART_ALARM_PUBLIC_ORIGIN": "https://alarm.example.com",
            "TB_HTTP_URL": "https://tb.example.com",
            "TB_HTTP_CA_FILE": str(ca),
            "TB_MQTT_HOST": "mqtt.example.com",
            "TB_MQTT_PORT": "8883",
            "TB_MQTT_TLS": "true",
            "TB_MQTT_CA_FILE": str(ca),
            "SMART_ALARM_DATABASE_HOST": "postgres.internal",
            "SMART_ALARM_DATABASE_PORT": "5432",
            "SMART_ALARM_DATABASE_NAME": "smart_alarm",
            "SMART_ALARM_DATABASE_USER": "smart_alarm_app",
            "SMART_ALARM_DATABASE_PASSWORD": "database-password-value",
            "SMART_ALARM_DATABASE_SSLMODE": "verify-full",
            "SMART_ALARM_DATABASE_CA_FILE": str(ca),
            "SMART_ALARM_VALKEY_HOST": "valkey.internal",
            "SMART_ALARM_VALKEY_PORT": "6379",
            "SMART_ALARM_VALKEY_TLS": "true",
            "SMART_ALARM_VALKEY_USERNAME": "smart_alarm_app",
            "SMART_ALARM_VALKEY_PASSWORD": "valkey-password-value",
            "SMART_ALARM_VALKEY_CA_FILE": str(ca),
            "SMART_ALARM_OIDC_ISSUER": "https://id.example.com/realms/smart-alarm",
            "SMART_ALARM_OIDC_CLIENT_ID": "smart-alarm-web",
            "SMART_ALARM_OIDC_CLIENT_SECRET": "oidc-client-secret-value",
            "SMART_ALARM_SESSION_KEY": "a" * 32,
            "SMART_ALARM_DEVICE_SECRET_ROOT": str(device_secrets),
            "SMART_ALARM_DEVICE_SECRET_KEY": "d" * 32,
            "SMART_ALARM_DEVICE_SECRET_KEY_VERSION": "1",
            "SMART_ALARM_POLICY_PUBLIC_KEY_FILE": str(public_key),
            "SMART_ALARM_ALLOWED_ORIGINS": "https://alarm.example.com",
            "SMART_ALARM_S3_ENDPOINT": "https://objects.example.com",
            "SMART_ALARM_S3_REGION": "test-1",
            "SMART_ALARM_S3_OTA_BUCKET": "smart-alarm-ota-test",
            "SMART_ALARM_S3_REPORT_BUCKET": "smart-alarm-reports-test",
            "SMART_ALARM_S3_AUDIT_BUCKET": "smart-alarm-audit-test",
            "SMART_ALARM_S3_ACCESS_KEY": "access-key",
            "SMART_ALARM_S3_SECRET_KEY": "object-secret-key-value",
            "SMART_ALARM_SMTP_HOST": "smtp.internal",
            "SMART_ALARM_SMTP_PORT": "587",
            "SMART_ALARM_SMTP_TLS": "true",
            "SMART_ALARM_SMTP_USERNAME": "smart-alarm",
            "SMART_ALARM_SMTP_PASSWORD": "smtp-password-value",
            "SMART_ALARM_NOTIFICATION_FROM": "smart-alarm@example.com",
            "SMART_ALARM_WEBHOOK_URL": "https://hooks.example.com/notify?key=secret",
            "SMART_ALARM_OTEL_EXPORTER_ENDPOINT": "https://otel.internal:4317",
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_accepts_complete_tls_configuration_without_exposing_secrets(self) -> None:
        settings = ProductionSettings.from_env(self.env)

        self.assertEqual(settings.environment, "staging-cn")
        self.assertEqual(settings.allowed_origins, ("https://alarm.example.com",))
        representation = repr(settings)
        self.assertNotIn("database-password-value", representation)
        self.assertNotIn("valkey-password-value", representation)
        self.assertNotIn("key=secret", representation)
        self.assertNotIn("session_key", settings.public_summary())
        self.assertNotIn("device_secret_key", settings.public_summary())

    def test_requires_exact_device_secret_key_length(self) -> None:
        self.env["SMART_ALARM_DEVICE_SECRET_KEY"] = "d" * 33
        with self.assertRaisesRegex(ConfigError, "exactly 32 bytes"):
            ProductionSettings.from_env(self.env)

    def test_rejects_insecure_transport(self) -> None:
        self.env["TB_HTTP_URL"] = "http://tb.example.com"
        with self.assertRaisesRegex(ConfigError, "TB_HTTP_URL must be an absolute HTTPS URL"):
            ProductionSettings.from_env(self.env)

    def test_does_not_accept_legacy_redis_environment_variables(self) -> None:
        for suffix in ("HOST", "PORT", "TLS", "USERNAME", "PASSWORD", "CA_FILE"):
            self.env[f"SMART_ALARM_REDIS_{suffix}"] = self.env.pop(f"SMART_ALARM_VALKEY_{suffix}")

        with self.assertRaisesRegex(ConfigError, "SMART_ALARM_VALKEY_TLS is required"):
            ProductionSettings.from_env(self.env)

    def test_rejects_public_origin_missing_from_allowlist(self) -> None:
        self.env["SMART_ALARM_ALLOWED_ORIGINS"] = "https://other.example.com"
        with self.assertRaisesRegex(ConfigError, "must include SMART_ALARM_PUBLIC_ORIGIN"):
            ProductionSettings.from_env(self.env)

    def test_secret_file_and_inline_value_are_mutually_exclusive(self) -> None:
        secret = Path(self.temporary.name) / "secret"
        secret.write_text("file-secret-value", encoding="utf-8")
        with self.assertRaisesRegex(ConfigError, "set only one"):
            read_secret({"VALUE": "inline", "VALUE_FILE": str(secret)}, "VALUE")

    def test_reads_secret_file_without_trailing_newline(self) -> None:
        secret = Path(self.temporary.name) / "secret"
        secret.write_bytes(b"file-secret-value\n")
        self.assertEqual(read_secret({"VALUE_FILE": str(secret)}, "VALUE"), b"file-secret-value")


class LocalSettingsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        device_secrets = Path(self.temporary.name) / "device-secrets"
        device_secrets.mkdir()
        self.env = {
            "SMART_ALARM_ENVIRONMENT": "local",
            "SMART_ALARM_DEPLOYMENT_COMMIT": "0123456789abcdef",
            "SMART_ALARM_PUBLIC_ORIGIN": "http://127.0.0.1:5173",
            "TB_HTTP_URL": "http://127.0.0.1:9090",
            "SMART_ALARM_DATABASE_HOST": "127.0.0.1",
            "SMART_ALARM_DATABASE_PORT": "55432",
            "SMART_ALARM_DATABASE_NAME": "smart_alarm",
            "SMART_ALARM_DATABASE_USER": "smart_alarm_app",
            "SMART_ALARM_DATABASE_PASSWORD": "local-database-password",
            "SMART_ALARM_VALKEY_HOST": "localhost",
            "SMART_ALARM_VALKEY_PORT": "6379",
            "SMART_ALARM_SESSION_KEY": "a" * 32,
            "SMART_ALARM_DEVICE_SECRET_ROOT": str(device_secrets),
            "SMART_ALARM_DEVICE_SECRET_KEY": "d" * 32,
            "SMART_ALARM_DEVICE_SECRET_KEY_VERSION": "1",
            "SMART_ALARM_ALLOWED_ORIGINS": "http://127.0.0.1:5173,http://localhost:5173",
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_accepts_loopback_dependencies_without_tls(self) -> None:
        settings = LocalSettings.from_env(self.env)

        self.assertFalse(settings.database_tls)
        self.assertFalse(settings.valkey_tls)
        self.assertFalse(settings.oidc_readiness)
        self.assertFalse(settings.secure_cookies)
        self.assertEqual(settings.bind_host, "127.0.0.1")
        self.assertEqual(settings.session_cookie_name, "smart_alarm_session_local")
        self.assertEqual(settings.device_secret_key_version, 1)

    def test_rejects_non_loopback_http_origins(self) -> None:
        for name, value in (
            ("SMART_ALARM_PUBLIC_ORIGIN", "http://192.168.1.10:5173"),
            ("TB_HTTP_URL", "http://thingsboard.internal:9090"),
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ConfigError, "loopback HTTP origin"):
                    LocalSettings.from_env({**self.env, name: value})

    def test_rejects_non_loopback_data_services(self) -> None:
        for name in ("SMART_ALARM_DATABASE_HOST", "SMART_ALARM_VALKEY_HOST"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ConfigError, "must be loopback addresses"):
                    LocalSettings.from_env({**self.env, name: "database.internal"})

    def test_load_settings_only_selects_local_mode_explicitly(self) -> None:
        self.assertIsInstance(load_settings(self.env), LocalSettings)
        with self.assertRaisesRegex(ConfigError, "SMART_ALARM_PUBLIC_ORIGIN must be an absolute HTTPS URL"):
            load_settings({**self.env, "SMART_ALARM_ENVIRONMENT": "development"})


if __name__ == "__main__":
    unittest.main()
