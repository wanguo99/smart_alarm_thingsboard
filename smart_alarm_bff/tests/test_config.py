from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from smart_alarm_bff.config import ConfigError, ProductionSettings, read_secret


class ProductionSettingsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        ca = root / "ca.pem"
        ca.write_text("test-ca", encoding="utf-8")
        public_key = root / "policy.pem"
        public_key.write_text("test-public-key", encoding="utf-8")
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
            "SMART_ALARM_REDIS_HOST": "redis.internal",
            "SMART_ALARM_REDIS_PORT": "6379",
            "SMART_ALARM_REDIS_TLS": "true",
            "SMART_ALARM_REDIS_USERNAME": "smart_alarm_app",
            "SMART_ALARM_REDIS_PASSWORD": "redis-password-value",
            "SMART_ALARM_REDIS_CA_FILE": str(ca),
            "SMART_ALARM_OIDC_ISSUER": "https://id.example.com/realms/smart-alarm",
            "SMART_ALARM_OIDC_CLIENT_ID": "smart-alarm-web",
            "SMART_ALARM_OIDC_CLIENT_SECRET": "oidc-client-secret-value",
            "SMART_ALARM_SESSION_KEY": "a" * 32,
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
        self.assertNotIn("redis-password-value", representation)
        self.assertNotIn("key=secret", representation)
        self.assertNotIn("session_key", settings.public_summary())

    def test_rejects_insecure_transport(self) -> None:
        self.env["TB_HTTP_URL"] = "http://tb.example.com"
        with self.assertRaisesRegex(ConfigError, "TB_HTTP_URL must be an absolute HTTPS URL"):
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


if __name__ == "__main__":
    unittest.main()
