from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from uuid import UUID

from smart_alarm_bff.secret_provider import EncryptedFileSecretStore, MountedSecretProvider, SecretReferenceError
from smart_alarm_bff.worker import DeliveryError, OutboxEvent, OutboxRepository, OutboxWorker, retry_delay
from smart_alarm_bff.worker_config import WorkerSettings


class WorkerConfigTest(unittest.TestCase):
    def test_worker_configuration_uses_separate_identity_and_bounded_timeouts(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            ca = root / "ca.pem"
            ca.write_text("ca", encoding="ascii")
            secret_root = root / "secrets"
            secret_root.mkdir()
            env = {
                "SMART_ALARM_ENVIRONMENT": "test",
                "SMART_ALARM_DEPLOYMENT_COMMIT": "abcdef1",
                "SMART_ALARM_WORKER_ID": "worker-1",
                "TB_HTTP_URL": "https://tb.example.com",
                "TB_HTTP_CA_FILE": str(ca),
                "SMART_ALARM_DATABASE_HOST": "postgres.internal",
                "SMART_ALARM_DATABASE_PORT": "5432",
                "SMART_ALARM_DATABASE_NAME": "smart_alarm",
                "SMART_ALARM_WORKER_DATABASE_USER": "smart_alarm_worker",
                "SMART_ALARM_WORKER_DATABASE_PASSWORD": "worker-password-value",
                "SMART_ALARM_DATABASE_SSLMODE": "verify-full",
                "SMART_ALARM_DATABASE_CA_FILE": str(ca),
                "SMART_ALARM_WORKER_SECRET_ROOT": str(secret_root),
                "SMART_ALARM_DEVICE_SECRET_ROOT": str(secret_root),
                "SMART_ALARM_DEVICE_SECRET_KEY": "k" * 32,
                "SMART_ALARM_DEVICE_SECRET_KEY_VERSION": "1",
                "SMART_ALARM_WORKER_BATCH_SIZE": "10",
                "SMART_ALARM_WORKER_POLL_INTERVAL_MS": "500",
                "SMART_ALARM_WORKER_LEASE_SECONDS": "30",
                "SMART_ALARM_WORKER_HANDLER_TIMEOUT_SECONDS": "20",
                "SMART_ALARM_WORKER_MAX_ATTEMPTS": "8",
                "SMART_ALARM_WORKER_INITIAL_BACKOFF_SECONDS": "2",
                "SMART_ALARM_WORKER_MAX_BACKOFF_SECONDS": "60",
            }
            settings = WorkerSettings.from_env(env)
            self.assertEqual(settings.database_user, "smart_alarm_worker")
            self.assertNotIn("worker-password-value", repr(settings))
            with self.assertRaisesRegex(ValueError, "lower than the lease"):
                WorkerSettings.from_env({**env, "SMART_ALARM_WORKER_HANDLER_TIMEOUT_SECONDS": "30"})
            with self.assertRaisesRegex(ValueError, "exactly 32 bytes"):
                WorkerSettings.from_env({**env, "SMART_ALARM_DEVICE_SECRET_KEY": "k" * 33})


class MountedSecretProviderTest(unittest.TestCase):
    def test_reads_only_namespaced_files_below_the_secret_root(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            tenant = root / "tenants" / "tenant-1"
            tenant.mkdir(parents=True)
            (tenant / "thingsboard.json").write_bytes(b'{"username":"service"}\n')
            provider = MountedSecretProvider(root)
            self.assertEqual(provider.read("mounted:tenants/tenant-1/thingsboard.json"), b'{"username":"service"}')
            for reference in ("/etc/passwd", "mounted:../outside", "vault:tenant-1"):
                with self.assertRaises(SecretReferenceError):
                    provider.read(reference)

    def test_device_credentials_are_atomic_and_encrypted_at_rest(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            store = EncryptedFileSecretStore(root, b"k" * 32, 7)
            reference, value = store.get_or_create("devices/tenant-1/device-1.bin", lambda: b"device-token")
            self.assertEqual(reference, "encrypted:v7:devices/tenant-1/device-1.bin")
            self.assertEqual(value, b"device-token")
            self.assertEqual(store.read(reference), b"device-token")
            self.assertNotIn(b"device-token", (root / "devices" / "tenant-1" / "device-1.bin").read_bytes())
            second = store.get_or_create("devices/tenant-1/device-1.bin", lambda: b"different-token")
            self.assertEqual(second, (reference, b"device-token"))
            store.delete(reference)
            store.delete(reference)
            with self.assertRaises(SecretReferenceError):
                store.read(reference)

    def test_device_credentials_reject_symlink_escape_and_converge_under_concurrency(self) -> None:
        with TemporaryDirectory() as directory, TemporaryDirectory() as outside_directory:
            root = Path(directory)
            outside = Path(outside_directory)
            (root / "escaped").symlink_to(outside, target_is_directory=True)
            store = EncryptedFileSecretStore(root, b"k" * 32, 1)
            with self.assertRaises(SecretReferenceError):
                store.get_or_create("escaped/device.bin", lambda: b"must-not-escape")
            self.assertEqual(list(outside.iterdir()), [])

            values = [f"token-{index}".encode("ascii") for index in range(8)]
            with ThreadPoolExecutor(max_workers=len(values)) as executor:
                results = list(executor.map(
                    lambda value: store.get_or_create("devices/shared.bin", lambda: value),
                    values,
                ))
            references = {reference for reference, _value in results}
            stored_values = {value for _reference, value in results}
            self.assertEqual(references, {"encrypted:v1:devices/shared.bin"})
            self.assertEqual(len(stored_values), 1)
            self.assertIn(next(iter(stored_values)), values)


class WorkerKernelTest(unittest.TestCase):
    @staticmethod
    def event(attempts: int = 1) -> OutboxEvent:
        return OutboxEvent(
            event_id=UUID("11111111-1111-4111-8111-111111111111"),
            tenant_id=UUID("22222222-2222-4222-8222-222222222222"),
            aggregate_type="DEVICE",
            aggregate_id="device-1",
            event_type="device.test.requested",
            payload={},
            attempts=attempts,
            lease_token=3,
        )

    @staticmethod
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
            secret_root=Path("/secrets"),
            device_secret_root=Path("/device-secrets"),
            device_secret_key=b"k" * 32,
            device_secret_key_version=1,
            batch_size=10,
            poll_interval_ms=100,
            lease_seconds=30,
            handler_timeout_seconds=20,
            max_attempts=max_attempts,
            initial_backoff_seconds=2,
            max_backoff_seconds=60,
        )

    def test_backoff_is_exponential_and_capped(self) -> None:
        self.assertEqual([retry_delay(value, 2, 10) for value in (1, 2, 3, 4)], [2, 4, 8, 10])

    def test_success_retry_and_dead_letter_are_fenced(self) -> None:
        class Repository:
            def __init__(self) -> None:
                self.calls: list[tuple[str, object]] = []

            async def delivered(self, event: OutboxEvent, owner: str) -> bool:
                self.calls.append(("delivered", (event.lease_token, owner)))
                return True

            async def retry(self, event: OutboxEvent, owner: str, code: str, delay: int) -> bool:
                self.calls.append(("retry", (code, delay, event.lease_token, owner)))
                return True

            async def dead_letter(self, event: OutboxEvent, owner: str, code: str) -> bool:
                self.calls.append(("dead", (code, event.lease_token, owner)))
                return True

        async def scenario() -> list[tuple[str, object]]:
            repository = Repository()

            async def success(_event: OutboxEvent) -> None:
                return None

            worker = OutboxWorker(self.settings(), repository, {"device.test.requested": success})  # type: ignore[arg-type]
            await worker.process(self.event())

            async def retryable(_event: OutboxEvent) -> None:
                raise DeliveryError("temporary_failure")

            worker = OutboxWorker(self.settings(), repository, {"device.test.requested": retryable})  # type: ignore[arg-type]
            await worker.process(self.event())

            async def permanent(_event: OutboxEvent) -> None:
                raise DeliveryError("invalid_request", retryable=False)

            worker = OutboxWorker(self.settings(), repository, {"device.test.requested": permanent})  # type: ignore[arg-type]
            await worker.process(self.event())
            return repository.calls

        calls = asyncio.run(scenario())
        self.assertEqual([call[0] for call in calls], ["delivered", "retry", "dead"])
        self.assertEqual(calls[1][1][1], 2)  # type: ignore[index]

    def test_repository_claims_with_skip_locked_and_completes_with_fencing(self) -> None:
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
                    "id": UUID("11111111-1111-4111-8111-111111111111"),
                    "tenant_id": UUID("22222222-2222-4222-8222-222222222222"),
                    "aggregate_type": "DEVICE",
                    "aggregate_id": "device-1",
                    "event_type": "device.test.requested",
                    "payload": {},
                    "attempts": 1,
                    "lease_token": 7,
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
            repository = OutboxRepository(Pool(connection))
            events = await repository.claim("worker-1", limit=10, lease_seconds=30, max_attempts=8)
            self.assertEqual(events[0].lease_token, 7)
            self.assertTrue(await repository.delivered(events[0], "worker-1"))
            return connection.statements

        statements = asyncio.run(scenario())
        self.assertTrue(any("FOR UPDATE SKIP LOCKED" in statement for statement in statements))
        self.assertTrue(any("lease_token = $3" in statement for statement in statements))
        self.assertGreaterEqual(sum("smart_alarm.system_scope" in statement for statement in statements), 2)
