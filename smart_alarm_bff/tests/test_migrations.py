from __future__ import annotations

from pathlib import Path
import unittest

from smart_alarm_bff.migrate import load_migrations


class MigrationContractTest(unittest.TestCase):
    def test_initial_schema_covers_production_control_plane(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        migrations = load_migrations(directory)
        self.assertEqual([item[0] for item in migrations], ["0001_initial.sql", "0002_seed_product_roles.sql", "0003_allow_system_scope_records.sql", "0004_system_scope_rls.sql", "0005_device_profile_metadata.sql", "0006_async_device_lifecycle.sql", "0007_outbox_fencing.sql", "0008_usernames.sql", "0009_device_activation_grants.sql", "0010_retired_device_credentials.sql", "0011_operation_retry_chain.sql", "0012_platform_entity_sync.sql", "0013_sad_identity_prefix.sql", "0014_persistent_device_commands.sql"])
        sql = migrations[0][2]
        for table in (
            "tenants",
            "customers",
            "users",
            "product_roles",
            "role_assignments",
            "device_inventory",
            "device_profiles",
            "assets",
            "business_groups",
            "devices",
            "entity_groups",
            "entity_group_members",
            "entity_relations",
            "http_sessions",
            "operations",
            "command_approvals",
            "command_batches",
            "command_batch_items",
            "notification_events",
            "outbox_events",
            "collision_events",
            "alarm_event_log",
            "audit_events",
        ):
            self.assertIn(f"CREATE TABLE smart_alarm.{table}", sql)
        self.assertIn("FORCE ROW LEVEL SECURITY", sql)
        self.assertIn("CREATE TRIGGER audit_events_append_only", sql)
        self.assertIn("credential_secret_ref", sql)

    def test_product_role_seed_matches_policy_contract(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        seed = load_migrations(directory)[1][2]
        for role in ("SYSTEM_OPERATOR", "TENANT_OWNER", "TENANT_OPERATOR", "TENANT_VIEWER", "CUSTOMER_OPERATOR", "CUSTOMER_VIEWER"):
            self.assertIn(f"('{role}'", seed)

    def test_system_scope_policy_keeps_global_records_isolated(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        policy = load_migrations(directory)[2][2]
        self.assertIn("tenant_id IS NULL", policy)
        self.assertIn("tenant_isolation_operations", policy)
        self.assertIn("tenant_isolation_outbox_events", policy)
        self.assertIn("tenant_isolation_audit_events", policy)

    def test_system_scope_rls_is_explicit(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        policy = load_migrations(directory)[3][2]
        self.assertIn("is_system_scope", policy)
        self.assertIn("current_tenant_id", policy)

    def test_device_profile_metadata_is_persistent(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        migration = load_migrations(directory)[4][2]
        self.assertIn("profile_type", migration)
        self.assertIn("transport_type", migration)

    def test_platform_entity_sync_state_is_explicit(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        migration = load_migrations(directory)[11][2]
        self.assertIn("platform_sync_status", migration)
        self.assertIn("LOCAL_ONLY", migration)
        self.assertIn("assets_platform_sync_idx", migration)

    def test_sad_identity_prefix_migrates_historical_names(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        migration = load_migrations(directory)[12][2]
        self.assertIn("DROP CONSTRAINT IF EXISTS devices_technical_name_check", migration)
        self.assertIn("'SAD-' || substring(serial_number FROM 5)", migration)
        self.assertIn("'sad-' || substring(technical_name FROM 5)", migration)
        self.assertIn("devices_technical_name_sad_check", migration)

    def test_device_activation_can_wait_for_outbox_worker(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        migration = load_migrations(directory)[5][2]
        self.assertIn("service_identity_secret_ref", migration)
        self.assertIn("ALTER COLUMN thingsboard_device_id DROP NOT NULL", migration)
        self.assertIn("device_platform_binding_ck", migration)

    def test_outbox_completion_uses_a_monotonic_fencing_token(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        migration = load_migrations(directory)[6][2]
        self.assertIn("lease_token", migration)
        self.assertIn("outbox_lease_shape_ck", migration)

    def test_usernames_are_primary_and_email_is_optional(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        migration = load_migrations(directory)[7][2]
        self.assertIn("ADD COLUMN username", migration)
        self.assertIn("ALTER COLUMN email DROP NOT NULL", migration)
        self.assertIn("users_active_username_uq", migration)

    def test_activation_grants_store_only_encrypted_references_under_forced_rls(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        migration = load_migrations(directory)[8][2]
        self.assertIn("CREATE TABLE smart_alarm.device_activation_grants", migration)
        self.assertIn("credential_secret_ref", migration)
        self.assertIn("FORCE ROW LEVEL SECURITY", migration)
        self.assertIn("smart_alarm.is_system_scope()", migration)
        self.assertNotIn("access_token", migration.lower())

    def test_retired_devices_keep_platform_history_without_live_secret_reference(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        migration = load_migrations(directory)[9][2]
        self.assertIn("device_platform_binding_ck", migration)
        self.assertIn("lifecycle_state = 'RETIRED'", migration)
        self.assertIn("credential_secret_ref IS NULL", migration)
        self.assertIn("device_activation_grants_consumed_at_ck", migration)

    def test_operation_retry_chain_cannot_fork(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        migration = load_migrations(directory)[10][2]
        self.assertIn("operations_single_retry_child_uq", migration)
        self.assertIn("parent_operation_id", migration)
        self.assertIn("WHERE parent_operation_id IS NOT NULL", migration)

    def test_persistent_command_state_is_indexed_and_idempotent(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        migration = load_migrations(directory)[13][2]
        self.assertIn("platform_rpc_id", migration)
        self.assertIn("command_expires_at", migration)
        self.assertIn("operations_command_pending_idx", migration)
        self.assertIn("command_approvals_request_idempotency_uq", migration)
        self.assertIn("command_approvals_decision_idempotency_uq", migration)

    def test_migration_names_and_checksums_are_stable(self) -> None:
        directory = Path(__file__).resolve().parents[1] / "migrations"
        for name, checksum, sql in load_migrations(directory):
            self.assertRegex(name, r"^[0-9]{4}_[a-z0-9_]+\.sql$")
            self.assertRegex(checksum, r"^[0-9a-f]{64}$")
            self.assertTrue(sql.endswith("\n"))


if __name__ == "__main__":
    unittest.main()
