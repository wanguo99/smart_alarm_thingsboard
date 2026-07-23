from __future__ import annotations

import unittest

try:
    from fastapi import APIRouter
    from smart_alarm_bff.policy import ProductPrincipal
    from smart_alarm_bff.write_routes import _audit, _body_hash, _idempotency, _outbox, register_write_routes
except ModuleNotFoundError as exc:
    _missing_dependency = exc.name
else:
    _missing_dependency = None


@unittest.skipUnless(_missing_dependency is None, f"runtime dependency is not installed: {_missing_dependency}")
class WriteRouteContractTest(unittest.TestCase):
    def test_request_hash_is_canonical(self) -> None:
        self.assertEqual(_body_hash({"b": 2, "a": 1}), _body_hash({"a": 1, "b": 2}))
        self.assertNotEqual(_body_hash({"a": 1}), _body_hash({"a": 2}))

    def test_all_initial_lifecycle_write_paths_are_mounted(self) -> None:
        router = APIRouter()
        register_write_routes(router, object(), object())  # type: ignore[arg-type]
        paths = {route.path for route in router.routes}
        self.assertTrue({
            "/api/v1/system/tenants",
            "/api/v1/system/tenants/{tenant_id}",
            "/api/v1/system/tenants/{tenant_id}/archive",
            "/api/v1/system/users",
            "/api/v1/system/users/{user_id}",
            "/api/v1/system/users/{user_id}/archive",
            "/api/v1/system/role-assignments",
            "/api/v1/system/role-assignments/{user_id}",
            "/api/v1/system/role-assignments/{user_id}/archive",
            "/api/v1/customers",
            "/api/v1/customers/{customer_id}",
            "/api/v1/customers/{customer_id}/archive",
            "/api/v1/customers/{customer_id}/members",
            "/api/v1/customers/{customer_id}/members/{member_id}",
            "/api/v1/customers/{customer_id}/members/{member_id}/archive",
            "/api/v1/assets",
            "/api/v1/assets/{asset_id}",
            "/api/v1/assets/{asset_id}/archive",
            "/api/v1/device-profiles",
            "/api/v1/device-profiles/{profile_id}",
            "/api/v1/device-profiles/{profile_id}/archive",
            "/api/v1/entity-groups",
            "/api/v1/entity-groups/{group_id}",
            "/api/v1/entity-groups/{group_id}/archive",
            "/api/v1/entity-groups/{group_id}/restore",
            "/api/v1/entity-groups/{group_id}/members",
        }.issubset(paths))

    def test_audit_and_outbox_execute_independent_inserts(self) -> None:
        class Connection:
            def __init__(self) -> None:
                self.statements: list[str] = []

            async def fetchval(self, statement: str, *_args: object) -> None:
                self.statements.append(statement)
                return None

            async def execute(self, statement: str, *_args: object) -> None:
                self.statements.append(statement)

        from uuid import UUID

        principal = ProductPrincipal(
            local_user_id=UUID("11111111-1111-4111-8111-111111111111"),
            platform_user_id=UUID("22222222-2222-4222-8222-222222222222"),
            authority="TENANT_ADMIN",
            product_role="TENANT_OWNER",
            internal_tenant_id=UUID("33333333-3333-4333-8333-333333333333"),
            platform_tenant_id=UUID("44444444-4444-4444-8444-444444444444"),
            internal_customer_id=None,
            platform_customer_id=None,
            capabilities=frozenset(),
            policy_version=1,
            identity_version=1,
        )
        connection = Connection()
        import asyncio

        asyncio.run(_audit(connection, principal, "request-123", "TESTED", "DEVICE", "device-1", {}))
        self.assertEqual(len(connection.statements), 3)
        self.assertIn("pg_advisory_xact_lock", connection.statements[0])
        self.assertIn("INSERT INTO smart_alarm.audit_events", connection.statements[2])

        connection.statements.clear()
        asyncio.run(_outbox(connection, principal.internal_tenant_id, "DEVICE", "device-1", "test.requested", {}))
        self.assertEqual(len(connection.statements), 1)
        self.assertIn("INSERT INTO smart_alarm.outbox_events", connection.statements[0])


if __name__ == "__main__":
    unittest.main()
