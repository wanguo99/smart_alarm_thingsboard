from __future__ import annotations

import unittest
from datetime import datetime, timezone
from uuid import UUID

try:
    from fastapi import APIRouter
    from smart_alarm_bff.directory_routes import _page, _system_audit_entry, register_directory_routes
except ModuleNotFoundError as exc:
    _missing_dependency = exc.name
else:
    _missing_dependency = None


@unittest.skipUnless(_missing_dependency is None, f"runtime dependency is not installed: {_missing_dependency}")
class DirectoryRouteContractTest(unittest.TestCase):
    def test_page_contract_is_explicit_and_stable(self) -> None:
        self.assertEqual(_page([]), {"data": [], "totalPages": 0, "totalElements": 0, "hasNext": False})
        self.assertEqual(_page([{"id": "one"}]), {"data": [{"id": "one"}], "totalPages": 1, "totalElements": 1, "hasNext": False})

    def test_all_frontend_directory_paths_are_mounted(self) -> None:
        router = APIRouter()
        register_directory_routes(router, object(), object())  # type: ignore[arg-type]
        paths = {route.path for route in router.routes}
        self.assertTrue({
            "/api/v1/customers",
            "/api/v1/customers/{customer_id}",
            "/api/v1/customers/{customer_id}/members",
            "/api/v1/assets",
            "/api/v1/assets/{asset_id}",
            "/api/v1/assets/{asset_id}/relations",
            "/api/v1/entity-groups",
            "/api/v1/device-profiles",
            "/api/v1/device-management/devices",
            "/api/v1/device-management/assignment-options",
            "/api/v1/system/tenants",
            "/api/v1/system/users",
            "/api/v1/system/role-assignments",
            "/api/v1/system/audit",
            "/api/v1/system/tenants/{tenant_id}/users",
        }.issubset(paths))

    def test_system_audit_entry_preserves_scope_and_resource_context(self) -> None:
        actor_id = UUID("10000000-0000-4000-8000-000000000001")
        row = {
            "id": 42,
            "tenant_id": None,
            "actor_user_id": actor_id,
            "actor_username": "sysadmin",
            "request_id": "request-123",
            "action": "TENANT_CREATED",
            "resource_type": "TENANT",
            "resource_id": "tenant-1",
            "outcome": "SUCCEEDED",
            "detail": {"name": "XXX交警大队"},
            "created_at": datetime(2026, 7, 24, tzinfo=timezone.utc),
        }
        self.assertEqual(_system_audit_entry(row), {
            "auditId": "42",
            "tenantId": "SYSTEM",
            "subject": "sysadmin",
            "deviceUid": None,
            "action": "TENANT_CREATED",
            "requestId": "request-123",
            "details": {
                "name": "XXX交警大队",
                "resourceType": "TENANT",
                "resourceId": "tenant-1",
                "outcome": "SUCCEEDED",
            },
            "createdAt": 1784851200000,
        })


if __name__ == "__main__":
    unittest.main()
