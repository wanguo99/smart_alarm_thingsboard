from __future__ import annotations

import unittest

try:
    from fastapi import APIRouter
    from smart_alarm_bff.device_routes import _optional_uuid, register_device_routes
    from smart_alarm_bff.write_routes import WriteError
except ModuleNotFoundError as exc:
    _missing_dependency = exc.name
else:
    _missing_dependency = None


@unittest.skipUnless(_missing_dependency is None, f"runtime dependency is not installed: {_missing_dependency}")
class DeviceRouteContractTest(unittest.TestCase):
    def test_device_lifecycle_paths_and_methods_are_mounted(self) -> None:
        router = APIRouter()
        register_device_routes(router, object(), object())  # type: ignore[arg-type]
        routes = {(route.path, frozenset(route.methods or set())) for route in router.routes}
        self.assertIn(("/api/v1/device-management/devices", frozenset({"POST"})), routes)
        self.assertIn(("/api/v1/device-management/devices/{device_uid}", frozenset({"PATCH"})), routes)
        self.assertIn(("/api/v1/device-management/devices/{device_uid}/retirements", frozenset({"POST"})), routes)

    def test_optional_uuid_rejects_non_string_and_invalid_values(self) -> None:
        self.assertIsNone(_optional_uuid(None, "device_uid"))
        with self.assertRaises(WriteError):
            _optional_uuid(123, "device_uid")
        with self.assertRaises(WriteError):
            _optional_uuid("not-a-uuid", "device_uid")


if __name__ == "__main__":
    unittest.main()
