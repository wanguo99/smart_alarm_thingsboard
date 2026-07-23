from __future__ import annotations

import hashlib
import unittest

try:
    from fastapi import APIRouter
    from smart_alarm_bff.activation_routes import ActivationRequestError, _claim_proof, register_activation_routes
except ModuleNotFoundError as exc:
    _missing_dependency = exc.name
else:
    _missing_dependency = None


@unittest.skipUnless(_missing_dependency is None, f"runtime dependency is not installed: {_missing_dependency}")
class ActivationRouteContractTest(unittest.TestCase):
    def test_device_grant_and_acknowledgement_routes_are_mounted(self) -> None:
        router = APIRouter()
        register_activation_routes(router, object(), object())  # type: ignore[arg-type]
        routes = {(route.path, frozenset(route.methods or set())) for route in router.routes}
        self.assertIn(("/api/v1/device-activation/{device_uid}/grants", frozenset({"POST"})), routes)
        self.assertIn(
            ("/api/v1/device-activation/{device_uid}/grants/{request_id}/acknowledgements", frozenset({"POST"})),
            routes,
        )

    def test_claim_proof_is_hashed_and_never_returned(self) -> None:
        serial, digest, version = _claim_proof(
            {"serialNumber": "SIM-000001", "claimToken": "factory-claim-token-value"},
            acknowledgement=False,
        )
        self.assertEqual(serial, "SIM-000001")
        self.assertEqual(digest, hashlib.sha256(b"factory-claim-token-value").digest())
        self.assertIsNone(version)
        self.assertNotIn(b"factory-claim-token-value", digest)

    def test_acknowledgement_requires_exact_positive_credential_version(self) -> None:
        body = {
            "serialNumber": "SIM-000001",
            "claimToken": "factory-claim-token-value",
            "credentialVersion": 1,
        }
        self.assertEqual(_claim_proof(body, acknowledgement=True)[2], 1)
        for value in (True, 0, -1, "1", None):
            with self.subTest(value=value), self.assertRaises(ActivationRequestError):
                _claim_proof({**body, "credentialVersion": value}, acknowledgement=True)

    def test_unknown_fields_are_rejected(self) -> None:
        with self.assertRaises(ActivationRequestError):
            _claim_proof(
                {
                    "serialNumber": "SIM-000001",
                    "claimToken": "factory-claim-token-value",
                    "tenantId": "not-device-controlled",
                },
                acknowledgement=False,
            )


if __name__ == "__main__":
    unittest.main()
