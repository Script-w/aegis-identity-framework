import base64
import unittest

import pyotp
from fastapi.testclient import TestClient

from main import app


class SecurityBrainTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health_check_reports_active_service(self):
        response = self.client.get("/health")

        self.assertEqual(200, response.status_code)
        self.assertEqual({"status": "active", "service": "security-brain"}, response.json())

    def test_generate_qr_returns_png_payload(self):
        response = self.client.post(
            "/mfa/setup",
            json={"username": "alice", "secret": "JBSWY3DPEHPK3PXP"},
        )

        self.assertEqual(200, response.status_code)
        result = response.json()
        self.assertEqual("success", result["status"])
        image = base64.b64decode(result["data"]["qr_code"])
        self.assertTrue(image.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_verify_mfa_accepts_current_code(self):
        secret = "JBSWY3DPEHPK3PXP"
        code = pyotp.TOTP(secret).now()

        response = self.client.post("/mfa/verify", json={"secret": secret, "code": code})

        self.assertEqual(200, response.status_code)
        self.assertEqual({"status": "success", "message": "Code verified"}, response.json())

    def test_verify_mfa_rejects_wrong_code(self):
        secret = "JBSWY3DPEHPK3PXP"
        current = pyotp.TOTP(secret).now()
        wrong = f"{(int(current) + 1) % 1_000_000:06d}"
        response = self.client.post("/mfa/verify", json={"secret": secret, "code": wrong})

        self.assertEqual(400, response.status_code)
        self.assertEqual({"detail": "Invalid code"}, response.json())

    def test_mfa_endpoints_reject_missing_or_malformed_fields(self):
        self.assertEqual(422, self.client.post("/mfa/setup", json={}).status_code)
        self.assertEqual(
            422,
            self.client.post(
                "/mfa/verify",
                json={"secret": "JBSWY3DPEHPK3PXP", "code": "ABC123"},
            ).status_code,
        )


if __name__ == "__main__":
    unittest.main()
