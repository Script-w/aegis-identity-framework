import base64
import unittest

import pyotp

from main import MfaSetupRequest, MfaVerifyRequest, generate_qr, health_check, verify_mfa


class SecurityBrainTests(unittest.TestCase):
    def test_health_check_reports_active_service(self):
        self.assertEqual(
            {"status": "active", "service": "security-brain"},
            health_check(),
        )

    def test_generate_qr_returns_png_payload(self):
        result = generate_qr(MfaSetupRequest(username="alice", secret="JBSWY3DPEHPK3PXP"))

        self.assertEqual("success", result["status"])
        image = base64.b64decode(result["data"]["qr_code"])
        self.assertTrue(image.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_verify_mfa_accepts_current_code(self):
        secret = "JBSWY3DPEHPK3PXP"
        code = pyotp.TOTP(secret).now()

        self.assertEqual(
            {"status": "success", "message": "Code verified"},
            verify_mfa(MfaVerifyRequest(secret=secret, code=code)),
        )

    def test_verify_mfa_rejects_wrong_code(self):
        result = verify_mfa(MfaVerifyRequest(secret="JBSWY3DPEHPK3PXP", code="000000"))

        self.assertEqual(({"status": "failure", "message": "Invalid code"}, 400), result)


if __name__ == "__main__":
    unittest.main()
