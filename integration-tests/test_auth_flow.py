import os
import uuid

import pyotp
import requests


AUTH_URL = os.getenv("AUTH_URL", "http://localhost:8080")
SECURITY_BRAIN_URL = os.getenv("SECURITY_BRAIN_URL", "http://localhost:8000")
USERNAME = f"compose-e2e-{uuid.uuid4().hex[:8]}"
PASSWORD = "correct-horse-battery-staple"


def csrf_headers(session: requests.Session) -> dict[str, str]:
    response = session.get(f"{AUTH_URL}/api/auth/csrf", timeout=10)
    response.raise_for_status()
    payload = response.json()
    assert session.cookies.get("XSRF-TOKEN")
    return {payload["headerName"]: payload["token"]}


def post(session: requests.Session, path: str, payload: dict) -> requests.Response:
    return session.post(
        f"{AUTH_URL}{path}",
        json=payload,
        headers=csrf_headers(session),
        timeout=15,
    )


def test_compose_registration_login_and_mfa_flow():
    health = requests.get(f"{SECURITY_BRAIN_URL}/health", timeout=10)
    assert health.status_code == 200
    assert health.json()["status"] == "active"

    session = requests.Session()

    registration = post(
        session,
        "/api/auth/register",
        {"username": USERNAME, "password": PASSWORD},
    )
    assert registration.status_code == 200, registration.text

    login = post(
        session,
        "/api/auth/login",
        {"username": USERNAME, "password": PASSWORD},
    )
    assert login.status_code == 200, login.text
    assert session.cookies.get("AEGIS_TOKEN")

    setup = session.get(f"{AUTH_URL}/api/auth/mfa/setup", timeout=15)
    assert setup.status_code == 200, setup.text
    enrollment = setup.json()
    assert enrollment["success"] is True
    assert enrollment["qrCode"]
    secret = enrollment["manualEntryKey"]
    assert secret

    confirmation = post(
        session,
        "/api/auth/mfa/confirm",
        {"code": pyotp.TOTP(secret).now()},
    )
    assert confirmation.status_code == 200, confirmation.text

    logout = post(session, "/api/auth/logout", {})
    assert logout.status_code == 200, logout.text
    assert not session.cookies.get("AEGIS_TOKEN")

    missing_mfa = post(
        session,
        "/api/auth/login",
        {"username": USERNAME, "password": PASSWORD},
    )
    assert missing_mfa.status_code == 401
    assert not session.cookies.get("AEGIS_TOKEN")

    mfa_login = post(
        session,
        "/api/auth/login",
        {
            "username": USERNAME,
            "password": PASSWORD,
            "mfaCode": pyotp.TOTP(secret).now(),
        },
    )
    assert mfa_login.status_code == 200, mfa_login.text
    assert session.cookies.get("AEGIS_TOKEN")
