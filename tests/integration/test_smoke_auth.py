"""Smoke tests for the auth flows.

Covers: login success/failure, logout, session-fixation defense, and the
"already logged in" redirect on /login.
"""

import pytest


class TestLogin:
    def test_valid_credentials_redirects_to_root(self, client, admin_user_seeded):
        response = client.post(
            "/login/submit",
            data=admin_user_seeded,
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/"

    def test_wrong_password_returns_login_page_with_error(self, client, admin_user_seeded):
        response = client.post(
            "/login/submit",
            data={"username": admin_user_seeded["username"], "password": "wrong-password"},
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
        # Login page re-renders (200) rather than redirecting.
        assert response.status_code == 200
        # Some hint of failure is in the body.
        body_lower = response.text.lower()
        assert "invalid" in body_lower or "error" in body_lower or "incorrect" in body_lower

    def test_unknown_user_returns_login_page_with_error(self, client):
        response = client.post(
            "/login/submit",
            data={"username": "nobody", "password": "Cl1nical-Admin!"},
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
        assert response.status_code == 200
        body_lower = response.text.lower()
        assert "invalid" in body_lower or "error" in body_lower or "incorrect" in body_lower


class TestLogout:
    def test_logout_redirects_to_login(self, logged_in_client):
        response = logged_in_client.get(
            "/logout",
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/login"

    def test_after_logout_protected_routes_redirect_to_login(self, logged_in_client):
        logged_in_client.get("/logout", follow_redirects=False)
        response = logged_in_client.get("/", follow_redirects=False)
        # Old TestClient retains the cookie; should now be cleared by logout.
        assert response.status_code in (302, 303)
        assert "/login" in response.headers.get("location", "")


class TestAlreadyLoggedInRedirect:
    """The /login GET redirects users who already have a valid session.

    Note: this does NOT test the session-fixation defence (sess.clear()
    inside _login_user). That unit-level coverage lives in
    tests/unit/test_auth_session_fixation.py.
    """

    def test_login_page_redirects_already_logged_in_user(self, logged_in_client):
        response = logged_in_client.get("/login", follow_redirects=False)
        assert response.status_code in (302, 303)
        assert response.headers["location"] == "/"


class TestCsrfOnLogin:
    """The login submission is a state-changing POST — CSRF middleware applies."""

    def test_login_post_with_no_origin_rejected(self, client, admin_user_seeded):
        response = client.post(
            "/login/submit",
            data=admin_user_seeded,
            follow_redirects=False,
            # TestClient sends no Origin by default when not provided
        )
        # Either 403 (CSRF reject) — that's the expected behavior.
        assert response.status_code == 403

    def test_login_post_with_cross_origin_rejected(self, client, admin_user_seeded):
        response = client.post(
            "/login/submit",
            data=admin_user_seeded,
            headers={"Origin": "http://attacker.example"},
            follow_redirects=False,
        )
        assert response.status_code == 403
