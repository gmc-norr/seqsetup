"""SEQSETUP_HTTPS_ONLY reaches the session cookie, HSTS and the crash page
(group 3a). The fresh_app fixture reloads seqsetup.app, so each test sets the
variable in a fixture listed before it."""

import re

import pytest
from starlette.testclient import TestClient


_HSTS = "max-age=63072000; includeSubDomains"


@pytest.fixture
def https_only_on(monkeypatch):
    monkeypatch.setenv("SEQSETUP_HTTPS_ONLY", "1")


@pytest.fixture
def https_only_unset(monkeypatch):
    monkeypatch.delenv("SEQSETUP_HTTPS_ONLY", raising=False)


def _login(app, user):
    client = TestClient(app, base_url="http://testserver")
    response = client.post(
        "/login/submit",
        data={"username": user["username"], "password": user["password"]},
        headers={"Origin": "http://testserver"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    return response


def _crash(app, login_response, path="/probe-unhandled-error", target=None):
    """GET a probe route that raises, logged in, over plain http."""

    def boom():
        raise RuntimeError("probe: an unhandled error")

    (target or app).add_api_route(path.removeprefix("/api"), boom)
    client = TestClient(app, base_url="http://testserver", raise_server_exceptions=False)
    # A Secure cookie is not sent back over http by the test client; set it by hand.
    client.cookies.set("seqsetup_session", login_response.cookies["seqsetup_session"])
    return client.get(path, follow_redirects=False)


class TestHttpsOnlyOn:
    """With SEQSETUP_HTTPS_ONLY=1: a Secure cookie, and HSTS on every answer,
    crash pages included, even when the app sees plain http."""

    def test_the_session_cookie_is_secure(self, https_only_on, fresh_app, admin_user_seeded):
        response = _login(fresh_app[0], admin_user_seeded)
        assert re.search(r";\s*secure\b", response.headers["set-cookie"], re.IGNORECASE)

    def test_hsts_is_sent_over_plain_http(self, https_only_on, fresh_app):
        response = TestClient(fresh_app[0], base_url="http://testserver").get("/login")
        assert response.status_code == 200
        assert response.headers.get_list("strict-transport-security") == [_HSTS]

    def test_a_crash_page_has_the_security_headers(self, https_only_on, fresh_app,
                                                    admin_user_seeded):
        app = fresh_app[0]
        response = _crash(app, _login(app, admin_user_seeded))
        assert response.status_code == 500
        assert response.text == "Internal Server Error"
        assert "Content-Security-Policy" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers.get_list("strict-transport-security") == [_HSTS]

    def test_an_api_crash_page_still_has_the_headers_once(self, https_only_on, fresh_app,
                                                          admin_user_seeded):
        import sys

        app = fresh_app[0]
        api = sys.modules["seqsetup.app"]._api_subapp
        response = _crash(app, _login(app, admin_user_seeded), "/api/probe-unhandled-error", api)
        assert response.status_code == 500
        assert response.headers.get_list("content-security-policy") == [
            response.headers["content-security-policy"]]
        assert response.headers.get_list("strict-transport-security") == [_HSTS]


class TestHttpsOnlyUnset:
    """Without the setting (a developer's machine): as before, no Secure and no
    HSTS over http; the crash page still gets the other headers."""

    def test_the_session_cookie_is_not_secure(self, https_only_unset, fresh_app,
                                              admin_user_seeded):
        response = _login(fresh_app[0], admin_user_seeded)
        assert not re.search(r";\s*secure\b", response.headers["set-cookie"], re.IGNORECASE)

    def test_no_hsts_over_plain_http(self, https_only_unset, fresh_app):
        response = TestClient(fresh_app[0], base_url="http://testserver").get("/login")
        assert response.status_code == 200
        assert "strict-transport-security" not in response.headers

    def test_a_crash_page_has_the_headers_but_no_hsts(self, https_only_unset, fresh_app,
                                                      admin_user_seeded):
        app = fresh_app[0]
        response = _crash(app, _login(app, admin_user_seeded))
        assert response.status_code == 500
        assert response.text == "Internal Server Error"
        assert "Content-Security-Policy" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "strict-transport-security" not in response.headers
