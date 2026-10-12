"""What the login limiter holds, and the answers it must keep giving.

One address posting ``/login/submit`` with a new username each time added a
``login-user:`` bucket per request and never gave one back, so the process
grew until someone restarted it (security review 2026-10). The per-address
cap now runs first, a request it refuses never touches a per-username
bucket, and a bucket whose window has passed is dropped.

Every limit, window, message and ``Retry-After`` value is unchanged, so
each refusal below pins the answer as well as the bookkeeping.
"""

import time
from collections import deque

import pytest
from starlette.testclient import TestClient

from seqsetup.rate_limit import get_login_limiter

ORIGIN = {"Origin": "http://testserver"}
TOO_MANY = "Too many login attempts. Try again later."
# The test client's own address, as rate_limit.client_identity reads it.
HERE = "testclient"


@pytest.fixture(autouse=True)
def _direct_client_address(monkeypatch):
    """Bucket by the TCP client, not by a forwarded header."""
    monkeypatch.delenv("SEQSETUP_TRUST_FORWARDED_FOR", raising=False)


@pytest.fixture(autouse=True)
def _cheap_timing_sentinel(monkeypatch):
    """The sentinel hash an unknown username is compared against, at bcrypt
    rounds 4 instead of 12.

    These tests are about the limiter's bookkeeping, and some of them post
    thousands of times. The real comparison still runs; it just costs
    milliseconds, so a change that stops the limiter refusing cannot make
    this file take ten minutes to say so.
    """
    import bcrypt
    from seqsetup.services import auth as auth_module
    monkeypatch.setattr(auth_module, "_DUMMY_BCRYPT_HASH", bcrypt.hashpw(
        b"seqsetup-timing-sentinel", bcrypt.gensalt(rounds=4)).decode("utf-8"))


def _defaults(limiter):
    """Fail loudly if another test left a non-default limiter behind: the
    expected waits below are computed from 20 attempts per 60 seconds."""
    assert (limiter.max_requests, limiter.window_seconds) == (20, 60), (
        "these tests assume the default login limit of 20 per 60 seconds"
    )


def _post(client, username, password="not-the-password"):
    return client.post(
        "/login/submit", data={"username": username, "password": password},
        headers=ORIGIN, follow_redirects=False)


class TestTheLimiterDoesNotGrowWithTheNamesItIsSent:
    def test_a_new_name_each_time_leaves_only_a_handful_of_buckets(self, client):
        """2000 posts from one address, each naming a username never seen
        before. Only the names the address was still allowed to try may
        leave a bucket behind."""
        limiter = get_login_limiter()
        _defaults(limiter)

        for n in range(2000):
            _post(client, f"ghost-{n}")

        assert len(limiter._buckets) <= 22, (
            f"{len(limiter._buckets)} buckets held after 2000 posts with "
            f"2000 different usernames from one address"
        )

    def test_a_refused_request_makes_no_bucket_for_the_name_it_carries(self, client):
        limiter = get_login_limiter()
        _defaults(limiter)
        for n in range(limiter.max_requests):
            _post(client, f"spent-{n}")

        refused = _post(client, "never-seen")

        assert refused.status_code == 429
        assert "login-user:never-seen" not in limiter._buckets

    def test_a_refused_request_spends_none_of_the_names_own_budget(
            self, fresh_app, client, admin_user_seeded):
        """The name a refused request carried must still have its full
        allowance when it is tried from an address that has some left.

        More requests are refused while carrying the name than the name's
        own cap allows, so had any of them counted, its bucket would be
        full and the sign-in from the fresh address would be refused too.
        """
        limiter = get_login_limiter()
        _defaults(limiter)
        name = admin_user_seeded["username"]
        for n in range(limiter.max_requests):
            _post(client, f"spent-{n}")
        for _ in range(limiter.max_requests + 5):
            assert _post(client, name).status_code == 429

        app, _ctx, _db = fresh_app
        elsewhere = TestClient(app, base_url="http://testserver",
                               client=("198.51.100.7", 44321))
        signed_in = elsewhere.post(
            "/login/submit",
            data={"username": name, "password": admin_user_seeded["password"]},
            headers=ORIGIN, follow_redirects=False)

        wait = limiter.retry_after(f"login-user:{name}")

        assert signed_in.status_code == 303, (
            f"the name {limiter.max_requests + 5} refused requests carried "
            f"could not sign in from an untouched address "
            f"(status={signed_in.status_code}, wait reported for its own "
            f"bucket {wait}s)"
        )
        assert len(limiter._buckets[f"login-user:{name}"]) == 1, (
            "only the one attempt the limiter allowed may count against "
            "the name"
        )


class TestTheRefusalItselfIsUnchanged:
    def test_the_address_refusal_keeps_its_status_body_and_wait(self, client):
        limiter = get_login_limiter()
        _defaults(limiter)
        now = time.monotonic()
        # Filled 40.5 s ago: 19.5 s of the window left, so the handler has
        # always answered 20.
        limiter._buckets[f"login-ip:{HERE}"] = deque([now - 40.5] * 20)

        refused = _post(client, "dana")

        assert refused.status_code == 429
        assert refused.text == TOO_MANY
        assert refused.headers["Retry-After"] == "20"

    def test_an_address_refusal_still_answers_the_longer_of_the_two_waits(self, client):
        """``retry = max(retry_ip, retry_user)``: the address cap was filled
        40.5 s ago (20 s left) while the name's own cap was filled 10.5 s ago
        from other addresses (50 s left). The header must still say 50 —
        reading the name's bucket must not mean counting a request into it."""
        limiter = get_login_limiter()
        _defaults(limiter)
        now = time.monotonic()
        limiter._buckets[f"login-ip:{HERE}"] = deque([now - 40.5] * 20)
        limiter._buckets["login-user:erik"] = deque([now - 10.5] * 20)

        refused = _post(client, "erik")

        assert refused.status_code == 429
        assert refused.text == TOO_MANY
        assert refused.headers["Retry-After"] == "50"

    def test_the_name_refusal_keeps_its_status_body_and_wait(self, client):
        """The address has plenty left; the name does not."""
        limiter = get_login_limiter()
        _defaults(limiter)
        now = time.monotonic()
        limiter._buckets["login-user:frida"] = deque([now - 10.5] * 20)

        refused = _post(client, "Frida")

        assert refused.status_code == 429
        assert refused.text == TOO_MANY
        assert refused.headers["Retry-After"] == "50"

    def test_the_21st_wrong_password_for_one_name_from_one_address_is_refused(
            self, client, admin_user_seeded):
        limiter = get_login_limiter()
        _defaults(limiter)
        name = admin_user_seeded["username"]

        for _ in range(20):
            assert _post(client, name).status_code == 200
        refused = _post(client, name)

        assert refused.status_code == 429
        assert refused.text == TOO_MANY

    def test_the_right_password_still_signs_in(self, client, admin_user_seeded):
        """Control: the reordering must not refuse a first attempt."""
        signed_in = _post(client, admin_user_seeded["username"],
                          admin_user_seeded["password"])

        assert signed_in.status_code == 303


class TestTheDirectorySignInTestRefusesTheSameWay:
    """``/admin/settings/ldap/test-auth`` shares the limiter and had the
    same two unconditional counts (the same bug in the same pattern)."""

    def test_a_refused_test_makes_no_bucket_for_the_name_it_carries(
            self, logged_in_client):
        limiter = get_login_limiter()
        _defaults(limiter)
        now = time.monotonic()
        limiter._buckets[f"ldap-test-ip:{HERE}"] = deque([now - 40.5] * 20)

        refused = logged_in_client.post(
            "/admin/settings/ldap/test-auth", headers={"HX-Request": "true", **ORIGIN},
            data={"test_username": "never-tested", "test_password": "x" * 12})

        assert "Too many test attempts. Retry after 20s." in refused.text
        assert "ldap-test-user:never-tested" not in limiter._buckets

    def test_a_refused_test_still_answers_the_longer_of_the_two_waits(
            self, logged_in_client):
        limiter = get_login_limiter()
        _defaults(limiter)
        now = time.monotonic()
        limiter._buckets[f"ldap-test-ip:{HERE}"] = deque([now - 40.5] * 20)
        limiter._buckets["ldap-test-user:gustav"] = deque([now - 10.5] * 20)

        refused = logged_in_client.post(
            "/admin/settings/ldap/test-auth", headers={"HX-Request": "true", **ORIGIN},
            data={"test_username": "Gustav", "test_password": "x" * 12})

        assert "Too many test attempts. Retry after 50s." in refused.text


class TestTheApiLimiterIsUnchanged:
    """The API bearer limiter shares ``RateLimiter``, so dropping dead
    buckets must not change what it lets through. It is keyed by address
    only, so no caller can name a bucket into existence."""

    def test_it_refuses_past_its_cap_with_the_same_answer(self, client, monkeypatch):
        import seqsetup.rate_limit as rl
        monkeypatch.setattr(rl, "_api_limiter", None)
        monkeypatch.setenv("SEQSETUP_API_RATE_LIMIT", "3")

        answers = [client.get("/api/runs") for _ in range(4)]

        assert [a.status_code for a in answers] == [401, 401, 401, 429]
        assert answers[-1].json()["detail"] == "Rate limit exceeded"
        assert int(answers[-1].headers["Retry-After"]) > 0

    def test_it_lets_a_caller_through_again_once_the_window_has_passed(
            self, client, monkeypatch):
        import seqsetup.rate_limit as rl
        monkeypatch.setattr(rl, "_api_limiter", None)
        monkeypatch.setenv("SEQSETUP_API_RATE_LIMIT", "2")
        monkeypatch.setenv("SEQSETUP_API_RATE_WINDOW", "60")
        for _ in range(2):
            client.get("/api/runs")
        assert client.get("/api/runs").status_code == 429

        # Age the recorded requests out of the window by hand, as time would.
        limiter = rl.get_api_limiter()
        limiter._buckets[f"api-ip:{HERE}"] = deque(
            [time.monotonic() - 61.0] * limiter.max_requests)

        assert client.get("/api/runs").status_code == 401
