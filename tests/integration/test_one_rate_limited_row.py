"""A flood of refused sign-ins leaves one audit row per address per window.

Every refused request wrote its own ``login.rate_limited`` row, so a few
thousand refusals buried every other event on Admin > Audit under a few
thousand rows that all said the same thing, and the page's 100-at-a-time
listing could show nothing else for a long while. Each row now says how
many refusals it accounts for, and no row is ever changed after it is
written -- the trail is insert-only, so the refusals counted after a row
went out are carried by that address's next row.
"""

import time
from collections import deque

import pytest

from seqsetup.rate_limit import get_login_limiter, get_login_refusal_counter


ORIGIN = {"Origin": "http://testserver"}
HERE = "testclient"


@pytest.fixture(autouse=True)
def _direct_client_address(monkeypatch):
    monkeypatch.delenv("SEQSETUP_TRUST_FORWARDED_FOR", raising=False)


@pytest.fixture(autouse=True)
def _cheap_timing_sentinel(monkeypatch):
    """bcrypt at rounds 4, as in test_login_limiter_memory.py: these tests
    post past the cap and are about the rows, not the hashing."""
    import bcrypt
    from seqsetup.services import auth as auth_module
    monkeypatch.setattr(auth_module, "_DUMMY_BCRYPT_HASH", bcrypt.hashpw(
        b"seqsetup-timing-sentinel", bcrypt.gensalt(rounds=4)).decode("utf-8"))


def _spend_the_address(limiter, identity=HERE):
    """Fill the per-address bucket so the next post is refused."""
    limiter._buckets[f"login-ip:{identity}"] = deque(
        [time.monotonic()] * limiter.max_requests)


def _post(client, username="dana"):
    return client.post("/login/submit", data={"username": username, "password": "no"},
                       headers=ORIGIN, follow_redirects=False)


def _rows(ctx):
    """Oldest first."""
    found = ctx.audit_event_repo.search(limit=500, event_prefix="login.rate_limited")
    return list(reversed(found))


class TestOneRowPerAddressPerWindow:
    def test_twelve_refusals_leave_one_row(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        limiter = get_login_limiter()
        _spend_the_address(limiter)

        refused = [_post(client) for _ in range(12)]

        assert [r.status_code for r in refused] == [429] * 12
        assert len(_rows(ctx)) == 1

    def test_the_row_says_how_many_it_accounts_for(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        _spend_the_address(get_login_limiter())

        _post(client)

        (row,) = _rows(ctx)
        assert row.details["refused"] == 1

    def test_the_refusal_itself_is_unchanged(self, client, fresh_app):
        """Still 429, still the same body and Retry-After for every one."""
        _app, _ctx, _db = fresh_app
        _spend_the_address(get_login_limiter())

        refused = [_post(client) for _ in range(5)]

        assert {r.status_code for r in refused} == {429}
        assert {r.text for r in refused} == {"Too many login attempts. Try again later."}
        assert all(int(r.headers["Retry-After"]) > 0 for r in refused)

    def test_two_addresses_each_get_a_row(self, client, fresh_app):
        from starlette.testclient import TestClient

        app, ctx, _db = fresh_app
        limiter = get_login_limiter()
        elsewhere = TestClient(app, base_url="http://testserver",
                               client=("198.51.100.7", 44321))
        _spend_the_address(limiter, HERE)
        _spend_the_address(limiter, "198.51.100.7")

        for _ in range(4):
            _post(client)
            elsewhere.post("/login/submit", data={"username": "dana", "password": "no"},
                           headers=ORIGIN, follow_redirects=False)

        rows = _rows(ctx)
        assert len(rows) == 2
        assert {row.details["ip"] for row in rows} == {HERE, "198.51.100.7"}


class TestTheCountIsNotLost:
    def test_the_next_window_carries_what_was_counted(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        limiter = get_login_limiter()
        _spend_the_address(limiter)
        for _ in range(7):
            _post(client)

        # Let both windows pass, as waiting a minute would.
        counter = get_login_refusal_counter()
        started, pending = counter._windows[HERE]
        counter._windows[HERE] = (started - counter.window_seconds, pending)
        _spend_the_address(limiter)

        _post(client)

        rows = _rows(ctx)
        assert [row.details["refused"] for row in rows] == [1, 7]

    def test_the_first_row_is_never_rewritten(self, client, fresh_app):
        """Insert-only: the row that went out keeps the count it was written
        with, whatever happens afterwards."""
        _app, ctx, _db = fresh_app
        _spend_the_address(get_login_limiter())
        _post(client)
        (before,) = _rows(ctx)

        for _ in range(6):
            _post(client)

        (after,) = _rows(ctx)
        assert (after.timestamp, after.details["refused"]) == (
            before.timestamp, before.details["refused"])

    def test_every_refusal_is_accounted_for(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        limiter = get_login_limiter()
        counter = get_login_refusal_counter()
        refusals = 0
        for _round in range(3):
            _spend_the_address(limiter)
            for _ in range(5):
                if _post(client).status_code == 429:
                    refusals += 1
            started, pending = counter._windows[HERE]
            counter._windows[HERE] = (started - counter.window_seconds, pending)
        _spend_the_address(limiter)
        if _post(client).status_code == 429:
            refusals += 1

        assert sum(row.details["refused"] for row in _rows(ctx)) == refusals


class TestWhatTheCarriedCountBelongsTo:
    """A count carried from an earlier window was typed with whatever names
    came before it at that address, so crediting it to the name on the row
    would show one account with attempts that were made on other names."""

    def _carry_nine_other_names(self, client, limiter, counter):
        """One refusal for 'alice', nine for other names, then the window
        passes: the next row carries those nine."""
        _spend_the_address(limiter)
        _post(client, "alice")
        for n in range(9):
            _post(client, f"name-{n}")
        started, pending = counter._windows[HERE]
        counter._windows[HERE] = (started - counter.window_seconds, pending)
        _spend_the_address(limiter)

    def test_the_row_says_how_much_came_from_earlier(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        self._carry_nine_other_names(client, get_login_limiter(),
                                     get_login_refusal_counter())

        _post(client, "admin-test")

        carried = _rows(ctx)[-1]
        assert (carried.details["refused"], carried.details["refused_earlier"]) == (10, 9)

    def test_an_ordinary_row_does_not_mention_it(self, client, fresh_app):
        """Nothing was carried, so the row keeps the shape it had."""
        _app, ctx, _db = fresh_app
        _spend_the_address(get_login_limiter())

        _post(client)

        (row,) = _rows(ctx)
        assert "refused_earlier" not in row.details

    def test_the_audit_page_shows_it(self, logged_in_client, fresh_app):
        _app, _ctx, _db = fresh_app
        self._carry_nine_other_names(logged_in_client, get_login_limiter(),
                                     get_login_refusal_counter())
        _post(logged_in_client, "admin-test")

        page = logged_in_client.get("/admin/audit",
                                    params={"event": "login.rate_limited"}).text

        assert "refused_earlier" in page


class TestWhoTheRowNames:
    def test_it_names_the_typed_account_when_seqsetup_knows_it(
            self, client, fresh_app, admin_user_seeded):
        _app, ctx, _db = fresh_app
        _spend_the_address(get_login_limiter())

        _post(client, admin_user_seeded["username"])

        (row,) = _rows(ctx)
        assert row.actor == admin_user_seeded["username"]

    def test_it_names_no_unknown_typed_name(self, client, fresh_app):
        from seqsetup.services.audit_log import UNKNOWN_ACTOR

        _app, ctx, _db = fresh_app
        _spend_the_address(get_login_limiter())

        _post(client, "a-password-typed-into-the-name-box")

        (row,) = _rows(ctx)
        assert row.actor.startswith(UNKNOWN_ACTOR)
        assert "password" not in row.actor
