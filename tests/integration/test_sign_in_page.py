"""The sign-in page: one message, audited reasons, one name limit
(spec 2026-09-28 group 2b; review P3)."""

import ldap3
import pytest

from seqsetup.models.local_user import LocalUser
from seqsetup.models.user import UserRole
from seqsetup.services.auth import SIGN_IN_FAILED
from tests.fake_directory import ADMINS, PASSWORD, FakeDirectory, ad_account, use_directory

ORIGIN = {"Origin": "http://testserver"}
PW = "Cl1nical-Admin!"          # admin_user_seeded's password
LONG = "a" * 64


def _login(client, name, password):
    return client.post("/login/submit", data={"username": name, "password": password},
                       headers=ORIGIN, follow_redirects=False)


def _events(ctx, prefix):
    return ctx.audit_event_repo.search(limit=50, event_prefix=prefix)


@pytest.fixture
def directory(monkeypatch):
    d = FakeDirectory()
    monkeypatch.setattr(ldap3, "Connection", d.connection)
    return d


class TestOneMessage:
    """Every failed sign-in shows the same message; it never says which part failed."""

    def test_wrong_password_shows_the_one_message(self, client, admin_user_seeded):
        r = _login(client, "admin-test", "Wrong-Passw0rd!")
        assert r.status_code == 200 and SIGN_IN_FAILED in r.text

    def test_unknown_name_shows_the_same_message(self, client):
        r = _login(client, "nobody", PW)
        assert r.status_code == 200 and SIGN_IN_FAILED in r.text
