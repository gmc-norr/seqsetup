"""Admin > Authentication > Test sign-in: its refused row keeps a typed name
the way a refused sign-in does (the night run's Q4, answered 2026-10-13).

``ldap.test_auth.rate_limited`` stored the typed name verbatim in
``target_user``, so an admin who typed a password into that page's name box
and tripped the limiter had it kept in the audit trail and shown on
Admin > Audit. Only a name SeqSetup knows is kept as typed; anything else is
the "(unknown name)" marker and a keyed fingerprint.
"""

import time
from collections import deque

from seqsetup.rate_limit import get_login_limiter
from seqsetup.services.audit_log import UNKNOWN_ACTOR

from .test_login_limiter_memory import HERE, ORIGIN, _defaults


def _refused_test(client, typed):
    limiter = get_login_limiter()
    _defaults(limiter)
    limiter._buckets[f"ldap-test-ip:{HERE}"] = deque([time.monotonic() - 40.5] * 20)
    resp = client.post("/admin/settings/ldap/test-auth", headers={"HX-Request": "true", **ORIGIN},
                       data={"test_username": typed, "test_password": "x" * 12})
    assert "Too many test attempts" in resp.text


def _row(ctx):
    (event,) = ctx.audit_event_repo.search(limit=50, event_prefix="ldap.test_auth.rate_limited")
    return event


class TestTheRefusedTestRowKeepsOnlyAKnownName:
    def test_a_password_typed_as_the_name_is_not_kept(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        typed = "hunter2-secret-pw"

        _refused_test(logged_in_client, typed)

        row = _row(ctx)
        assert row.details["target_user"].startswith(UNKNOWN_ACTOR)
        assert typed not in str(row.details) and typed not in row.actor

    def test_a_known_account_is_kept_as_typed(self, logged_in_client, fresh_app, admin_user_seeded):
        _app, ctx, _db = fresh_app
        name = admin_user_seeded["username"]

        _refused_test(logged_in_client, name)

        assert _row(ctx).details["target_user"] == name.lower()
