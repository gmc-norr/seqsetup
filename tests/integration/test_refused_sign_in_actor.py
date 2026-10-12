"""Only a name SeqSetup knows reaches the audit trail of a refused sign-in.

A password typed into the name box used to be stored as the ``actor`` of
the ``login.failure`` event -- kept for good, and shown on Admin > Audit to
every admin. What SeqSetup can know is its local accounts: there is no
collection of directory users, only ``web_sessions``, which lists live
logins and is emptied as they end, so a directory name that has never
signed in is not a name SeqSetup knows. Anything it does not know becomes
``(unknown name)`` and a keyed fingerprint.
"""

from seqsetup.services.audit_log import UNKNOWN_ACTOR


ORIGIN = {"Origin": "http://testserver"}
# What this stands for: a password typed into the name box by mistake. Spelled
# so it cannot read as a credential -- this repository is public.
TYPED_PASSWORD = "a-password-typed-into-the-name-box"


def _failures(ctx):
    return ctx.audit_event_repo.search(limit=500, event_prefix="login.failure")


def _refuse(client, username, password="wrong-on-purpose"):
    return client.post("/login/submit", data={"username": username, "password": password},
                       headers=ORIGIN)


class TestANameSeqSetupDoesNotKnow:
    def test_the_typed_text_is_not_stored(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        _refuse(client, TYPED_PASSWORD)

        (event,) = _failures(ctx)
        assert TYPED_PASSWORD not in event.actor

    def test_the_marker_is_stored_with_a_fingerprint(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        _refuse(client, TYPED_PASSWORD)

        (event,) = _failures(ctx)
        assert event.actor.startswith(UNKNOWN_ACTOR)
        assert event.actor != UNKNOWN_ACTOR

    def test_repeats_group_together(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        _refuse(client, TYPED_PASSWORD)
        _refuse(client, TYPED_PASSWORD)
        _refuse(client, "someone-else")

        actors = [e.actor for e in _failures(ctx)]
        assert len(set(actors)) == 2

    def test_the_audit_page_shows_the_marker_and_not_the_name(
            self, logged_in_client, fresh_app):
        _app, _ctx, _db = fresh_app
        _refuse(logged_in_client, TYPED_PASSWORD)

        page = logged_in_client.get("/admin/audit", params={"event": "login"}).text

        assert UNKNOWN_ACTOR in page
        assert TYPED_PASSWORD not in page

    def test_the_fingerprint_is_not_a_bare_hash_of_the_name(self, client, fresh_app):
        import hashlib

        _app, ctx, _db = fresh_app
        _refuse(client, TYPED_PASSWORD)

        (event,) = _failures(ctx)
        fingerprint = event.actor.removeprefix(UNKNOWN_ACTOR).strip()
        assert not hashlib.sha256(TYPED_PASSWORD.encode()).hexdigest().startswith(fingerprint)


class TestANameSeqSetupKnows:
    def test_a_local_account_is_stored_as_typed(self, client, fresh_app, admin_user_seeded):
        _app, ctx, _db = fresh_app
        _refuse(client, admin_user_seeded["username"])

        (event,) = _failures(ctx)
        assert event.actor == admin_user_seeded["username"]

    def test_a_name_that_only_differs_in_case_is_not_that_account(
            self, client, fresh_app, admin_user_seeded):
        """Sign-in matches the account name exactly, so this one is a name
        SeqSetup does not know."""
        _app, ctx, _db = fresh_app
        _refuse(client, admin_user_seeded["username"].upper())

        (event,) = _failures(ctx)
        assert event.actor.startswith(UNKNOWN_ACTOR)

    def test_a_successful_sign_in_still_stores_the_name(
            self, client, fresh_app, admin_user_seeded):
        _app, ctx, _db = fresh_app
        client.post("/login/submit", data=admin_user_seeded, headers=ORIGIN)

        (event,) = ctx.audit_event_repo.search(limit=500, event_prefix="login.success")
        assert event.actor == admin_user_seeded["username"]
