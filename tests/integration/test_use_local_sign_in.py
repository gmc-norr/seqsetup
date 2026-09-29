"""pixi run use-local-sign-in: the way back in (spec 2026-09-28 group 2b, review P2;
plan review 1, P3)."""

import tomllib
from pathlib import Path

import ldap3
import pytest
from pymongo.errors import AutoReconnect

from seqsetup import use_local_sign_in
from seqsetup.models.auth_config import AuthMethod
from seqsetup.repositories.auth_config_repo import AuthConfigRepository
from tests.fake_directory import ADMINS, AD_PATTERN, USERS, FakeDirectory, use_directory

ORIGIN = {"Origin": "http://testserver"}
PW = "Cl1nical-Admin!"          # admin_user_seeded's password
ROOT = Path(__file__).resolve().parents[2]
NOW_LOCAL = ("Sign-in is now local only. The directory settings were kept; switch back on "
             "Admin → Authentication.")


@pytest.fixture
def directory(monkeypatch):
    d = FakeDirectory()
    monkeypatch.setattr(ldap3, "Connection", d.connection)
    return d


def _run(db):
    said = []
    return use_local_sign_in.main(get_db=lambda: db, say=said.append), said


def _login(client, name, password):
    return client.post("/login/submit", data={"username": name, "password": password},
                       headers=ORIGIN, follow_redirects=False)


def _boom():
    raise ConnectionError("no database")


class TestUseLocalSignIn:
    """With the directory on and fallback off, this is how admins get back in."""

    def test_a_locked_out_admin_gets_back_in(self, client, fresh_app, admin_user_seeded,
                                             directory):
        _app, ctx, db = fresh_app
        use_directory(ctx, fallback=False)
        assert _login(client, "admin-test", PW).status_code == 200      # locked out
        assert _run(db) == (0, [NOW_LOCAL])
        assert _login(client, "admin-test", PW).status_code == 303

    def test_the_directory_settings_are_kept(self, fresh_app):
        _app, ctx, db = fresh_app
        use_directory(ctx, fallback=False)
        _run(db)
        config = ctx.auth_config_repo.get()
        assert config.auth_method is AuthMethod.LOCAL
        assert (config.ldap_config.user_dn_pattern, config.ldap_config.user_group_dn,
                config.ldap_config.admin_group_dn) == (AD_PATTERN, USERS, ADMINS)

    def test_it_is_recorded_in_the_audit_trail(self, fresh_app):
        _app, ctx, db = fresh_app
        use_directory(ctx, fallback=False)
        _run(db)
        (event,) = ctx.audit_event_repo.search(limit=10, event_prefix="auth.method.changed")
        assert (event.actor, event.details["method"], event.details["via"]) == (
            "use-local-sign-in", "local", "server command")

    def test_already_local_changes_nothing(self, fresh_app):
        _app, ctx, db = fresh_app
        assert _run(db) == (0, ["Sign-in is already local only."])
        assert ctx.audit_event_repo.search(limit=10, event_prefix="auth.method.changed") == []

    def test_an_unreachable_database(self):
        said = []
        assert use_local_sign_in.main(get_db=_boom, say=said.append) == 1
        assert said == ["Could not reach the database. Nothing was changed."]

    def test_the_pixi_task_runs_the_command(self):
        tasks = tomllib.loads((ROOT / "pixi.toml").read_text())["tasks"]
        assert tasks["use-local-sign-in"] == "PYTHONPATH=src python -m seqsetup.use_local_sign_in"


class TestDatabaseFailures:
    """A failure before the save changes nothing; a failure during the save
    leaves the outcome unknown, and the command says so (plan review 1, P3)."""

    def test_a_failed_read_changes_nothing(self, fresh_app, monkeypatch):
        _app, ctx, db = fresh_app
        use_directory(ctx, fallback=False)

        def lost(self):
            raise AutoReconnect("connection closed")

        monkeypatch.setattr(AuthConfigRepository, "get", lost)
        assert _run(db) == (1, [
            "The database failed while reading (AutoReconnect). Nothing was changed."])
        monkeypatch.undo()
        assert ctx.auth_config_repo.get().auth_method is AuthMethod.ACTIVE_DIRECTORY

    def test_a_lost_answer_while_saving_says_it_is_not_known(self, fresh_app, monkeypatch):
        # The switch reaches the database, then its answer is lost.
        _app, ctx, db = fresh_app
        use_directory(ctx, fallback=False)
        real_save = AuthConfigRepository.save

        def save_then_lose(self, config):
            real_save(self, config)
            raise AutoReconnect("connection closed")

        monkeypatch.setattr(AuthConfigRepository, "save", save_then_lose)
        assert _run(db) == (1, [
            "The database failed while saving (AutoReconnect), so it is not known whether "
            "sign-in was switched to local. Run 'pixi run use-local-sign-in' again: it says "
            "'Sign-in is already local only.' if the switch was saved."])
        monkeypatch.undo()
        # What the message says to do works: running it again tells.
        assert _run(db) == (0, ["Sign-in is already local only."])
