"""pixi run create-admin (spec 2026-09-28 group 2b, N-20, review P2/P3;
plan review 1, P3/P4)."""

import tomllib
from pathlib import Path

import pytest
from pymongo.errors import AutoReconnect

from seqsetup import create_admin
from seqsetup.models.local_user import LocalUser
from seqsetup.models.user import UserRole
from seqsetup.repositories.auth_config_repo import AuthConfigRepository
from seqsetup.repositories.local_user_repo import LocalUserRepository
from tests.fake_directory import use_directory

ORIGIN = {"Origin": "http://testserver"}
STRONG = "Lab-Admin-Pass-42"
ROOT = Path(__file__).resolve().parents[2]
CREATED = "Admin 'labadmin' created. Sign in on the web page."
UNSURE = ("The database failed while saving (AutoReconnect), so it is not known whether "
          "'labadmin' was created. Run 'pixi run create-admin' again with the same name: if it "
          "says the account already exists, it was created.")
TOO_LONG = ("Password must be at most 72 bytes. Most characters are 1 byte; letters like "
            "å, ä and ö are 2.")
# 70 characters, 90 bytes: å, ä and ö are 2 bytes each.
LONG_MULTIBYTE = "Räksmörgås-öl-" * 5


def _run(db, *answers, secrets=(STRONG, STRONG)):
    asked, hidden, said = list(answers), list(secrets), []
    code = create_admin.main(ask=lambda prompt: asked.pop(0),
                             ask_secret=lambda prompt: hidden.pop(0),
                             get_db=lambda: db, say=said.append)
    return code, said


def _login(client, name, password):
    return client.post("/login/submit", data={"username": name, "password": password},
                       headers=ORIGIN, follow_redirects=False)


def _boom():
    raise ConnectionError("no database")


def _lost(*args, **kwargs):
    raise AutoReconnect("connection closed")


class TestCreateAdmin:
    """The first admin is made on the server, with the Users page's rules."""

    def test_the_new_admin_signs_in(self, client, fresh_app):
        _app, ctx, db = fresh_app
        code, said = _run(db, "labadmin", "Lab Admin", "")
        assert (code, said) == (0, [CREATED])
        assert ctx.local_user_repo.get_by_username("labadmin").role is UserRole.ADMIN
        assert _login(client, "labadmin", STRONG).status_code == 303

    def test_a_64_character_name_signs_in(self, client, fresh_app):
        _app, _ctx, db = fresh_app
        assert _run(db, "a" * 64, "Long", "")[0] == 0
        assert _login(client, "a" * 64, STRONG).status_code == 303

    def test_a_65_character_name_is_refused(self, fresh_app):
        _app, ctx, db = fresh_app
        assert _run(db, "a" * 65, "Long", "") == (1, [
            "A username is 1-64 letters, digits, '.', '_', '@' or '-'. Nothing was changed."])
        assert not ctx.local_user_repo.exists("a" * 65)

    def test_a_weak_password_is_refused(self, fresh_app):
        _app, ctx, db = fresh_app
        assert _run(db, "labadmin", "Lab Admin", "", secrets=("admin123", "admin123")) == (1, [
            "Password is on the list of well-known weak/default passwords. Nothing was changed."])
        assert not ctx.local_user_repo.exists("labadmin")

    def test_different_passwords_are_refused(self, fresh_app):
        _app, ctx, db = fresh_app
        assert _run(db, "labadmin", "Lab Admin", "", secrets=(STRONG, STRONG + "x")) == (1, [
            "The two passwords differ. Nothing was changed."])
        assert not ctx.local_user_repo.exists("labadmin")

    def test_an_existing_account_is_never_changed(self, fresh_app):
        _app, ctx, db = fresh_app
        ctx.local_user_repo.save(LocalUser(username="labadmin", display_name="Old",
                                           role=UserRole.STANDARD, password_hash="h"))
        # Full answers, so a missing name check reaches the insert-only create().
        assert _run(db, "labadmin", "Lab Admin", "") == (1, [
            "An account named 'labadmin' already exists. Nothing was changed."])
        kept = ctx.local_user_repo.get_by_username("labadmin")
        assert (kept.display_name, kept.role, kept.password_hash) == ("Old", UserRole.STANDARD, "h")

    def test_an_empty_display_name_is_refused(self, fresh_app):
        _app, ctx, db = fresh_app
        assert _run(db, "labadmin", "   ") == (1, ["A display name is required. Nothing was changed."])
        assert not ctx.local_user_repo.exists("labadmin")

    def test_an_unreachable_database_changes_nothing(self):
        said = []
        assert create_admin.main(ask=lambda p: "x", ask_secret=lambda p: STRONG,
                                 get_db=_boom, say=said.append) == 1
        assert said == ["Could not reach the database. Nothing was changed."]

    def test_the_audit_trail_records_it(self, fresh_app):
        _app, ctx, db = fresh_app
        _run(db, "labadmin", "Lab Admin", "")
        (event,) = ctx.audit_event_repo.search(limit=10, event_prefix="user.created")
        assert (event.actor, event.target, event.details["role"], event.details["via"]) == (
            "create-admin", "labadmin", "admin", "server command")

    def test_it_warns_when_the_admin_cannot_sign_in_yet(self, fresh_app):
        # Directory sign-in on and local fallback off (review P2).
        _app, ctx, db = fresh_app
        use_directory(ctx, fallback=False)
        assert _run(db, "labadmin", "Lab Admin", "") == (0, [CREATED, (
            "Directory sign-in is on and local fallback is off, so this admin cannot sign in "
            "yet. Run 'pixi run use-local-sign-in' first, or turn on local fallback.")])

    def test_no_warning_when_local_sign_in_works(self, fresh_app):
        _app, _ctx, db = fresh_app
        assert _run(db, "labadmin", "Lab Admin", "") == (0, [CREATED])

    def test_the_pixi_task_runs_the_command(self):
        tasks = tomllib.loads((ROOT / "pixi.toml").read_text())["tasks"]
        assert tasks["create-admin"] == "PYTHONPATH=src python -m seqsetup.create_admin"

    def test_create_never_overwrites(self, fresh_app):
        _app, _ctx, db = fresh_app
        repo = LocalUserRepository(db)
        assert repo.create(LocalUser(username="x", display_name="First")) is True
        assert repo.create(LocalUser(username="x", display_name="Second")) is False
        assert repo.get_by_username("x").display_name == "First"


class TestDatabaseFailures:
    """A failure before the save changes nothing; a failure during the save
    leaves the outcome unknown, and the command says so (plan review 1, P3)."""

    @pytest.mark.parametrize("read", [(LocalUserRepository, "exists"), (AuthConfigRepository, "get")],
                             ids=["accounts", "sign-in-settings"])
    def test_a_failed_read_changes_nothing(self, fresh_app, monkeypatch, read):
        _app, ctx, db = fresh_app
        monkeypatch.setattr(*read, _lost)
        assert _run(db, "labadmin", "Lab Admin", "") == (1, [
            "The database failed while reading (AutoReconnect). Nothing was changed."])
        monkeypatch.undo()
        assert not ctx.local_user_repo.exists("labadmin")

    def test_a_lost_answer_while_saving_says_it_is_not_known(self, fresh_app, monkeypatch):
        # The insert reaches the database, then its answer is lost.
        _app, ctx, db = fresh_app
        real_create = LocalUserRepository.create

        def create_then_lose(self, user):
            real_create(self, user)
            raise AutoReconnect("connection closed")

        monkeypatch.setattr(LocalUserRepository, "create", create_then_lose)
        assert _run(db, "labadmin", "Lab Admin", "") == (1, [UNSURE])
        monkeypatch.undo()
        # What the message says to do works: running it again tells.
        assert _run(db, "labadmin") == (1, [
            "An account named 'labadmin' already exists. Nothing was changed."])


class TestPasswordsOver72Bytes:
    """The 72-byte rule is in the model, so create-admin and the Users page
    both refuse a long password with a clear message, never a crash
    (plan review 1, P4)."""

    @pytest.mark.parametrize("password", [STRONG * 5, LONG_MULTIBYTE],
                             ids=["ascii-85-bytes", "multibyte-70-characters"])
    def test_create_admin_refuses_it(self, fresh_app, password):
        _app, ctx, db = fresh_app
        assert _run(db, "labadmin", "Lab Admin", "", secrets=(password, password)) == (1, [
            TOO_LONG + " Nothing was changed."])
        assert not ctx.local_user_repo.exists("labadmin")

    def test_the_users_page_refuses_it(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        response = logged_in_client.post("/admin/users/create", headers=ORIGIN, data={
            "username": "longpass", "display_name": "Long", "role": "standard",
            "password": LONG_MULTIBYTE})
        assert response.status_code == 200
        assert TOO_LONG in response.text
        assert not ctx.local_user_repo.exists("longpass")
