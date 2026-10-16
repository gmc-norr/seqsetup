"""Two admin requests at once cannot leave no admin, make two accounts of
one name, or bring a deleted account back (outside review of f490536,
finding F15).

The last-admin guard, and the "name already taken" check, are
check-then-write: two requests on the server's thread pool can both pass
the check. And ``edit_user`` loaded the account and saved it with
``replace_one(..., upsert=True)``, so an edit that loaded before another
admin deleted the account wrote it back -- a deleted account returns, with
its password hash, able to sign in.

The interleaving is forced with a barrier inside the check, the way two
requests can meet. The barrier gives up after 2 s, so a fix that
serialises the two (one lock across check and write) is not held up by it:
the second request then sees the first one's write.
"""

import concurrent.futures
import threading

import pytest
from starlette.testclient import TestClient

from seqsetup.models.local_user import LocalUser
from seqsetup.models.user import UserRole

ORIGIN = {"Origin": "http://testserver"}


def _meet(barrier):
    try:
        barrier.wait(timeout=2)
    except threading.BrokenBarrierError:
        pass


def _second_admin(app, ctx, username="admin-two", password="Review-Adm1n-Two!"):
    user = LocalUser(username=username, display_name="Admin Two", role=UserRole.ADMIN)
    user.set_password(password)
    ctx.local_user_repo.save(user)
    client = TestClient(app, base_url="http://testserver")
    login = client.post("/login/submit", data={"username": username, "password": password},
                        headers=ORIGIN, follow_redirects=False)
    assert login.status_code == 303
    return client


def _admins(ctx):
    return ctx.local_user_repo.collection.count_documents({"role": UserRole.ADMIN.value})


class TestTheLastAdminCannotBeRacedAway:

    @pytest.mark.parametrize("second_action", ["delete", "demote"])
    def test_two_admins_removing_each_other_leave_one(
            self, fresh_app, logged_in_client, monkeypatch, second_action):
        app, ctx, _db = fresh_app
        client_two = _second_admin(app, ctx)
        assert _admins(ctx) == 2
        real_count = ctx.local_user_repo.count_admins
        barrier = threading.Barrier(2)

        def count_then_meet():
            n = real_count()
            _meet(barrier)
            return n

        monkeypatch.setattr(ctx.local_user_repo, "count_admins", count_then_meet)

        def second():
            if second_action == "delete":
                return client_two.delete("/admin/users/admin-test", headers=ORIGIN)
            return client_two.post("/admin/users/admin-test/edit", headers=ORIGIN,
                                   data={"display_name": "Test Admin", "role": "standard"})

        with concurrent.futures.ThreadPoolExecutor() as pool:
            a = pool.submit(logged_in_client.delete, "/admin/users/admin-two", headers=ORIGIN)
            b = pool.submit(second)
            a.result(), b.result()

        assert _admins(ctx) >= 1, "both requests passed the last-admin check: no admin is left"

    def test_control_one_admin_cannot_remove_itself(self, fresh_app, logged_in_client):
        _app, ctx, _db = fresh_app
        assert _admins(ctx) == 1

        resp = logged_in_client.delete("/admin/users/admin-test", headers=ORIGIN)

        assert "Cannot delete the last admin user" in resp.text
        assert _admins(ctx) == 1


class TestCreatingAUserNeverReplacesOne:

    def test_two_creates_of_one_name_make_one_account(
            self, fresh_app, logged_in_client, monkeypatch):
        app, ctx, _db = fresh_app
        client_two = _second_admin(app, ctx)
        real_exists = ctx.local_user_repo.exists
        barrier = threading.Barrier(2)

        def exists_then_meet(username):
            found = real_exists(username)
            _meet(barrier)
            return found

        monkeypatch.setattr(ctx.local_user_repo, "exists", exists_then_meet)

        def create(client, display):
            return client.post("/admin/users/create", headers=ORIGIN, data={
                "username": "newcomer", "display_name": display, "role": "standard",
                "password": "Newc0mer-Passw0rd!" + display})

        with concurrent.futures.ThreadPoolExecutor() as pool:
            a = pool.submit(create, logged_in_client, "First")
            b = pool.submit(create, client_two, "Second")
            answers = [a.result().text, b.result().text]

        created = sum("created successfully" in text for text in answers)
        refused = sum("already exists" in text for text in answers)
        assert (created, refused) == (1, 1), (
            f"{created} requests said the account was created, {refused} that the name is taken")

    def test_control_a_plain_create_still_works(self, fresh_app, logged_in_client):
        _app, ctx, _db = fresh_app

        resp = logged_in_client.post("/admin/users/create", headers=ORIGIN, data={
            "username": "solo", "display_name": "Solo", "role": "standard",
            "password": "S0lo-Passw0rd!x"})

        assert "created successfully" in resp.text, resp.text[:300]
        assert ctx.local_user_repo.get_by_username("solo") is not None

    def test_control_a_taken_name_is_still_refused(self, fresh_app, logged_in_client):
        _app, ctx, _db = fresh_app
        existing = LocalUser(username="taken", display_name="Keep me", role=UserRole.STANDARD)
        existing.set_password("Tak3n-Passw0rd!")
        ctx.local_user_repo.save(existing)

        resp = logged_in_client.post("/admin/users/create", headers=ORIGIN, data={
            "username": "taken", "display_name": "Overwrite", "role": "admin",
            "password": "0ther-Passw0rd!x"})

        assert "already exists" in resp.text, resp.text[:300]
        kept = ctx.local_user_repo.get_by_username("taken")
        assert kept.display_name == "Keep me", "the second create replaced the account"
        assert kept.role == UserRole.STANDARD


class TestAnEditDoesNotBringBackADeletedUser:

    def test_an_edit_racing_a_delete_does_not_recreate_the_account(
            self, fresh_app, logged_in_client, monkeypatch):
        """End to end, and it really does force the order: the edit's write
        waits for the delete. With _ADMIN_WRITE_LOCK the delete is blocked on
        the lock, so the wait runs its 5 s out and the write then has nothing
        to resurrect -- the lock alone closes this, which is why reverting
        the route to save() reddens nothing (break check L4, recorded as
        inert). The write itself is pinned by
        TestTheRepositoryWriteThatWillNotCreate below (L5, L6)."""
        app, ctx, _db = fresh_app
        client_two = _second_admin(app, ctx)
        leaver = LocalUser(username="leaver", display_name="Leaver", role=UserRole.STANDARD)
        leaver.set_password("Leav3r-Passw0rd!")
        ctx.local_user_repo.save(leaver)
        repo = ctx.local_user_repo
        real_get, real_update = repo.get_by_username, repo.update_existing
        loaded, deleted = threading.Event(), threading.Event()

        def get_then_signal(username):
            found = real_get(username)
            if username == "leaver":
                loaded.set()
            return found

        def write_after_the_delete(user):
            # The edit writes only once the delete has finished: the exact
            # order an upsert turns into a resurrection. Patched on the
            # writer the route actually calls -- the first cut of this test
            # patched save(), which edit_user no longer uses, so nothing was
            # forced at all (review of e355460, P3-1).
            if user.username == "leaver":
                deleted.wait(timeout=5)
            return real_update(user)

        monkeypatch.setattr(repo, "get_by_username", get_then_signal)
        monkeypatch.setattr(repo, "update_existing", write_after_the_delete)

        def edit():
            return logged_in_client.post("/admin/users/leaver/edit", headers=ORIGIN, data={
                "display_name": "Edited", "role": "standard"})

        def remove():
            assert loaded.wait(timeout=5), "the edit never loaded the account"
            answer = client_two.delete("/admin/users/leaver", headers=ORIGIN)
            deleted.set()
            return answer

        with concurrent.futures.ThreadPoolExecutor() as pool:
            a = pool.submit(edit)
            b = pool.submit(remove)
            a.result(), b.result()

        assert repo.get_by_username("leaver") is None, (
            "the edit wrote the deleted account back: it can sign in again")

    def test_an_edit_of_a_name_that_is_gone_says_so(self, fresh_app, logged_in_client):
        _app, ctx, _db = fresh_app

        resp = logged_in_client.post("/admin/users/ghost/edit", headers=ORIGIN, data={
            "display_name": "Ghost", "role": "standard"})

        assert "not found" in resp.text, resp.text[:300]
        assert ctx.local_user_repo.get_by_username("ghost") is None

    def test_control_a_plain_edit_still_saves(self, fresh_app, logged_in_client):
        _app, ctx, _db = fresh_app
        user = LocalUser(username="editme", display_name="Before", role=UserRole.STANDARD)
        user.set_password("Editm3-Passw0rd!")
        ctx.local_user_repo.save(user)

        resp = logged_in_client.post("/admin/users/editme/edit", headers=ORIGIN, data={
            "display_name": "After", "role": "standard"})

        assert "updated" in resp.text, resp.text[:300]
        assert ctx.local_user_repo.get_by_username("editme").display_name == "After"


class TestTheRepositoryWriteThatWillNotCreate:
    """``_ADMIN_WRITE_LOCK`` already stops a delete landing between the
    edit's load and its write, so the route-level race cannot be forced any
    more. ``update_existing`` is the second line of defence -- it is what
    makes the write itself unable to resurrect an account -- so it is
    tested here directly. (Break checks L5 and L6.)"""

    def test_it_writes_an_account_that_is_still_there(self, fresh_app):
        _app, ctx, _db = fresh_app
        user = LocalUser(username="stays", display_name="Before", role=UserRole.STANDARD)
        user.set_password("Stay5-Passw0rd!")
        ctx.local_user_repo.save(user)

        user.display_name = "After"
        assert ctx.local_user_repo.update_existing(user) is True
        assert ctx.local_user_repo.get_by_username("stays").display_name == "After"

    def test_it_writes_nothing_and_says_so_when_the_account_is_gone(self, fresh_app):
        _app, ctx, _db = fresh_app
        user = LocalUser(username="gone", display_name="Gone", role=UserRole.STANDARD)
        user.set_password("G0ne-Passw0rd!")

        assert ctx.local_user_repo.update_existing(user) is False
        assert ctx.local_user_repo.get_by_username("gone") is None, (
            "update_existing created the account it was told to update")

    def test_save_by_contrast_would_have_created_it(self, fresh_app):
        """Why update_existing exists: the inherited save upserts."""
        _app, ctx, _db = fresh_app
        user = LocalUser(username="upserted", display_name="Upserted",
                         role=UserRole.STANDARD)
        user.set_password("Upsert3d-Passw0rd!")

        ctx.local_user_repo.save(user)

        assert ctx.local_user_repo.get_by_username("upserted") is not None


class TestTheInvariantsTheLockRelies0n:
    """Two things a later change could quietly undo, pinned here because
    nothing else would notice (review of e355460, P3-3 and P3-4)."""

    def test_no_code_writes_a_local_user_through_the_upserting_save(self):
        """LocalUserRepository inherits BaseRepository.save, which upserts.
        update_existing exists because that save can resurrect a deleted
        account. Test seeding may use save; shipped code may not."""
        import re
        from pathlib import Path
        root = Path(__file__).resolve().parents[2] / "src"
        offenders = []
        # The handlers bind it to a local name (`repo = ctx.local_user_repo`),
        # so looking only for "local_user_repo.save(" missed the shape a real
        # regression takes -- break check L4 was green until this widened.
        call = re.compile(r"(?:local_user_repo|\brepo)\s*\.\s*save\s*\(")
        for path in root.rglob("*.py"):
            text = path.read_text()
            if "local_user_repo" not in text:
                continue
            for number, line in enumerate(text.splitlines(), 1):
                if call.search(line):
                    offenders.append(f"{path.relative_to(root)}:{number}: {line.strip()}")
        assert offenders == [], (
            "shipped code writes a local user with the upserting save; use "
            f"update_existing (an edit) or create (a new account):\n" + "\n".join(offenders))

    def test_the_three_admin_write_handlers_are_plain_def(self):
        """_ADMIN_WRITE_LOCK blocks the thread that holds it. Starlette runs a
        plain ``def`` handler on a worker thread, so blocking is fine; an
        ``async def`` one runs on the event loop that serves everyone, and
        the block would stall every request."""
        import inspect
        from seqsetup.routes import local_users
        for name in ("create_user", "edit_user", "delete_user"):
            handler = getattr(local_users, name)
            assert not inspect.iscoroutinefunction(handler), (
                f"{name} is async def: _ADMIN_WRITE_LOCK would block the event loop")
