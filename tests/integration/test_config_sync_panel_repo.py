"""The config-sync panel does not show one repository's last sync under
another repository's name.

The panel's Repo line comes from the saved configuration and its Last sync
line from the stored status, so the moment an admin saved a new repository URL
the panel read as though that repository had been synced -- with the old
repository's time, status, count and message. The panel now says, when it
knows the last sync was of another repository or branch, that this one has not
been synced yet, and which one the figures below belong to. It says "the
repository and branch saved here", not "this repository", because a
branch-only change leaves the repository synced; and it compares the URLs
as the sync normalizes them, so re-saving one with a trailing slash or
.git is not an alarm (batch 4 review fix F).
"""

from .test_group_a4 import TESTS_BEFORE, _sync_tests
from .test_paste_preview import ORIGIN

REPO = "https://github.com/example/config"
OTHER = "https://github.com/example/other"
NOT_SYNCED = "The repository and branch saved here have not been synced yet."


def _panel(page: str) -> str:
    """The config-sync page from its last-sync element to the config form."""
    start = page.index('<div id="last-sync"')
    return page[start:page.index("<form", start)]


def _save_repo(client, url: str, branch: str = "main"):
    resp = client.post("/admin/config-sync/config",
                       data={"github_repo_url": url, "github_branch": branch},
                       headers=ORIGIN)
    assert resp.status_code == 200, resp.text[:200]
    return resp


class TestTheLastSyncIsAttributedToItsRepo:
    def test_a_newly_saved_repo_says_it_has_not_been_synced(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message

        _save_repo(logged_in_client, OTHER)
        panel = _panel(logged_in_client.get("/admin/config-sync").text)

        assert NOT_SYNCED in panel
        assert REPO in panel
        assert "Synced 1 application profiles, 3 test profiles" in panel

    def test_a_new_branch_of_the_same_repo_says_it_too(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message

        _save_repo(logged_in_client, REPO, branch="release")
        panel = _panel(logged_in_client.get("/admin/config-sync").text)

        assert NOT_SYNCED in panel
        assert "main" in panel

    def test_the_repo_that_was_synced_does_not_say_it(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message

        _save_repo(logged_in_client, REPO)
        panel = _panel(logged_in_client.get("/admin/config-sync").text)

        assert NOT_SYNCED not in panel
        assert "Synced 1 application profiles, 3 test profiles" in panel

    def test_a_sync_stores_the_repo_and_branch_it_read(
            self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message

        status = ctx.profile_sync_config_repo.get()
        assert (status.last_sync_repo_url, status.last_sync_branch) == (REPO, "main")

    def test_a_status_stored_before_this_was_remembered_raises_no_alarm(
            self, logged_in_client, fresh_app, monkeypatch):
        """A configuration saved by an older SeqSetup has no last-sync repo.
        The panel says nothing rather than claiming the repo is unsynced."""
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message
        config = ctx.profile_sync_config_repo.get()
        config.last_sync_repo_url = ""
        config.last_sync_branch = ""
        ctx.profile_sync_config_repo.save(config)

        _save_repo(logged_in_client, OTHER)
        panel = _panel(logged_in_client.get("/admin/config-sync").text)

        assert NOT_SYNCED not in panel

    def test_a_repo_with_no_sync_at_all_says_only_the_dash(
            self, logged_in_client, fresh_app):
        _save_repo(logged_in_client, REPO)
        panel = _panel(logged_in_client.get("/admin/config-sync").text)

        assert "<strong>Last sync:</strong> —</div>" in panel
        assert NOT_SYNCED not in panel


class TestTheSameRepoWrittenAnotherWayIsNoAlarm:
    """_parse_repo_url normalizes a trailing slash and a .git suffix away
    before fetching, so comparing the raw strings raised the alarm about a
    repository synced an hour ago (batch 4 review fix F)."""

    def test_the_same_url_with_a_trailing_slash(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message

        _save_repo(logged_in_client, REPO + "/")
        panel = _panel(logged_in_client.get("/admin/config-sync").text)

        assert NOT_SYNCED not in panel
        assert "Synced 1 application profiles, 3 test profiles" in panel

    def test_the_same_url_with_a_dot_git_suffix(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message

        _save_repo(logged_in_client, REPO + ".git")
        panel = _panel(logged_in_client.get("/admin/config-sync").text)

        assert NOT_SYNCED not in panel

    def test_a_url_that_will_not_parse_is_compared_as_written(
            self, logged_in_client, fresh_app, monkeypatch):
        """Nothing to normalize, so the raw strings decide: this one differs
        from the synced repository and the panel says so."""
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message

        _save_repo(logged_in_client, "not-a-repo")
        panel = _panel(logged_in_client.get("/admin/config-sync").text)

        assert NOT_SYNCED in panel
        assert REPO in panel

    def test_another_repo_of_the_same_owner_still_says_it(
            self, logged_in_client, fresh_app, monkeypatch):
        """Normalizing must not collapse two repositories into one."""
        _app, ctx, _db = fresh_app
        ok, message, _logged = _sync_tests(ctx, monkeypatch, TESTS_BEFORE)
        assert ok, message

        _save_repo(logged_in_client, "https://github.com/example/config-other")
        panel = _panel(logged_in_client.get("/admin/config-sync").text)

        assert NOT_SYNCED in panel
