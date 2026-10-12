"""The Users page and the index-kit upload refuse a name made only of dots.

Such a name could be created but never removed, demoted or reset: the
browser rewrites the URL the app would need and the dot-segment guard in
``middleware.py`` refuses a percent-encoded one with 400 before the route
runs, so an account named ``..`` kept whatever role it was given and only
direct database access could undo it (security review 2026-10).

The refusal is the model's, so nothing can reach the database by another
ingest path; these tests prove it where a person reaches it.
"""

import pytest

ORIGIN = {"Origin": "http://testserver"}
HX = {"HX-Request": "true", **ORIGIN}
DOT_ONLY = [".", "..", "..."]
STRONG = "Lab-Admin-Pass-42"

KIT_YAML = (
    b"index_mode: unique_dual\n"
    b"index_pairs:\n"
    b"  - id: DK-P1\n"
    b"    name: P1\n"
    b"    index1:\n"
    b"      name: i7-A01\n"
    b"      sequence: ATTACTCG\n"
    b"    index2:\n"
    b"      name: i5-A01\n"
    b"      sequence: TATAGCCT\n"
)


def _create_user(client, username, role="admin"):
    return client.post("/admin/users/create", headers=HX, data={
        "username": username, "display_name": "Dots", "role": role,
        "password": STRONG})


def _upload_kit(client, *, name, version, body=KIT_YAML):
    return client.post(
        "/indexes/upload",
        data={"index_mode": "unique_dual", "kit_name": name, "kit_version": version},
        files={"index_file": ("kit.yaml", body, "text/yaml")},
        headers=ORIGIN)


class TestTheUsersPageRefusesAUsernameOfDotsOnly:
    @pytest.mark.parametrize("username", DOT_ONLY)
    def test_it_is_refused_with_a_plain_message_and_nothing_is_stored(
            self, logged_in_client, fresh_app, username):
        _app, ctx, _db = fresh_app
        before = len(ctx.local_user_repo.list_all())

        refused = _create_user(logged_in_client, username)

        assert refused.status_code == 400
        assert "A username cannot be made only of dots." in refused.text
        assert not ctx.local_user_repo.exists(username)
        assert len(ctx.local_user_repo.list_all()) == before

    def test_an_ordinary_name_with_a_dot_in_it_is_still_created(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        created = _create_user(logged_in_client, "first.last", role="standard")

        assert created.status_code == 200
        assert ctx.local_user_repo.exists("first.last")

    def test_a_badly_charactered_name_is_answered_as_before(
            self, logged_in_client, fresh_app):
        """Control on the shape: the form's alphabet still rejects at 422,
        the dot-only rule did not move that refusal."""
        _app, ctx, _db = fresh_app

        refused = _create_user(logged_in_client, "a/b")

        assert refused.status_code == 422
        assert not ctx.local_user_repo.exists("a/b")


class TestTheIndexKitUploadRefusesANameOrVersionOfDotsOnly:
    @pytest.mark.parametrize("name", DOT_ONLY)
    def test_a_name_of_dots_stores_no_kit(self, logged_in_client, fresh_app, name):
        _app, ctx, _db = fresh_app
        before = len(ctx.index_kit_repo.list_all())

        refused = _upload_kit(logged_in_client, name=name, version="1.0")

        assert refused.headers.get("HX-Redirect") is None
        assert "Failed to parse file" in refused.text
        assert len(ctx.index_kit_repo.list_all()) == before

    @pytest.mark.parametrize("version", DOT_ONLY)
    def test_a_version_of_dots_stores_no_kit(self, logged_in_client, fresh_app, version):
        _app, ctx, _db = fresh_app
        before = len(ctx.index_kit_repo.list_all())

        refused = _upload_kit(logged_in_client, name="DotKit", version=version)

        assert refused.headers.get("HX-Redirect") is None
        assert "Failed to parse file" in refused.text
        assert len(ctx.index_kit_repo.list_all()) == before

    def test_a_name_of_dots_inside_the_file_stores_no_kit(
            self, logged_in_client, fresh_app):
        """The name can come from the file as well as from the form."""
        _app, ctx, _db = fresh_app
        before = len(ctx.index_kit_repo.list_all())

        refused = _upload_kit(logged_in_client, name="", version="",
                              body=b"name: '..'\nversion: '1.0'\n" + KIT_YAML)

        assert refused.headers.get("HX-Redirect") is None
        assert len(ctx.index_kit_repo.list_all()) == before

    def test_a_name_and_version_that_merely_hold_a_dot_still_upload(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        uploaded = _upload_kit(logged_in_client, name="IDT.v2", version="1.0")

        assert uploaded.headers.get("HX-Redirect") == "/indexes", uploaded.text[:300]
        assert ctx.index_kit_repo.exists("IDT.v2", "1.0")
