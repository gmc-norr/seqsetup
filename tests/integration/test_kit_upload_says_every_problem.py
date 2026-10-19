"""An uploaded kit file's problems are all shown, each with its line.

Anything the old parser did not refuse itself became one sentence --
"Failed to parse file. Please check the format and try again." -- with no
line, no key and no count, whether the file had one fault or forty. Step 3 of
the input rules (docs/design/2026-10-18-input-rules-design.md) gives the
upload the same problem list the Config Sync page has: file, line, place and
what is wrong. The form's own boxes are checked by the same rules, refused
rather than cut, and named.
"""

ORIGIN = {"Origin": "http://testserver"}

GOOD = (b"name: Probe Kit\nversion: '1.0'\nindex_mode: single\n"
        b"i7_indexes:\n  - name: A1\n    sequence: ATTACTCG\n")


def _upload(client, content, mode="single", filename="kit.yaml", **boxes):
    return client.post(
        "/indexes/upload",
        data={"index_mode": mode, **boxes},
        files={"index_file": (filename, content, "text/yaml")},
        headers=ORIGIN,
    )


class TestEveryProblemIsShownWithItsLine:

    def test_a_good_file_is_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, GOOD)

        assert resp.headers.get("HX-Redirect") == "/indexes"
        (kit,) = ctx.index_kit_repo.list_all()
        assert (kit.name, kit.version) == ("Probe Kit", "1.0")

    def test_two_problems_are_both_named_with_their_lines(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        content = GOOD + b"ownr: me\nis_fixed_layout: 'no'\n"

        resp = _upload(logged_in_client, content)

        assert "HX-Redirect" not in resp.headers
        assert "ownr" in resp.text and "line 7" in resp.text
        assert "is_fixed_layout" in resp.text and "line 8" in resp.text
        assert "true or false" in resp.text
        assert "Failed to parse file" not in resp.text
        # The list fragment, not one sentence: it carries a title and one
        # entry per problem (_error_fragment_list, not _error_fragment).
        assert "This kit was not saved:" in resp.text
        assert resp.text.count("line 7") == 1 and resp.text.count("line 8") == 1
        assert ctx.index_kit_repo.list_all() == []
        (row,) = ctx.audit_event_repo.search(limit=10, event_prefix="index_kit.upload")
        assert (row.outcome, row.details["reason"]) == ("failure", "kit_file_problems")

    def test_broken_yaml_names_its_line_and_column(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, b"name: [unclosed\n")

        assert "HX-Redirect" not in resp.headers
        assert "Failed to parse file" not in resp.text
        assert "line 2" in resp.text and "list" in resp.text
        assert ctx.index_kit_repo.list_all() == []


class TestTheFormSBoxesAreCheckedToo:

    def test_a_kit_name_over_256_characters_is_refused_naming_the_box(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, GOOD, kit_name="N" * 257)

        assert "HX-Redirect" not in resp.headers
        assert "Kit name" in resp.text and "at most 256 characters" in resp.text
        assert ctx.index_kit_repo.list_all() == []
        (row,) = ctx.audit_event_repo.search(limit=10, event_prefix="index_kit.upload")
        assert (row.outcome, row.details["reason"]) == ("failure", "form_box_refused")

    def test_an_adapter_box_of_8000_bases_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, GOOD, adapter_read1="A" * 8000)

        assert "HX-Redirect" not in resp.headers
        assert "Adapter Read 1" in resp.text and "at most 1000 characters" in resp.text
        assert ctx.index_kit_repo.list_all() == []

    def test_a_kit_name_of_256_characters_is_saved_as_written(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, GOOD, kit_name="N" * 256)

        assert resp.headers.get("HX-Redirect") == "/indexes"
        (kit,) = ctx.index_kit_repo.list_all()
        assert kit.name == "N" * 256


class TestACsvNeedsTheTwoBoxes:
    """Neither CSV shape carries a name or a version, so the kit was stored
    under the upload's filename and the invented version "1.0"."""

    def test_a_csv_with_no_boxes_is_refused_naming_them(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, b"name,index\nA1,ATTACTCG\n",
                       filename="my_kit_file.csv")

        assert "HX-Redirect" not in resp.headers
        assert "Kit name box" in resp.text
        assert ctx.index_kit_repo.list_all() == []
        (row,) = ctx.audit_event_repo.search(limit=10, event_prefix="index_kit.upload")
        assert (row.outcome, row.details["reason"]) == ("failure", "kit_names_nothing")

    def test_a_csv_with_both_boxes_is_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, b"name,index\nA1,ATTACTCG\n",
                       filename="my_kit_file.csv", kit_name="Bench kit", kit_version="2.0")

        assert resp.headers.get("HX-Redirect") == "/indexes"
        (kit,) = ctx.index_kit_repo.list_all()
        assert (kit.name, kit.version) == ("Bench kit", "2.0")


class TestAFileSModeMustBeTheModePicked:

    def test_a_file_naming_another_mode_is_refused_naming_both(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        content = (b"name: Probe Kit\nversion: '1.0'\nindex_mode: combinatorial\n"
                   b"i7_indexes:\n  - name: A1\n    sequence: ATTACTCG\n")

        resp = _upload(logged_in_client, content, mode="single")

        assert "HX-Redirect" not in resp.headers
        assert "combinatorial" in resp.text and "single" in resp.text
        assert ctx.index_kit_repo.list_all() == []
        (row,) = ctx.audit_event_repo.search(limit=10, event_prefix="index_kit.upload")
        assert (row.outcome, row.details["reason"]) == ("failure", "kit_mode_differs")


class TestARefusedKitFileSProblemsReachTheSync:
    """The sync puts every problem of a file in its own list, which the
    Config Sync page shows as a table and the audit row carries: the
    refusal's own line names the first problem only."""

    def test_the_sync_result_carries_every_problem_of_the_file(self, fresh_app, monkeypatch):
        from .test_synced_kit_indexes import _sync_with_kits

        _app, ctx, _db = fresh_app
        bad = ("name: Lab Kit\nversion: '1.0'\nindex_mode: single\nownr: me\n"
               "i7_indexes:\n  - name: A1\n    sequence: ATTACTCG\n"
               "is_fixed_layout: 'no'\n")

        result = _sync_with_kits(ctx, monkeypatch, {"lab.yaml": bad})

        places = [(p.file, p.line, tuple(p.path)) for p in result.problems]
        assert ("index_kits/lab.yaml", 4, ("ownr",)) in places, places
        assert ("index_kits/lab.yaml", 8, ("is_fixed_layout",)) in places, places
