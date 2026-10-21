"""An uploaded kit file's problems are all shown, each with its line.

Anything the old parser did not refuse itself became one sentence --
"Failed to parse file. Please check the format and try again." -- with no
line, no key and no count, whether the file had one fault or forty. Step 3 of
the input rules (docs/design/2026-10-18-input-rules-design.md) gives the
upload the same problem list the Config Sync page has: file, line, place and
what is wrong. The form's own boxes are checked by the same rules, refused
rather than cut, and named.
"""

import pytest

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

    @pytest.mark.parametrize("box, value, says", [
        ("default_read1_override", "Y" * 257, "at most 256 characters"),
        ("default_read2_override", "Y*Z", "Y, I, U, N"),
        ("default_index1_override", "I601", "at most 600"),
    ])
    def test_an_override_box_is_refused_at_the_route(self, logged_in_client, fresh_app,
                                                    box, value, says):
        """A 402-character read pattern became a 410-character OverrideCycles
        on every sample the kit touched (fresh review of a382f57, P2-1)."""
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, GOOD, **{box: value})

        assert "HX-Redirect" not in resp.headers
        assert says in resp.text, resp.text
        assert ctx.index_kit_repo.list_all() == []

    @pytest.mark.parametrize("box", ["default_index1_override", "default_index2_override"])
    @pytest.mark.parametrize("value", ["N2I8", "I8garbage", "I8N2", "8", "X", "I", "I 8",
                                       # Plain digits only (fresh review of the P2 fixes, P3-4).
                                       "I\uff18", "I\u0968", "\u0131" + "8"])
    def test_an_index_override_is_read_whole_or_refused(self, logged_in_client, fresh_app,
                                                        box, value):
        """The box is I and a number of cycles, I* or empty, as the form
        says; anything else is refused naming the box. Only its start was
        read: N2I8 meant no override and I8garbage meant 8, and the check saw
        the converted value (outside review of 51eb3c4, P2-3)."""
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, GOOD, **{box: value})

        assert "HX-Redirect" not in resp.headers
        label = "Default Index1 Override" if box.endswith("1_override") else "Default Index2 Override"
        assert label in resp.text and "such as I8" in resp.text, resp.text
        assert ctx.index_kit_repo.list_all() == []
        (row,) = ctx.audit_event_repo.search(limit=10, event_prefix="index_kit.upload")
        assert (row.outcome, row.details["reason"]) == ("failure", "form_box_refused")

    @pytest.mark.parametrize("value, cycles", [
        ("I8", 8), ("i8", 8), (" I8 ", 8), ("I*", None), ("i*", None), ("", None)])
    def test_an_index_override_that_fits_is_saved(self, logged_in_client, fresh_app,
                                                  value, cycles):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, GOOD, default_index1_override=value)

        assert resp.headers.get("HX-Redirect") == "/indexes", resp.text
        (kit,) = ctx.index_kit_repo.list_all()
        assert kit.default_index1_cycles == cycles

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


class TestACsvRowWhoseQuotesDoNotCloseIsRefused:
    """A broken quote was read as it could be: ``P1,"ACGT"NNNN`` saved the
    sequence ACGTNNNN and a quote never closed was accepted (outside review
    of 51eb3c4, P2-2). The upload is refused naming the file's line."""

    @pytest.mark.parametrize("content, line", [
        (b'name,index\nP1,"ACGT"NNNN\nP2,TCCGGAGA\n', 2),
        (b'name,index\nP1,ACGTACGT\nP2,"TCCGGAGA\n', 3),
        (b'[i7]\nname,sequence\nA,ATTACTCG\nB,"TCCG"GAGA\n\n[i5]\nname,sequence\n01,TATAGCCT\n', 4),
        (b'[i7]\nname,sequence\nA,ATTACTCG\n\n[i5]\nname,sequence\n01,"TATA"GCCT\n', 7),
        # A blank line before the row is not the row (fresh review of the
        # P2 fixes, P2-1).
        (b'name,index,index2\nD701,ATTACTCG,TATAGCCT\n\nD702,"TCCG"GAGA,ATAGAGGC\n', 4),
        (b'name,index,index2\r\nD701,ATTACTCG,TATAGCCT\r\n\r\n\r\nD702,"TCCG"GAGA,ATAGAGGC\r\n', 5),
        # A line break in a column no one reads is refused too, as the guide says.
        (b'name,index,Description\nD701,ATTACTCG,"two\nlines"\nD702,TCCGGAGA,x\n', 2),
    ])
    def test_the_upload_is_refused_naming_the_line(self, logged_in_client, fresh_app,
                                                  content, line):
        _app, ctx, _db = fresh_app
        mode = "combinatorial" if content.startswith(b"[i7]") else "single"

        resp = _upload(logged_in_client, content, mode=mode, filename="kit.csv",
                       kit_name="Quote Kit", kit_version="1.0")

        assert "HX-Redirect" not in resp.headers
        assert f"Line {line}:" in resp.text and "double quote" in resp.text, resp.text
        assert ctx.index_kit_repo.list_all() == []
        (row,) = ctx.audit_event_repo.search(limit=10, event_prefix="index_kit.upload")
        assert (row.outcome, row.details["reason"]) == ("failure", "table_not_read")


class TestACellUnderAColumnWithNoNameIsRefused:
    """A column whose header name is blank was read by no one: in a Single
    upload an i5 there was dropped, and with two such columns the second's
    empty cell took the first one's place, so a row of one sequence read as
    empty and was skipped (second fresh review of the P2 fixes). A row
    with a cell there is refused naming its line, as a cell past the last
    column always was."""

    @pytest.mark.parametrize("content, mode, lines", [
        (b"name,index,\nA,ACGTACGT,TTGGCCAA\nB,GGGGCCCC,AACCGGTT\n", "single", "line 2, line 3"),
        (b"name,index,,\nA,ACGTACGT,,\n,,GGGGCCCC,\n", "single", "line 3"),
        (b"name, ,index\nA,x,ACGTACGT\n", "single", "line 2"),
        (b"name,index,_\nA,ACGTACGT,TTGGCCAA\nB,GGGGCCCC,AACCGGTT\n", "single", "line 2, line 3"),
        # pandas' to_csv() with its defaults writes row numbers under no name.
        (b",name,index\n0,A,ACGTACGT\n1,B,GGGGCCCC\n", "single", "line 2, line 3"),
        (b"[i7]\nname,sequence,\nA,ATTACTCG,TATAGCCT\n\n[i5]\nname,sequence\n01,TATAGCCT\n",
         "combinatorial", "line 3"),
    ])
    def test_the_upload_is_refused_naming_the_rows(self, logged_in_client, fresh_app,
                                                   content, mode, lines):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, content, mode=mode, filename="kit.csv",
                       kit_name="Blank Kit", kit_version="1.0")

        assert "HX-Redirect" not in resp.headers
        assert f"saved: {lines}." in resp.text and "no column name" in resp.text, resp.text
        assert ctx.index_kit_repo.list_all() == []
        (row,) = ctx.audit_event_repo.search(limit=10, event_prefix="index_kit.upload")
        assert (row.outcome, row.details["reason"]) == ("failure", "columns_not_read")

    @pytest.mark.parametrize("content", [
        b"name,index,\nA,ACGTACGT,\nB,GGGGCCCC,\n",
        b"name,index,,\r\nA,ACGTACGT,,\r\nB,GGGGCCCC, ,\r\n",
        b"name,index, , ,_\nA,ACGTACGT,,,\nB,GGGGCCCC,,,\n",
    ])
    def test_an_empty_column_with_no_name_is_still_saved(self, logged_in_client, fresh_app,
                                                         content):
        """A spreadsheet's trailing separators: nothing in the column."""
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, content, filename="kit.csv",
                       kit_name="Blank Kit", kit_version="1.0")

        assert resp.headers.get("HX-Redirect") == "/indexes", resp.text
        (kit,) = ctx.index_kit_repo.list_all()
        assert [index.sequence for index in kit.i7_indexes] == ["ACGTACGT", "GGGGCCCC"]
