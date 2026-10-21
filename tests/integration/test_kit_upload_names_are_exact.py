"""A kit file whose index or pair names differ only in a space at an end, or
hold a hidden character, is refused and nothing is saved.

A CSV upload kept the spaces: ``D701`` and ``D701 `` were two pairs, the
duplicate-name check (exact text) passed, and the kit was saved with two chips
that both read "D701" in the index panel -- HTML hides the space, and the chip
shows the name only -- carrying different sequences (review OPSDOCS-2).

Illumina's own two shapes, the TSV and the YAML, strip a cell in their adapter
before the rulebook sees it, so there the two names became one name given twice
and the file was refused for that. The rule now lives in the one kit rulebook,
so the shapes whose names reach it as written refuse the space itself;
tests/unit/test_names_people_pick_are_exact.py records what each shape does.
"""

ORIGIN = {"Origin": "http://testserver"}

CSV_TWIN = (b"name,index,index2\n"
            b"D701,ACGTACGT,TTGGCCAA\n"
            b"D701 ,CAGTCAGT,AACCGGTT\n")
CSV_GOOD = (b"name,index,index2\n"
            b"D701,ACGTACGT,TTGGCCAA\n"
            b"D702,CAGTCAGT,AACCGGTT\n")
YAML_HIDDEN = ("name: Hidden kit\nversion: '1.0'\nindex_mode: unique_dual\n"
               "index_pairs:\n"
               "  - name: A01\n"
               "    index1: {name: A01-i7, sequence: ACGTACGT}\n"
               "    index2: {name: A01-i5, sequence: TTGGCCAA}\n"
               "  - name: \"A01​\"\n"
               "    index1: {name: A01-i7b, sequence: GGGGAAAA}\n"
               "    index2: {name: A01-i5b, sequence: CCCCTTTT}\n").encode("utf-8")


def _upload(client, content, mode, filename, **boxes):
    return client.post(
        "/indexes/upload",
        data={"index_mode": mode, **boxes},
        files={"index_file": (filename, content, "text/plain")},
        headers=ORIGIN,
    )


class TestTwoNamesThatLookTheSame:

    def test_a_csv_with_two_names_one_space_apart_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, CSV_TWIN, "unique_dual", "k.csv",
                       kit_name="Space kit", kit_version="1.0")

        assert "HX-Redirect" not in resp.headers, resp.text[:400]
        assert ctx.index_kit_repo.list_all() == []
        assert "must not begin or end with a space: U+0020" in resp.text
        assert "index_pairs" in resp.text and "item 2" in resp.text

    def test_the_same_csv_with_two_names_is_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, CSV_GOOD, "unique_dual", "k.csv",
                       kit_name="Space kit", kit_version="1.0")

        assert resp.headers.get("HX-Redirect") == "/indexes"
        (kit,) = ctx.index_kit_repo.list_all()
        assert [p.name for p in kit.index_pairs] == ["D701", "D702"]

    def test_a_yaml_pair_name_with_a_hidden_character_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, YAML_HIDDEN, "unique_dual", "k.yaml")

        assert "HX-Redirect" not in resp.headers, resp.text[:400]
        assert ctx.index_kit_repo.list_all() == []
        assert "U+200B" in resp.text
