"""An uploaded kit file's i7 and i5 are paired only by the same name.

An Illumina YAML kit file uploaded as Unique Dual -- the form's default --
was paired by a guess from the names (D701 with D501, -A with -B, _A with
_B, as substrings) and saved with no error and no warning, so a
combinatorial kit became fixed pairs: a tube holding D703 with D506 could
only be given D703 with D503. The user chose (2026-10-17) to stop guessing:
such a file is refused, naming the indexes that do not pair up, and the
admin is told why.
"""

ORIGIN = {"Origin": "http://testserver"}

GUESSED = (
    b"Name: Old kit\nVersion: '1.0'\nIndexSequences:\n"
    b"  i7Index1:\n    D701: ATTACTCG\n    D702: TCCGGAGA\n"
    b"  i5Index2:\n    D501: TATAGCCT\n    D502: ATAGAGGC\n"
)
SAME_NAMES = GUESSED.replace(b"D501", b"D701").replace(b"D502", b"D702")


def _upload(client, content, mode="unique_dual"):
    return client.post(
        "/indexes/upload",
        data={"index_mode": mode},
        files={"index_file": ("old.yaml", content, "text/yaml")},
        headers=ORIGIN,
    )


class TestAKitFileIsNotPairedByAGuess:

    def test_names_that_only_look_alike_are_refused_and_named(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, GUESSED)

        assert resp.status_code == 200 and "HX-Redirect" not in resp.headers
        for name in ("D701", "D702", "D501", "D502"):
            assert name in resp.text
        assert "Combinatorial" in resp.text
        assert "Failed to parse file" not in resp.text
        assert ctx.index_kit_repo.list_all() == []
        (row,) = ctx.audit_event_repo.search(limit=10, event_prefix="index_kit.upload")
        assert (row.outcome, row.details["reason"]) == ("failure", "unpaired_indexes")

    def test_the_same_file_as_combinatorial_is_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, GUESSED, mode="combinatorial")

        assert resp.headers.get("HX-Redirect") == "/indexes"
        (kit,) = ctx.index_kit_repo.list_all()
        assert [i.name for i in kit.i7_indexes] == ["D701", "D702"]
        assert [i.name for i in kit.i5_indexes] == ["D501", "D502"]

    def test_a_file_whose_names_match_is_saved_as_pairs(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, SAME_NAMES)

        assert resp.headers.get("HX-Redirect") == "/indexes"
        (kit,) = ctx.index_kit_repo.list_all()
        assert [(p.name, p.index1.sequence, p.index2.sequence) for p in kit.index_pairs] == [
            ("D701", "ATTACTCG", "TATAGCCT"),
            ("D702", "TCCGGAGA", "ATAGAGGC"),
        ]

    def test_a_name_given_twice_is_refused_and_named(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        repeated = SAME_NAMES.replace(b"    D702: TCCGGAGA\n", b"    D701: TCCGGAGA\n")

        resp = _upload(logged_in_client, repeated)

        assert "HX-Redirect" not in resp.headers
        assert "D701" in resp.text and "twice" in resp.text
        assert ctx.index_kit_repo.list_all() == []
        (row,) = ctx.audit_event_repo.search(limit=10, event_prefix="index_kit.upload")
        assert (row.outcome, row.details["reason"]) == ("failure", "repeated_names")
