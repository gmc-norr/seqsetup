"""The kit upload page says what a refused file would have lost.

Every refusal is a ``KitFileRefused``, so the route shows it in full and
audits its own ``reason`` instead of "Failed to parse file" -- and nothing
is saved (see ``tests/unit/test_kit_file_nothing_dropped.py`` for what each
file does wrong).
"""

ORIGIN = {"Origin": "http://testserver"}

DUAL_YAML = (
    b"Name: Old kit\nVersion: '1.0'\nIndexSequences:\n"
    b"  i7Index1:\n    A1: ATTACTCG\n    A2: TCCGGAGA\n"
    b"  i5Index2:\n    A1: TATAGCCT\n    A2: ATAGAGGC\n"
)
TWO_I7_KEYS = (
    b"Name: Old kit\nIndexSequences:\n"
    b"  i7Index1:\n    A1: ATTACTCG\n  Index1:\n    A2: TCCGGAGA\n"
)
CSV_SHORT_ROW = b"name,index,index2\nA1,ATTACTCG,TATAGCCT\n,CCCCGGGG,TTTTAAAA\n"
TSV_ODD_LINE = (
    b"[IndexKit]\nName\tOld kit\n\n[Indices]\nName\tSequence\tIndexNumber\n"
    b"A1\tATTACTCG\t1\nA2\tTCCGGAGA\t3\n"
)
SYNC_PAIRS = (
    b"name: Old kit\nindex_pairs:\n  - name: P1\n    index1:\n"
    b"      name: A1\n      sequence: ATTACTCG\n"
)


def _upload(client, content, filename="old.yaml", mode="unique_dual"):
    return client.post(
        "/indexes/upload",
        data={"index_mode": mode},
        files={"index_file": (filename, content, "text/plain")},
        headers=ORIGIN,
    )


class TestTheAdminIsToldWhatWouldHaveBeenLost:

    def test_a_dual_file_uploaded_as_single_is_refused_and_audited(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, DUAL_YAML, mode="single")

        assert resp.status_code == 200 and "HX-Redirect" not in resp.headers
        assert "i5Index2" in resp.text and "Combinatorial" in resp.text
        assert "Failed to parse file" not in resp.text
        assert ctx.index_kit_repo.list_all() == []
        (row,) = ctx.audit_event_repo.search(limit=10, event_prefix="index_kit.upload")
        assert (row.outcome, row.details["reason"]) == ("failure", "i5_data_in_single_kit")

    def test_two_keys_for_the_i7_list_are_refused_and_audited(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, TWO_I7_KEYS, mode="single")

        assert "HX-Redirect" not in resp.headers
        assert "i7Index1" in resp.text and "Index1" in resp.text
        assert ctx.index_kit_repo.list_all() == []
        (row,) = ctx.audit_event_repo.search(limit=10, event_prefix="index_kit.upload")
        assert (row.outcome, row.details["reason"]) == ("failure", "two_keys_for_one_list")

    def test_a_csv_row_with_no_name_is_refused_naming_its_line(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, CSV_SHORT_ROW, filename="old.csv")

        assert "HX-Redirect" not in resp.headers
        assert "line 3" in resp.text
        assert ctx.index_kit_repo.list_all() == []
        (row,) = ctx.audit_event_repo.search(limit=10, event_prefix="index_kit.upload")
        assert (row.outcome, row.details["reason"]) == ("failure", "incomplete_index_rows")

    def test_a_tsv_line_with_an_odd_index_number_is_refused_naming_its_line(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, TSV_ODD_LINE, filename="old.tsv")

        assert "HX-Redirect" not in resp.headers
        assert "line 7" in resp.text
        assert ctx.index_kit_repo.list_all() == []
        (row,) = ctx.audit_event_repo.search(limit=10, event_prefix="index_kit.upload")
        assert (row.outcome, row.details["reason"]) == ("failure", "incomplete_index_rows")

    def test_a_sync_file_with_pairs_uploaded_as_single_is_refused_and_audited(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, SYNC_PAIRS, mode="single")

        assert "HX-Redirect" not in resp.headers
        assert "index_pairs" in resp.text and "Unique Dual" in resp.text
        assert ctx.index_kit_repo.list_all() == []
        (row,) = ctx.audit_event_repo.search(limit=10, event_prefix="index_kit.upload")
        assert (row.outcome, row.details["reason"]) == ("failure", "pairs_in_single_kit")

    def test_the_same_dual_file_as_unique_dual_is_still_saved(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        resp = _upload(logged_in_client, DUAL_YAML)

        assert resp.headers.get("HX-Redirect") == "/indexes"
        (kit,) = ctx.index_kit_repo.list_all()
        assert [(p.index1.sequence, p.index2.sequence) for p in kit.index_pairs] == [
            ("ATTACTCG", "TATAGCCT"), ("TCCGGAGA", "ATAGAGGC")]
