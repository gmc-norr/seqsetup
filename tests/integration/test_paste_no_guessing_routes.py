"""The paste's Preview and Add refuse a paste whose index columns would be
guessed, and add nothing (index mix-up audit, 2026-10-14; the user's choice
"Refuse, say why"). The rules themselves: tests/unit/test_paste_no_guessing.py.
"""

import html

import pytest

from .test_paste_preview import _post, _run, _samples


class TestThePasteRoutesRefuse:

    @pytest.mark.parametrize("path", ["preview", "bulk"])
    def test_index_columns_without_a_header(self, logged_in_client, fresh_app, path):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)

        r = _post(logged_in_client, run_id, path, "S1\tWGS\tTATAGCCT\tATTACTCG\n")

        assert "Row(s) 1: this paste has no header row" in html.unescape(r.text)
        assert _samples(ctx, run_id) == {}

    @pytest.mark.parametrize("path", ["preview", "bulk"])
    def test_an_index_column_it_does_not_read(self, logged_in_client, fresh_app, path):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)

        r = _post(logged_in_client, run_id, path, "sample_id\ttest_id\tIndex 2\nS1\tWGS\tTATAGCCT\n")

        assert 'Column(s) "Index 2": SeqSetup does not read these' in html.unescape(r.text)
        assert _samples(ctx, run_id) == {}
