"""Every sample row says which version of the run it was drawn from:
``data-run-version``, the run's ``updated_at`` written to the microsecond,
so that two versions compare as text (fresh review of 38ca108, P2; design
note docs/design/2026-10-17-row-version-design.md).

Two answers about one row can come back in the other order than the server
stored them, and the row is then drawn from older data than the page
already showed. The stamp is how app.js tells.
"""

import json
import re
from datetime import datetime

import pytest

from .test_group_a1 import ORIGIN, RUN, _run, _stored


@pytest.fixture
def two_rows(fresh_app):
    _app, ctx, _db = fresh_app
    _run(ctx, ["PAT1", "PAT2"])
    return ctx


def _versions(html):
    """Row id -> the version it says it was drawn from."""
    found = {}
    for tag in re.findall(r'<tr id="sample-row-[^"]*"[^>]*>', html):
        row = re.search(r'id="([^"]*)"', tag).group(1)
        version = re.search(r'data-run-version="([^"]*)"', tag)
        found[row] = version.group(1) if version else None
    return found


def _stored_version(ctx):
    return _stored(ctx).updated_at.isoformat(timespec="microseconds")


class TestEveryRowSaysItsVersion:
    def test_the_run_page_draws_every_row_with_the_stored_version(
            self, logged_in_client, two_rows):
        resp = logged_in_client.get(f"/runs/{RUN}")

        assert resp.status_code == 200
        version = _stored_version(two_rows)
        assert _versions(resp.text) == {"sample-row-s1": version, "sample-row-s2": version}

    def test_a_box_save_answers_with_the_version_it_stored(self, logged_in_client, two_rows):
        before = _stored_version(two_rows)

        resp = logged_in_client.post(
            f"/runs/{RUN}/samples/s1/settings",
            data={"barcode_mismatches_index1": "0", "target_setting": "1"}, headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        after = _stored_version(two_rows)
        assert after != before
        assert _versions(resp.text) == {"sample-row-s1": after}

    def test_an_index_clear_answers_with_the_version_it_stored(
            self, logged_in_client, two_rows):
        before = _stored_version(two_rows)

        resp = logged_in_client.post(
            f"/runs/{RUN}/samples/s1/clear-index",
            data={"target_indexes": json.dumps([["", ""]])}, headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        after = _stored_version(two_rows)
        assert after != before
        assert _versions(resp.text) == {"sample-row-s1": after}

    def test_a_bulk_apply_draws_every_row_with_the_version_it_stored(
            self, logged_in_client, two_rows):
        resp = logged_in_client.post(
            f"/runs/{RUN}/samples/set-lanes",
            data={"sample_ids": json.dumps(["s1"]), "lanes": json.dumps([1, 2]),
                  "target_lanes": json.dumps([[1]])},
            headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        version = _stored_version(two_rows)
        assert _versions(resp.text) == {"sample-row-s1": version, "sample-row-s2": version}

    def test_a_version_on_the_whole_second_is_written_to_the_microsecond(
            self, logged_in_client, two_rows):
        """isoformat() leaves out a microsecond of 0; written in full, every
        version has one length, and text order is time order."""
        run = _stored(two_rows)
        run.updated_at = datetime(2026, 10, 17, 12, 0, 0)
        two_rows.run_repo.save(run)

        resp = logged_in_client.get(f"/runs/{RUN}")

        assert set(_versions(resp.text).values()) == {"2026-10-17T12:00:00.000000"}
