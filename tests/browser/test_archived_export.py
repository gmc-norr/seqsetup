"""Archived runs can download their exports from the Export panel.

The panel used to enable download buttons only for Ready runs, leaving an
archived run's buttons disabled with a misleading "Run must be marked as
ready" message even though its exports were pre-generated at Ready and
retained through the Ready->Archived transition.

ARCHIVED_RUN_ID's one seeded sample has an index_pair assigned, so the
Sample Sheet v2 button is enabled (not just JSON/validation) — this test
exercises that button directly.
"""

import pytest

from .conftest import ARCHIVED_RUN_ID


@pytest.mark.browser
def test_archived_run_downloads_sample_sheet_v2(logged_in_page, base_url):
    page = logged_in_page
    page.goto(f"{base_url}/runs/{ARCHIVED_RUN_ID}")
    page.wait_for_load_state("networkidle")

    with page.expect_download() as download_info:
        page.click("text=Download Sample Sheet v2")
    download = download_info.value

    assert download.suggested_filename.endswith(".csv")
