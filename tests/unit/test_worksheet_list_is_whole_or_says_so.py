"""The worksheet list asks for one large page, and says so when the LIMS has
more than it sent.

SeqSetup asked ``/worksheets?detail=true`` with no ``page_size``, so iGene
answered its own default first page -- 20 worksheets -- and the pagination
block beside them, which names the real total, was dropped. A laboratory with
25 worksheets saw 20, with no word that five were missing (review INGEST-2).
"""

import pytest

from seqsetup.models.sample_api_config import WORKSHEET_PAGE_SIZE, SampleApiConfig
from seqsetup.services import sample_api as sa

URL = "https://lims.example.org/api"


def _config() -> SampleApiConfig:
    return SampleApiConfig(base_url=URL, enabled=True)


def _answer(monkeypatch, worksheets, pagination=None):
    asked = []

    def answer(url, api_key=""):
        asked.append(url)
        return [worksheets, pagination] if pagination is not None else worksheets

    monkeypatch.setattr(sa, "_api_get", answer)
    return asked


def _page(count, first=1):
    return [{"id": f"WS-{n:03d}", "updated_at": f"2026-01-{(n % 28) + 1:02d}"}
            for n in range(first, first + count)]


class TestOneLargePageIsAskedFor:

    def test_the_page_size_is_the_named_constant(self):
        assert WORKSHEET_PAGE_SIZE == 200

    def test_the_url_asks_for_it(self):
        assert f"page_size={WORKSHEET_PAGE_SIZE}" in _config().worklists_url()

    def test_a_caller_that_names_a_limit_still_gets_it(self):
        assert "page_size=5" in _config().worklists_url(limit=5)

    def test_the_list_asks_for_it(self, monkeypatch):
        asked = _answer(monkeypatch, _page(3))

        sa.fetch_worklists(_config())

        assert asked and f"page_size={WORKSHEET_PAGE_SIZE}" in asked[0], asked


class TestTheListSaysWhenTheLimsHasMore:

    def test_a_lims_with_more_worksheets_than_one_page(self, monkeypatch):
        _answer(monkeypatch, _page(200), {"total": 254, "page": 1, "page_size": 200})

        ok, _message, worksheets, left_out = sa.fetch_worklists(_config())

        assert ok and len(worksheets) == 200
        said = [line for line in left_out if "254" in line]
        assert said, left_out
        assert "200" in said[0], said

    def test_nothing_is_said_when_the_list_is_whole(self, monkeypatch):
        _answer(monkeypatch, _page(20), {"total": 20, "page": 1, "page_size": 200})

        ok, _message, worksheets, left_out = sa.fetch_worklists(_config())

        assert ok and len(worksheets) == 20 and left_out == []

    def test_a_total_that_is_not_a_number_is_ignored(self, monkeypatch):
        _answer(monkeypatch, _page(20), {"total": "many"})

        ok, _message, _worksheets, left_out = sa.fetch_worklists(_config())

        assert ok and left_out == []

    def test_a_lims_that_answers_a_bare_list_behaves_as_before(self, monkeypatch):
        _answer(monkeypatch, _page(20))

        ok, _message, worksheets, left_out = sa.fetch_worklists(_config())

        assert ok and len(worksheets) == 20 and left_out == []

    def test_no_second_page_is_asked_for(self, monkeypatch):
        """A list that moves between two requests could show one worksheet
        twice, and the duplicate-ID rule would then hide it."""
        asked = _answer(monkeypatch, _page(200), {"total": 254})

        sa.fetch_worklists(_config())

        assert len(asked) == 1, asked


class TestOneLargePageFitsTheAnswerCap:

    def test_two_hundred_detailed_worksheets_fit_well_inside_ten_megabytes(self):
        """Measured against the mock LIMS's own model of an iGene worksheet
        (tools/mock_igene_api.py); the real iGene must be confirmed."""
        import json
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
        try:
            import mock_igene_api as mock
        finally:
            sys.path.pop(0)

        shape = list(mock.WORKSHEETS.values())[0]
        page = [dict(shape, id=f"WS-2026-{n:03d}") for n in range(WORKSHEET_PAGE_SIZE)]
        size = len(json.dumps([page, {"total": WORKSHEET_PAGE_SIZE, "page": 1,
                                      "page_size": WORKSHEET_PAGE_SIZE}]).encode("utf-8"))

        # Measured: about 200 * 230 bytes. A whole order of magnitude of room
        # under the 10 MB cap, so a worksheet ten times this size still fits.
        assert size < sa._MAX_RESPONSE_SIZE / 10, size
        print(f"200 detail=true worksheets: {size} bytes of {sa._MAX_RESPONSE_SIZE}")
