"""A name outside latin-1 must not break a download's Content-Disposition.

Starlette encodes header values as latin-1, so a run named in Polish,
Czech, Turkish, Cyrillic or CJK used to make all five export downloads
answer 500 with a message blaming generation -- the content itself was
fine and stored on the run. The header now carries an ASCII ``filename``
and the name as typed in ``filename*`` (RFC 6266 / RFC 5987).
"""

import pytest

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)

from .conftest import disable_repos, mark_ready
from .test_group_1c import _pair


ORIGIN = {"Origin": "http://testserver"}

# (route, the filename's suffix, the route's default stem)
EXPORT_ROUTES = [
    ("samplesheet-v2", ".csv", "SampleSheet_v2"),
    ("samplesheet-v1", ".csv", "SampleSheet"),
    ("json", ".json", "run_metadata"),
    ("validation-report", "_validation.json", "validation_report"),
    ("validation-pdf", "_validation.pdf", "validation_report"),
]


def _ready_run(logged_in_client, ctx, run_id: str, name: str) -> str:
    """A Ready one-sample NovaSeq 6000 run named ``name``.

    NovaSeq 6000 is one of the platforms that still has a v1 sheet, so all
    five export routes answer for this run. Marked Ready through the real
    route, so every export is pre-generated the way production does it.
    """
    disable_repos(ctx, "test_profile", "app_profile")
    run = SequencingRun(
        id=run_id,
        run_name=name,
        instrument_platform=InstrumentPlatform.NOVASEQ_6000,
        flowcell_type="S4",
        run_cycles=RunCycles(151, 151, 10, 10),
    )
    run.add_sample(Sample(sample_id="S1", index_pair=_pair("CCCCCCCC", "GGGGGGGG", "p1"),
                          lanes=[1]))
    ctx.run_repo.save(run)
    resp = mark_ready(logged_in_client, run.id, ORIGIN)
    assert resp.status_code == 200
    stored = ctx.run_repo.get_by_id(run.id)
    assert stored.generated_samplesheet_v2, "the run did not reach Ready"
    return run.id


class TestAsciiExportHeaderUnchanged:
    """An ASCII run name's header is exactly what it was: one ``filename``
    parameter, no ``filename*``."""

    def test_every_export_route_header_is_unchanged(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _ready_run(logged_in_client, ctx, "ascii-header-run", "Export Header Run")

        for route, suffix, _default in EXPORT_ROUTES:
            resp = logged_in_client.get(f"/runs/{run_id}/export/{route}")
            assert resp.status_code == 200, route
            assert resp.headers["content-disposition"] == (
                f'attachment; filename="Export_Header_Run{suffix}"'
            ), route
            assert resp.headers["cache-control"] == "no-store", route


class TestNonLatin1ExportHeader:
    """A name outside ASCII downloads with both parameters, and the one
    outside latin-1 no longer 500s."""

    # (name, the ASCII filename's stem, the percent-encoded name as typed)
    NAMES = [
        ("Próba Łukasz 1", "Proba_ukasz_1", "Pr%C3%B3ba_%C5%81ukasz_1"),
        ("Příliš žluťoučký", "Prilis_zlutoucky",
         "P%C5%99%C3%ADli%C5%A1_%C5%BElu%C5%A5ou%C4%8Dk%C3%BD"),
        ("Şükrü Run", "Sukru_Run", "%C5%9E%C3%BCkr%C3%BC_Run"),
    ]

    @pytest.mark.parametrize("name,ascii_stem,encoded", NAMES)
    def test_every_export_route_answers_with_both_parameters(
            self, logged_in_client, fresh_app, name, ascii_stem, encoded):
        _app, ctx, _db = fresh_app
        run_id = _ready_run(logged_in_client, ctx, "nonascii-header-run", name)

        for route, suffix, _default in EXPORT_ROUTES:
            resp = logged_in_client.get(f"/runs/{run_id}/export/{route}")
            assert resp.status_code == 200, route
            assert resp.headers["content-disposition"] == (
                f'attachment; filename="{ascii_stem}{suffix}"'
                f"; filename*=UTF-8''{encoded}{suffix}"
            ), route

    def test_a_name_that_folds_to_nothing_uses_the_routes_default(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _ready_run(logged_in_client, ctx, "cjk-header-run", "日本語ラン")
        encoded = "%E6%97%A5%E6%9C%AC%E8%AA%9E%E3%83%A9%E3%83%B3"

        for route, suffix, default in EXPORT_ROUTES:
            resp = logged_in_client.get(f"/runs/{run_id}/export/{route}")
            assert resp.status_code == 200, route
            assert resp.headers["content-disposition"] == (
                f'attachment; filename="{default}{suffix}"'
                f"; filename*=UTF-8''{encoded}{suffix}"
            ), route


class TestHeaderBuiltBeforeGeneration:
    """A header problem is never reported as a generation failure."""

    def test_a_header_failure_is_not_reported_as_a_failed_export(
            self, logged_in_client, fresh_app, monkeypatch):
        from seqsetup.routes import export as export_module

        _app, ctx, _db = fresh_app
        run_id = _ready_run(logged_in_client, ctx, "header-first-run", "Header First Run")

        class HeaderBoom(Exception):
            pass

        def boom(*_args, **_kwargs):
            raise HeaderBoom("the header could not be built")

        monkeypatch.setattr(export_module, "_attachment_headers", boom)

        for route, _suffix, _default in EXPORT_ROUTES:
            with pytest.raises(HeaderBoom):
                logged_in_client.get(f"/runs/{run_id}/export/{route}")
