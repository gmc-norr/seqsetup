"""A name outside latin-1 must not break a download's Content-Disposition.

Starlette encodes header values as latin-1, so a run named in Polish,
Czech, Turkish, Cyrillic or CJK used to make all five export downloads
answer 500 with a message blaming generation -- the content itself was
fine and stored on the run. The header now carries an ASCII ``filename``
and the name as typed in ``filename*`` (RFC 6266 / RFC 5987).
"""

from urllib.parse import quote

import pytest

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)

from .conftest import mark_ready, stored_export, seed_profiles
from .test_group_1c import _pair
from .conftest import hold_edit_lock


ORIGIN = {"Origin": "http://testserver"}

# (route, the filename's suffix, the route's default stem). Each sheet's
# name says its version and the software that reads it, so the two never
# download under one name (the user's request, 2026-10-13).
EXPORT_ROUTES = [
    ("samplesheet-v2", "_v2_BCLConvert.csv", "SampleSheet"),
    ("samplesheet-v1", "_v1_bcl2fastq.csv", "SampleSheet"),
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
    seed_profiles(ctx)
    run = SequencingRun(
        id=run_id,
        run_name=name,
        instrument_platform=InstrumentPlatform.NOVASEQ_6000,
        flowcell_type="S4",
        run_cycles=RunCycles(151, 151, 10, 10),
    )
    run.add_sample(Sample(test_id="WGS", test_version="1", sample_id="S1", index_pair=_pair("CCCCCCCC", "GGGGGGGG", "p1"),
                          lanes=[1]))
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)
    resp = mark_ready(logged_in_client, run.id, ORIGIN)
    assert resp.status_code == 200
    stored = ctx.run_repo.get_by_id(run.id)
    assert stored_export(ctx, stored, "samplesheet_v2"), "the run did not reach Ready"
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


class TestIndexKitDownloadHeader:
    """The index-kit YAML download -- open to every signed-in user, not only
    admins, and with no try/except -- had the same bug in its own filter
    (``str.isalnum()`` is Unicode-aware too), so it answered a raw 500."""

    @staticmethod
    def _kit(ctx, name: str, version: str) -> str:
        kit = IndexKit(
            name=name, version=version, index_mode=IndexMode.UNIQUE_DUAL,
            index_pairs=[IndexPair(
                id="p1", name="p1",
                index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
            )],
        )
        ctx.index_kit_repo.save(kit)
        return f"/indexes/download/{quote(name)}/{quote(version)}"

    def test_an_ascii_kit_header_is_unchanged(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        url = self._kit(ctx, "AsciiKit", "1.0")

        resp = logged_in_client.get(url)

        assert resp.status_code == 200
        assert resp.headers["content-disposition"] == (
            'attachment; filename="asciikit_v1_0.yaml"'
        )

    def test_a_cjk_kit_name_downloads_with_both_parameters(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        url = self._kit(ctx, "日本キット", "1.0")

        resp = logged_in_client.get(url)

        assert resp.status_code == 200
        assert resp.headers["content-disposition"] == (
            'attachment; filename="_v1_0.yaml"'
            "; filename*=UTF-8''%E6%97%A5%E6%9C%AC%E3%82%AD%E3%83%83%E3%83%88_v1_0.yaml"
        )
        assert "index_pairs" in resp.text

    def test_a_kit_whose_name_and_version_both_fold_away(self, logged_in_client, fresh_app):
        """Nothing of either is ASCII: the latin-1-safe name is what the kit's
        own filename leaves (the ``_v`` separator), and the name as typed is
        carried in full by ``filename*``."""
        _app, ctx, _db = fresh_app
        url = self._kit(ctx, "日本", "一")

        resp = logged_in_client.get(url)

        assert resp.status_code == 200
        assert resp.headers["content-disposition"] == (
            'attachment; filename="_v.yaml"'
            "; filename*=UTF-8''%E6%97%A5%E6%9C%AC_v%E4%B8%80.yaml"
        )

    def test_a_standard_user_gets_the_same_header(self, logged_in_standard_client, fresh_app):
        """The route is not admin-gated; the fix must hold for the user who
        can actually reach it."""
        _app, ctx, _db = fresh_app
        url = self._kit(ctx, "日本キット", "1.0")

        resp = logged_in_standard_client.get(url)

        assert resp.status_code == 200
        assert resp.headers["content-disposition"].startswith(
            'attachment; filename="_v1_0.yaml"; filename*=UTF-8\'\''
        )
