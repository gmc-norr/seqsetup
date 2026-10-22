"""Every reader of a stored export file goes through ``read_export``.

The bytes the exporters returned during Mark Ready are what the UI download,
the API endpoint, the API Exports page and the operator's tool all hand out —
and when a stored file cannot be served as it was stored, each of them says
so rather than quietly serving a legacy field, a file of another run, or a
fresh export (docs/design/2026-10-16-export-files-own-records-design.md,
"What proves it" 1 and 3).
"""

import pytest

from seqsetup.models.sequencing_run import EXPORT_KINDS, RunStatus

from .conftest import disable_repos, seed_profiles
from .test_export_files_own_records import (
    BOTH_SHEETS, ORIGIN, V2_ONLY, records, seed_run, spy_on_exporters,
)
from .conftest import mark_ready
from .test_served_runs import _token


# kind -> (UI export path, API path)
PATHS = {
    "samplesheet_v2": ("export/samplesheet-v2", "samplesheet-v2"),
    "samplesheet_v1": ("export/samplesheet-v1", "samplesheet-v1"),
    "json": ("export/json", "json"),
    "validation_json": ("export/validation-report", "validation-report"),
    "validation_pdf": ("export/validation-pdf", "validation-pdf"),
}


def _ready(client, ctx, run_id, which=BOTH_SHEETS, monkeypatch=None):
    """Mark the run Ready and freeze what each exporter returned while doing
    it. Frozen on purpose: a reader that generated a file afresh would call
    the same exporter again, and a spy read afterwards would hand the test
    that fresh value and call it a match.

    That makes the comparison bite for the two check reports, which carry
    their generation time; the sheets and the JSON are deterministic, so a
    regeneration of those would be byte-identical and this test alone could
    not see it. That nothing is regenerated at all is pinned separately, by
    TestTheV1DecisionComesFromTheManifest's no-live test and by the damaged
    tests below, which refuse rather than serve a fresh file (review 2,
    P3-7)."""
    seed = seed_run(ctx, run_id, which)
    seen = spy_on_exporters(monkeypatch) if monkeypatch is not None else None
    assert mark_ready(client, seed, ORIGIN).status_code == 200
    assert ctx.run_repo.get_by_id(run_id).status == RunStatus.READY
    return {kind: calls[-1] for kind, calls in seen.items()} if seen is not None else None


def _api(client, ctx, run_id, path):
    return client.get(f"/api/runs/{run_id}/{path}",
                      headers={"Authorization": f"Bearer {_token(ctx)}"})


class TestEveryReaderServesTheBytesTheChecksPassed:

    def test_the_ui_downloads_serve_them(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        seen = _ready(logged_in_client, ctx, "ui-bytes", monkeypatch=monkeypatch)

        for kind, (ui, _api_path) in PATHS.items():
            resp = logged_in_client.get(f"/runs/ui-bytes/{ui}")
            assert resp.status_code == 200, (kind, resp.status_code, resp.text[:200])
            written = seen[kind]
            raw = written.encode("utf-8") if isinstance(written, str) else written
            assert resp.content == raw, kind

    def test_the_api_serves_them(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        seen = _ready(logged_in_client, ctx, "api-bytes", monkeypatch=monkeypatch)

        for kind, (_ui, path) in PATHS.items():
            resp = _api(logged_in_client, ctx, "api-bytes", path)
            assert resp.status_code == 200, (kind, resp.status_code, resp.text[:200])
            written = seen[kind]
            raw = written.encode("utf-8") if isinstance(written, str) else written
            assert resp.content == raw, kind

    def test_the_api_exports_page_shows_them(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        seen = _ready(logged_in_client, ctx, "page-bytes", monkeypatch=monkeypatch)

        page = logged_in_client.get("/served-runs/page-bytes")

        assert page.status_code == 200
        # The v2 sheet's own text is on the page, and the PDF by its length.
        assert "FileFormatVersion" in page.text
        assert f"{len(seen['validation_pdf']):,}" in page.text

    def test_the_operator_tool_reads_the_stored_sheet(
            self, logged_in_client, fresh_app, monkeypatch):
        from tools.check_broken_samplesheets import check_runs
        _app, ctx, db = fresh_app
        _ready(logged_in_client, ctx, "tool-bytes", monkeypatch=monkeypatch)

        report, broken = check_runs(db)

        assert broken == 0, report
        assert "Checked 1 Ready/Archived run" in report, report


class TestADamagedFileIsRefusedByEveryReader:

    @staticmethod
    def _damage(ctx, run_id, kind):
        """Change a stored file's bytes and leave its own sha256 and size
        fields exactly as they were: a reader that compared stored fields
        rather than hashing the bytes would serve these."""
        entry = ctx.run_repo.get_by_id(run_id).exports[kind]
        record = ctx.run_export_repo.get(entry["id"])
        content = record["content"]
        changed = (b"X" * len(content) if isinstance(content, bytes)
                   else "X" * len(content))
        ctx.run_export_repo.collection.update_one(
            {"_id": entry["id"]}, {"$set": {"content": changed}})

    @pytest.mark.parametrize("kind", sorted(PATHS))
    def test_the_ui_download_refuses(self, logged_in_client, fresh_app, kind):
        _app, ctx, _db = fresh_app
        _ready(logged_in_client, ctx, "ui-damaged")
        self._damage(ctx, "ui-damaged", kind)

        resp = logged_in_client.get(f"/runs/ui-damaged/{PATHS[kind][0]}")

        assert resp.status_code == 500, (kind, resp.status_code, resp.text[:200])
        assert "cannot be served" in resp.text, resp.text[:300]
        assert "try again" not in resp.text.lower(), resp.text[:300]

    @pytest.mark.parametrize("kind", sorted(PATHS))
    def test_the_api_refuses(self, logged_in_client, fresh_app, kind):
        _app, ctx, _db = fresh_app
        _ready(logged_in_client, ctx, "api-damaged")
        self._damage(ctx, "api-damaged", kind)

        resp = _api(logged_in_client, ctx, "api-damaged", PATHS[kind][1])

        assert resp.status_code == 500, (kind, resp.status_code, resp.text[:200])
        assert "cannot be served" in resp.text, resp.text[:300]

    def test_the_api_exports_page_shows_the_one_damaged_file_and_the_rest(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _ready(logged_in_client, ctx, "page-damaged")
        self._damage(ctx, "page-damaged", "json")

        page = logged_in_client.get("/served-runs/page-damaged")

        assert page.status_code == 200, page.text[:300]
        assert "cannot be served" in page.text
        # The other files are still shown.
        assert "FileFormatVersion" in page.text

    def test_the_page_says_exactly_what_the_api_answers_for_it(
            self, logged_in_client, fresh_app):
        """The page's own promise: each row carries the answer the API gives.
        The missing rows and the Draft's 403 are pinned against the API
        itself in test_served_runs.py; this pins the damaged row the same way
        (review 2, P3-5)."""
        import html as html_module
        import re
        _app, ctx, _db = fresh_app
        _ready(logged_in_client, ctx, "page-vs-api")
        self._damage(ctx, "page-vs-api", "json")

        api = _api(logged_in_client, ctx, "page-vs-api", "json")
        page = logged_in_client.get("/served-runs/page-vs-api")
        section = re.search(r'<section[^>]*id="served-json".*?</section>',
                            page.text, re.S).group(0)

        assert api.status_code == 500, api.text[:200]
        assert f"500: {api.json()['detail']}" in html_module.unescape(section), section

    def test_the_operator_tool_reports_it_rather_than_passing_the_run(
            self, logged_in_client, fresh_app):
        from tools.check_broken_samplesheets import check_runs
        _app, ctx, db = fresh_app
        _ready(logged_in_client, ctx, "tool-damaged")
        self._damage(ctx, "tool-damaged", "samplesheet_v2")

        report, broken = check_runs(db)

        assert broken == 1, report
        assert "cannot be served" in report, report

    def test_a_manifest_pointed_at_another_run_s_file_is_refused(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _ready(logged_in_client, ctx, "mine")
        _ready(logged_in_client, ctx, "theirs")
        mine = ctx.run_repo.get_by_id("mine")
        theirs = ctx.run_repo.get_by_id("theirs")
        mine.exports = dict(mine.exports, samplesheet_v2=theirs.exports["samplesheet_v2"])
        ctx.run_repo.save(mine)

        resp = logged_in_client.get("/runs/mine/export/samplesheet-v2")

        assert resp.status_code == 500, resp.text[:300]
        assert "cannot be served" in resp.text

    def test_a_required_kind_dropped_from_the_manifest_is_refused(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _ready(logged_in_client, ctx, "dropped")
        run = ctx.run_repo.get_by_id("dropped")
        run.exports = {k: v for k, v in run.exports.items() if k != "json"}
        ctx.run_repo.save(run)

        assert logged_in_client.get("/runs/dropped/export/json").status_code == 500
        assert _api(logged_in_client, ctx, "dropped", "json").status_code == 500

    def test_a_deleted_file_record_is_refused_and_nothing_is_regenerated(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _ready(logged_in_client, ctx, "gone")
        entry = ctx.run_repo.get_by_id("gone").exports["samplesheet_v2"]
        ctx.run_export_repo.collection.delete_one({"_id": entry["id"]})

        resp = logged_in_client.get("/runs/gone/export/samplesheet-v2")

        assert resp.status_code == 500, resp.text[:300]
        assert "FileFormatVersion" not in resp.text, "a fresh sheet was served"

    def test_the_refusal_is_audited(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _ready(logged_in_client, ctx, "audited")
        self._damage(ctx, "audited", "json")

        logged_in_client.get("/runs/audited/export/json")

        events = ctx.audit_event_repo.search(limit=50, event_prefix="run.export.damaged")
        assert [e.target for e in events] == ["audited"], events


class TestTheV1DecisionComesFromTheManifest:

    def test_a_run_whose_instrument_writes_no_v1_sheet_still_says_so(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _ready(logged_in_client, ctx, "no-v1", V2_ONLY)

        ui = logged_in_client.get("/runs/no-v1/export/samplesheet-v1")
        api = _api(logged_in_client, ctx, "no-v1", "samplesheet-v1")

        assert ui.status_code == 400, ui.text[:200]
        assert api.status_code == 404, api.text[:200]

    def test_a_withheld_v1_sheet_says_why(self, logged_in_client, fresh_app, monkeypatch):
        from seqsetup.services.samplesheet_v1_exporter import SampleSheetV1Exporter
        _app, ctx, _db = fresh_app
        monkeypatch.setattr(SampleSheetV1Exporter, "withheld", classmethod(
            lambda cls, run, mismatches=None:
            ("S1 has OverrideCycles a v1 sheet cannot hold", ["S1"])))
        _ready(logged_in_client, ctx, "withheld")

        ui = logged_in_client.get("/runs/withheld/export/samplesheet-v1")
        api = _api(logged_in_client, ctx, "withheld", "samplesheet-v1")

        assert ui.status_code == 409, ui.text[:200]
        assert "No v1 sheet for this run" in ui.text
        assert api.status_code == 404 and "No v1 sheet for this run" in api.text

    def test_nothing_is_generated_live_for_a_run_with_a_manifest(
            self, logged_in_client, fresh_app, monkeypatch):
        """A reader that fell back to a live export would hand out bytes no
        check passed."""
        _app, ctx, _db = fresh_app
        _ready(logged_in_client, ctx, "no-live")
        run = ctx.run_repo.get_by_id("no-live")
        run.exports = {k: v for k, v in run.exports.items() if k != "samplesheet_v1"}
        ctx.run_repo.save(run)
        from seqsetup.services.samplesheet_v1_exporter import SampleSheetV1Exporter
        monkeypatch.setattr(SampleSheetV1Exporter, "export", staticmethod(
            lambda *a, **k: pytest.fail("a v1 sheet was generated for a run with a manifest")))

        assert logged_in_client.get("/runs/no-live/export/samplesheet-v1").status_code == 500


class TestARunStoredBeforeTheFilesMovedOutIsServedAsBefore:

    def _old_shape(self, ctx, run_id="old-shape"):
        from seqsetup.models.sample import Sample
        from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
        from .test_group_1c import _pair
        seed_profiles(ctx, lane=False)
        run = SequencingRun(
            id=run_id, run_name="Old shape", instrument_platform=InstrumentPlatform.MISEQ,
            flowcell_type="v3", run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.READY,
            generated_samplesheet_v2="[Header]\nFileFormatVersion,2\nOLD-V2\n",
            generated_samplesheet_v1="[Header]\nOLD-V1\n",
            generated_json='{"run_name": "Old shape"}',
            generated_validation_json='{"errors": []}',
            generated_validation_pdf=b"%PDF-1.4\nold\n",
        )
        run.add_sample(Sample(test_id="WGS", test_version="1", sample_id="S1", index_pair=_pair("ATTACTCG", "TATAGCCT", "p1"),
                              lanes=[1]))
        ctx.run_repo.save(run)
        return run

    def test_every_reader_serves_what_the_run_document_carries(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = self._old_shape(ctx)
        expected = {
            "samplesheet_v2": run.generated_samplesheet_v2,
            "samplesheet_v1": run.generated_samplesheet_v1,
            "json": run.generated_json,
            "validation_json": run.generated_validation_json,
            "validation_pdf": run.generated_validation_pdf,
        }

        for kind, (ui, path) in PATHS.items():
            want = expected[kind]
            raw = want.encode("utf-8") if isinstance(want, str) else want
            assert logged_in_client.get(f"/runs/old-shape/{ui}").content == raw, kind
            assert _api(logged_in_client, ctx, "old-shape", path).content == raw, kind

    def test_the_operator_tool_still_reads_its_sheet(self, logged_in_client, fresh_app):
        from tools.check_broken_samplesheets import check_runs
        _app, ctx, db = fresh_app
        self._old_shape(ctx)

        report, _broken = check_runs(db)

        assert "Checked 1 Ready/Archived run" in report, report
