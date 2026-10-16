"""What the API serves, shown in the web app (the user's request, 2026-10-13).

/served-runs lists the runs the API lists (Ready, or Archived; never a
Draft), in the API's order. /served-runs/{id} shows each stored file the
API hands out for that run, byte for byte, or the answer the API gives
when it has none. Read-only: it shows stored content, never makes it anew.
Anyone signed in may look; they can already download these files.
"""

import html
import json
import re
from datetime import datetime

import pytest

from seqsetup.models.api_token import ApiToken
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

from .conftest import (
    disable_repos, hold_edit_lock, mark_ready, seed_stored_exports, stored_export,
)
from .test_group_1c import _pair

SHEET = "[Header]\nFileFormatVersion,2\nRunName,Served <b>&amp; \"run\"</b>\n\n[Reads]\nRead1Cycles,151\n"
JSON_TEXT = '{\n  "run_name": "<script>alert(1)</script>",\n  "samples": []\n}'
PDF = b"%PDF-1.4\n" + bytes(range(256)) * 4

RESOURCES = ["samplesheet-v2", "samplesheet-v1", "json", "validation-report", "validation-pdf"]


def _token(ctx) -> str:
    plaintext = ApiToken.generate_token()
    token_hash, token_prefix = ApiToken.hash_token(plaintext)
    ctx.api_token_repo.save(ApiToken(name="served", token_hash=token_hash,
                                     token_prefix=token_prefix, created_by="admin-test"))
    return plaintext


def _run(ctx, run_id, status=RunStatus.READY, updated=datetime(2026, 1, 10, 9, 0), name="Served run",
         instrument=InstrumentPlatform.NOVASEQ_X, flowcell="10B", **stored):
    run = SequencingRun(
        id=run_id, run_name=name,
        instrument_platform=instrument, flowcell_type=flowcell,
        run_cycles=RunCycles(151, 151, 8, 8), status=status,
        created_at=updated, updated_at=updated, **stored,
    )
    run.add_sample(Sample(id=f"{run_id}-s1", sample_id="S1", lanes=[1]))
    ctx.run_repo.save(run)
    return run_id


def _full(ctx, run_id, **kw):
    """Every file stored, each in its own record, on an instrument that has a
    v1 sheet -- the shape a run marked Ready by this release has."""
    return _run(ctx, run_id, instrument=InstrumentPlatform.NOVASEQ_6000, flowcell="S4",
                exports=seed_stored_exports(
                    ctx, run_id,
                    samplesheet_v2=SHEET, samplesheet_v1=SHEET.replace("2", "1"),
                    json=JSON_TEXT, validation_json='{"errors": []}',
                    validation_pdf=PDF),
                **kw)


def _section(page, resource):
    m = re.search(rf'<section[^>]*id="served-{resource}".*?</section>', page, re.S)
    assert m, f"no section for {resource}"
    return m.group(0)


def _shown_text(section):
    """The text a reader sees in the section's <pre>: a browser drops the one
    newline that follows <pre>'s start tag."""
    m = re.search(r'<pre class="served-content">(.*?)</pre>', section, re.S)
    if not m:
        return None
    text = html.unescape(m.group(1))
    return text[1:] if text.startswith("\n") else text


class TestTheList:
    """/served-runs lists what GET /api/runs lists, in the same order."""

    def test_same_runs_in_the_same_order_as_the_api(self, logged_in_client, client, fresh_app):
        _app, ctx, _db = fresh_app
        for n, day in ((1, 3), (2, 9), (3, 6)):
            _run(ctx, f"ready-{n}", updated=datetime(2026, 1, day, 9, 0), name=f"Ready {n}")
        _run(ctx, "arch-1", status=RunStatus.ARCHIVED, name="Archived 1")
        _run(ctx, "draft-1", status=RunStatus.DRAFT, name="Draft 1")
        token = _token(ctx)

        for status in ("ready", "archived"):
            api = client.get(f"/api/runs?status={status}", headers={"Authorization": f"Bearer {token}"})
            expected = [item["id"] for item in api.json()["items"]]
            page = logged_in_client.get(f"/served-runs?status={status}")
            assert page.status_code == 200
            shown = re.findall(r'id="served-run-([^"]+)"', page.text)
            assert shown == expected
        assert expected == ["arch-1"]

    def test_ready_is_the_default(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "ready-1")
        _run(ctx, "arch-1", status=RunStatus.ARCHIVED)
        shown = re.findall(r'id="served-run-([^"]+)"', logged_in_client.get("/served-runs").text)
        assert shown == ["ready-1"]

    def test_a_draft_is_never_listed(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "draft-1", status=RunStatus.DRAFT, name="Hidden draft")
        for status in ("ready", "archived"):
            page = logged_in_client.get(f"/served-runs?status={status}").text
            assert "draft-1" not in page and "Hidden draft" not in page

    @pytest.mark.parametrize("status", ["draft", "all", ""])
    def test_another_status_is_refused_like_the_api(self, logged_in_client, client, fresh_app, status):
        _app, ctx, _db = fresh_app
        api = client.get(f"/api/runs?status={status}", headers={"Authorization": f"Bearer {_token(ctx)}"})
        page = logged_in_client.get(f"/served-runs?status={status}")
        assert api.status_code == page.status_code == 400
        assert api.json()["detail"] in html.unescape(page.text)

    def test_it_names_the_api_address(self, logged_in_client):
        assert "GET /api/runs?status=archived" in logged_in_client.get("/served-runs?status=archived").text

    def test_each_run_links_to_its_files(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, "ready-1")
        assert 'href="/served-runs/ready-1"' in logged_in_client.get("/served-runs").text


class TestTheName:
    """The pages are called API Exports (the user's choice, 2026-10-13)."""

    def test_the_list_is_called_api_exports(self, logged_in_client):
        page = logged_in_client.get("/served-runs").text
        assert re.search(r"<h1[^>]*>API Exports</h1>", page)
        assert "<title>API Exports" in page

    def test_a_runs_page_names_both(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        page = logged_in_client.get(f"/served-runs/{_full(ctx, 'named', name='Named Run')}").text
        assert re.search(r'<a [^>]*href="/served-runs\?status=ready"[^>]*>API Exports</a>\s*›', page)
        assert "<title>API Exports › Named Run" in page

    def test_the_sidebar_says_api_exports(self, logged_in_standard_client):
        assert re.search(r'<a href="/served-runs"[^>]*>API Exports</a>', logged_in_standard_client.get("/").text)

    def test_the_old_name_is_gone(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _full(ctx, "old-name")
        for url in ("/", "/served-runs", f"/served-runs/{run_id}", f"/runs/{run_id}"):
            assert "what the api serves" not in logged_in_client.get(url).text.lower(), url


class TestWhoMayLook:
    def test_signed_out_is_sent_to_sign_in(self, client):
        resp = client.get("/served-runs", follow_redirects=False)
        assert resp.status_code in (302, 303, 307) and "/login" in resp.headers["location"]
        resp = client.get("/served-runs/any", follow_redirects=False)
        assert resp.status_code in (302, 303, 307) and "/login" in resp.headers["location"]

    def test_a_standard_user_may_look(self, logged_in_standard_client, fresh_app):
        _app, ctx, _db = fresh_app
        _full(ctx, "ready-1")
        assert logged_in_standard_client.get("/served-runs").status_code == 200
        assert logged_in_standard_client.get("/served-runs/ready-1").status_code == 200

    def test_the_sidebar_links_here_for_everyone(self, logged_in_standard_client):
        assert 'href="/served-runs"' in logged_in_standard_client.get("/").text


class TestOneRunsFiles:
    """/served-runs/{id} shows what each per-run API address answers."""

    @pytest.mark.parametrize("status", [RunStatus.READY, RunStatus.ARCHIVED])
    def test_every_file_matches_the_api_byte_for_byte(self, logged_in_client, client, fresh_app, status):
        _app, ctx, _db = fresh_app
        run_id = _full(ctx, f"full-{status.value}", status=status)
        token = _token(ctx)
        page = logged_in_client.get(f"/served-runs/{run_id}")
        assert page.status_code == 200

        for resource in RESOURCES:
            api = client.get(f"/api/runs/{run_id}/{resource}", headers={"Authorization": f"Bearer {token}"})
            assert api.status_code == 200
            section = _section(page.text, resource)
            assert f"GET /api/runs/{run_id}/{resource}" in section
            if resource == "validation-pdf":
                assert f'href="/runs/{run_id}/export/validation-pdf"' in section
                assert f"{len(api.content):,} bytes" in section
                assert _shown_text(section) is None
            else:
                assert _shown_text(section) == api.text

    @pytest.mark.parametrize("status", [RunStatus.READY, RunStatus.ARCHIVED])
    def test_every_file_downloads_as_the_api_hands_it_out(self, logged_in_client, client, fresh_app, status):
        _app, ctx, _db = fresh_app
        run_id = _full(ctx, f"download-{status.value}", status=status)
        token = _token(ctx)
        page = logged_in_client.get(f"/served-runs/{run_id}").text

        for resource in RESOURCES:
            section = _section(page, resource)
            link = re.search(rf'<a [^>]*href="(/runs/{run_id}/export/{resource})"[^>]*>Download</a>', section)
            assert link, f"no Download link for {resource}"
            download = logged_in_client.get(link.group(1))
            api = client.get(f"/api/runs/{run_id}/{resource}", headers={"Authorization": f"Bearer {token}"})
            assert download.status_code == api.status_code == 200
            assert download.content == api.content, resource
            assert download.headers["content-disposition"].startswith("attachment;"), resource

    def test_a_file_that_starts_with_a_newline_shows_it(self, logged_in_client, fresh_app):
        """A browser drops one newline right after <pre>'s start tag; the
        page writes one there so the file's own first newline survives."""
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "newline-first", exports=seed_stored_exports(
            ctx, "newline-first", samplesheet_v2="\n[Header]\nFileFormatVersion,2\n",
            json="{}", validation_json='{"errors": []}', validation_pdf=b"%PDF-1.4\n"))
        section = _section(logged_in_client.get(f"/served-runs/{run_id}").text, "samplesheet-v2")
        assert _shown_text(section) == "\n[Header]\nFileFormatVersion,2\n"

    def test_markup_in_a_file_is_shown_as_text(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        page = logged_in_client.get(f"/served-runs/{_full(ctx, 'markup')}").text
        assert "<script>alert(1)</script>" not in page
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page

    @pytest.mark.parametrize("withheld", ["the test's profile has no v1 settings", ""])
    def test_a_missing_file_shows_the_api_answer(self, logged_in_client, client, fresh_app, withheld):
        """With and without a reason Mark Ready stored for making no v1 sheet."""
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, "bare", samplesheet_v1_withheld=withheld)
        token = _token(ctx)
        page = logged_in_client.get(f"/served-runs/{run_id}").text

        for resource in RESOURCES:
            api = client.get(f"/api/runs/{run_id}/{resource}", headers={"Authorization": f"Bearer {token}"})
            assert api.status_code == 404
            section = _section(page, resource)
            assert f"404: {api.json()['detail']}" in html.unescape(section)
            assert _shown_text(section) is None
            assert "/export/" not in section

    def test_a_draft_shows_the_api_answer_and_no_file(self, logged_in_client, client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _full(ctx, "a-draft", status=RunStatus.DRAFT)
        token = _token(ctx)
        api = client.get(f"/api/runs/{run_id}/samplesheet-v2", headers={"Authorization": f"Bearer {token}"})
        assert api.status_code == 403

        page = logged_in_client.get(f"/served-runs/{run_id}")
        assert page.status_code == 200
        assert "The API does not serve Drafts" in page.text
        assert f"403: {api.json()['detail']}" in html.unescape(page.text)
        assert "FileFormatVersion" not in page.text
        assert 'id="served-samplesheet-v2"' not in page.text

    def test_an_unknown_run_is_404(self, logged_in_client):
        assert logged_in_client.get("/served-runs/no-such-run").status_code == 404

    def test_looking_writes_an_audit_row(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _full(ctx, "audited")
        logged_in_client.get(f"/served-runs/{run_id}")
        (event,) = ctx.audit_event_repo.search(limit=50, event_prefix="export.viewed")
        assert event.target == run_id and event.actor

    def test_looking_changes_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _full(ctx, "unchanged")
        before = ctx.run_repo.get_by_id(run_id).to_dict()
        logged_in_client.get(f"/served-runs/{run_id}")
        assert ctx.run_repo.get_by_id(run_id).to_dict() == before


class TestTheRunPageLinksHere:
    @pytest.mark.parametrize("status", [RunStatus.READY, RunStatus.ARCHIVED])
    def test_the_export_box_links_to_the_files(self, logged_in_client, fresh_app, status):
        _app, ctx, _db = fresh_app
        run_id = _full(ctx, f"linked-{status.value}", status=status)
        page = logged_in_client.get(f"/runs/{run_id}").text
        export = page.split('id="export-panel"', 1)[1].split("</fieldset>", 1)[0]
        assert re.search(rf'<a [^>]*href="/served-runs/{run_id}"[^>]*>See this run in API Exports</a>', export)


# Shaped as ValidationReportJSON writes it: the counts, the error lists, then
# the per-lane tables last.
REPORT_DATA = {
    "run_id": "report",
    "summary": {"error_count": 0, "warning_count": 1, "collision_count": 0},
    "errors": {
        "index_collisions": [],
        "configuration_errors": [
            {"severity": "warning", "category": "c", "message": "a warning", "lane": None},
        ],
    },
    "per_lane": {
        "1": {
            "sample_count": 2,
            "distance_matrix": {
                "sample_names": ["S1", "S2"],
                "i7": [[0, 8], [8, 0]], "i5": [[0, 8], [8, 0]], "combined": [[0, 16], [16, 0]],
            },
        },
    },
}
REPORT = json.dumps(REPORT_DATA, indent=2)
REPORT_SHOWN = json.dumps({k: v for k, v in REPORT_DATA.items() if k != "per_lane"}, indent=2)


class TestTheCheckReportOnThePage:
    """The check report's per-lane tables -- the index distance of every
    sample pair, three times per lane, and the color balance -- are nearly
    all of its size, up to about 15 MB. The page shows the rest (the counts,
    the error lists, the warnings) and leaves the tables to the download,
    which, like the API, gives the whole file (the user's decision,
    2026-10-17). A Ready run never has a collision: Mark Ready refuses one."""

    def _report_run(self, ctx, run_id, report):
        return _run(ctx, run_id, exports=seed_stored_exports(
            ctx, run_id, samplesheet_v2=SHEET, json="{}", validation_json=report,
            validation_pdf=PDF))

    def _report_section(self, client, run_id):
        return _section(client.get(f"/served-runs/{run_id}").text, "validation-report")

    def test_the_per_lane_tables_are_left_out(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        section = self._report_section(logged_in_client, self._report_run(ctx, "tables", REPORT))
        assert _shown_text(section) == REPORT_SHOWN
        assert "distance_matrix" not in section

    def test_the_page_says_so_and_gives_the_whole_files_size(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        section = self._report_section(logged_in_client, self._report_run(ctx, "said", REPORT))
        assert "per-lane tables" in section
        assert f"{len(REPORT.encode()):,} bytes" in section

    def test_the_download_and_the_api_give_the_whole_file(self, logged_in_client, client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = self._report_run(ctx, "whole", REPORT)
        section = self._report_section(logged_in_client, run_id)
        link = re.search(r'<a [^>]*href="([^"]+)"[^>]*>Download</a>', section)
        assert link
        assert logged_in_client.get(link.group(1)).content == REPORT.encode()
        api = client.get(f"/api/runs/{run_id}/validation-report",
                         headers={"Authorization": f"Bearer {_token(ctx)}"})
        assert api.text == REPORT

    def test_a_page_with_nothing_left_out_says_nothing_is(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        page = logged_in_client.get(f"/served-runs/{_full(ctx, 'nothing-left-out')}").text
        assert "per-lane tables" not in page

    def test_a_report_with_no_per_lane_tables_is_shown_exactly(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        report = '{"summary": {"error_count": 0}, "per_lane": {}}'
        section = self._report_section(logged_in_client, self._report_run(ctx, "none", report))
        assert _shown_text(section) == report
        assert "per-lane tables" not in section

    @pytest.mark.parametrize("report", ["not json {", "[1, 2]", '"per_lane"'])
    def test_a_report_that_is_not_a_json_object_is_shown_as_stored(self, logged_in_client,
                                                                     fresh_app, report):
        _app, ctx, _db = fresh_app
        section = self._report_section(logged_in_client, self._report_run(ctx, "odd", report))
        assert _shown_text(section) == report
        assert "per-lane tables" not in section

    def test_a_report_nested_too_deep_to_read_is_shown_as_stored(self, logged_in_client, fresh_app):
        """Only a run stored before the files moved out, edited by hand, can
        hold one: a report too deep for the JSON reader is shown, not a 500."""
        _app, ctx, _db = fresh_app
        report = "[" * 100_000 + "]" * 100_000
        section = self._report_section(logged_in_client, self._report_run(ctx, "deep", report))
        assert _shown_text(section) == report
        assert "per-lane tables" not in section

    def test_a_damaged_report_shows_the_api_answer_and_nothing_of_it(self, logged_in_client,
                                                                      client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = self._report_run(ctx, "damaged-report", REPORT)
        entry = ctx.run_repo.get_by_id(run_id).exports["validation_json"]
        # The same length, other bytes, still a report with per-lane tables.
        changed = REPORT.replace('"S1"', '"S9"')
        ctx.run_export_repo.collection.update_one({"_id": entry["id"]},
                                                  {"$set": {"content": changed}})
        section = self._report_section(logged_in_client, run_id)
        api = client.get(f"/api/runs/{run_id}/validation-report",
                         headers={"Authorization": f"Bearer {_token(ctx)}"})
        assert api.status_code == 500
        assert f"500: {api.json()['detail']}" in html.unescape(section)
        assert "per-lane tables" not in section
        assert "<pre" not in section and "Download" not in section

    def test_the_page_says_a_note_marks_what_it_leaves_out(self, logged_in_client, fresh_app):
        """Its opening line promises each file as the API hands it out; the
        check report's tables are the one exception, and the line says so."""
        _app, ctx, _db = fresh_app
        page = logged_in_client.get(f"/served-runs/{self._report_run(ctx, 'promise', REPORT)}").text
        assert "Where part of a file is left out, a note above it says so." in page

    def test_a_ready_runs_report_shows_its_counts_not_its_tables(self, logged_in_client, fresh_app):
        """Marked Ready through the real route, so the report is the one the
        checks wrote."""
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run = SequencingRun(
            id="real-report", run_name="Rapport å ä ö — Ł",
            instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
        )
        run.add_sample(Sample(sample_id="S1", index_pair=_pair("ACGTACGT", "TTGGCCAA", "p1"),
                              lanes=[1]))
        run.add_sample(Sample(sample_id="S2", index_pair=_pair("CATGCATG", "AATTCCGG", "p2"),
                              lanes=[1]))
        ctx.run_repo.save(run)
        hold_edit_lock(ctx, run.id)
        assert mark_ready(logged_in_client, run.id, {"Origin": "http://testserver"}).status_code == 200
        assert ctx.run_repo.get_by_id(run.id).status == RunStatus.READY, "Mark Ready refused the run"
        stored = stored_export(ctx, ctx.run_repo.get_by_id(run.id), "validation_json")
        assert '"distance_matrix"' in stored, "the checks wrote no per-lane table to leave out"

        shown = _shown_text(self._report_section(logged_in_client, run.id))
        # The stored file up to its per-lane tables, closed: what the checks
        # wrote, character for character.
        assert shown == stored[:stored.index(',\n  "per_lane": ')] + "\n}"
        assert '"collision_count": 0' in shown
        assert '"per_lane":' not in shown
        assert '"distance_matrix":' not in shown and '"color_balance":' not in shown
        assert len(shown) < len(stored)
