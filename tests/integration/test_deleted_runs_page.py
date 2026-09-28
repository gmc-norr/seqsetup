"""Admin → Deleted runs (spec 2026-09-28 group 2a, F16, review P2).

What the page lists is decided from each copy's state and whether its run
still exists, so a delete that did not finish never looks finished."""

import html
import re
from datetime import datetime, timedelta

from seqsetup.models.deleted_run import DeletedRun
from seqsetup.models.run_history import RunHistoryEntry
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import RunStatus, SequencingRun

T0 = datetime(2026, 9, 1, 9, 0, 0)
EMPTY = "No runs have been deleted."


def _archived(run_id, name="Kept run", samples=("PT-001", "PT-002")):
    run = SequencingRun(id=run_id, run_name=name, status=RunStatus.ARCHIVED,
                        created_by="maker", updated_by="maker", created_at=T0, updated_at=T0)
    for sid in samples:
        run.add_sample(Sample(sample_id=sid))
    return run


def _copy(ctx, run, state="completed", at=T0, who="admin-test"):
    copy = DeletedRun.of(run, who, at)
    ctx.deleted_run_repo.start(copy)
    if state == "completed":
        ctx.deleted_run_repo.mark_completed(copy.copy_id, at + timedelta(seconds=1))
    elif state == "abandoned":
        ctx.deleted_run_repo.mark_abandoned(copy.copy_id, at + timedelta(seconds=1), "run_changed")
    return copy.copy_id


class TestAdminOnly:
    def test_standard_user_is_refused(self, logged_in_standard_client, fresh_app):
        _app, ctx, _db = fresh_app
        cid = _copy(ctx, _archived("r-std"))
        for url in ("/admin/deleted-runs", f"/admin/deleted-runs/{cid}",
                    f"/admin/deleted-runs/{cid}/history"):
            assert logged_in_standard_client.get(url).status_code == 403, url

    def test_sidebar_links_the_page(self, logged_in_client):
        assert 'href="/admin/deleted-runs"' in logged_in_client.get("/admin/audit").text


class TestList:
    def test_empty(self, logged_in_client):
        resp = logged_in_client.get("/admin/deleted-runs")
        assert resp.status_code == 200
        assert EMPTY in resp.text

    def test_completed_copies_newest_first_with_their_details(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _copy(ctx, _archived("r-old", name="Older run"), at=T0)
        new = _copy(ctx, _archived("r-new", name="Newer run", samples=("A",)), at=T0 + timedelta(days=1))
        text = logged_in_client.get("/admin/deleted-runs").text
        assert text.index("Newer run") < text.index("Older run")
        row = text.split(f'href="/admin/deleted-runs/{new}"')[1].split("</tr>")[0]
        for cell in ("Archived", "maker", "admin-test", "2026-09-02 09:00", "Deleted"):
            assert cell in row, cell
        assert re.search(r">\s*1\s*</td>", row)          # one sample
        assert "not confirmed" not in text


class TestWhatIsShown:
    """The spec's table of copy states."""

    def test_pending_copy_of_a_live_run_is_not_listed(self, logged_in_client, fresh_app):
        # Review case 3: the copy was written, but the run was not deleted.
        _app, ctx, _db = fresh_app
        run = _archived("r-live")
        ctx.run_repo.save(run)
        cid = _copy(ctx, run, state="pending")
        assert EMPTY in logged_in_client.get("/admin/deleted-runs").text
        assert logged_in_client.get(f"/admin/deleted-runs/{cid}").status_code == 404

    def test_abandoned_copy_is_not_listed(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        cid = _copy(ctx, _archived("r-ab"), state="abandoned")
        assert EMPTY in logged_in_client.get("/admin/deleted-runs").text
        assert logged_in_client.get(f"/admin/deleted-runs/{cid}").status_code == 404

    def test_pending_copy_of_a_gone_run_shows_not_confirmed(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        cid = _copy(ctx, _archived("r-gone", name="Gone run"), state="pending")   # never in runs
        text = logged_in_client.get("/admin/deleted-runs").text
        assert "Gone run" in text and "Deleted — not confirmed" in text
        assert "the app stopped before it could mark this copy done" in text
        detail = logged_in_client.get(f"/admin/deleted-runs/{cid}")
        assert detail.status_code == 200 and "Deleted — not confirmed" in detail.text

    def test_stale_pending_copy_is_hidden_when_another_attempt_finished(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _archived("r-twice", name="Twice")
        stale = _copy(ctx, run, state="pending", at=T0, who="first")
        done = _copy(ctx, run, state="completed", at=T0 + timedelta(minutes=1), who="second")
        text = logged_in_client.get("/admin/deleted-runs").text
        assert text.count('href="/admin/deleted-runs/') == 1
        assert f'href="/admin/deleted-runs/{done}"' in text
        assert logged_in_client.get(f"/admin/deleted-runs/{stale}").status_code == 404

    def test_unfinished_attempts_show_the_newest_version_not_the_newest_attempt(
            self, logged_in_client, fresh_app):
        # Second review, P1: B deleted version 2 and stopped before marking its
        # copy; A, holding version 1, started later and stopped too.
        _app, ctx, _db = fresh_app
        v1 = _archived("r-crash", samples=("PT-001",))
        v2 = _archived("r-crash", samples=("PT-001", "NEWER"))
        v2.updated_at = T0 + timedelta(hours=1)
        b = _copy(ctx, v2, state="pending", at=T0 + timedelta(hours=2), who="second")
        a = _copy(ctx, v1, state="pending", at=T0 + timedelta(hours=3), who="first")
        text = logged_in_client.get("/admin/deleted-runs").text
        assert text.count('href="/admin/deleted-runs/') == 1
        row = text.split(f'href="/admin/deleted-runs/{b}"')[1].split("</tr>")[0]
        assert "second" in row and "first" not in row and "Deleted — not confirmed" in row
        assert "NEWER" in logged_in_client.get(f"/admin/deleted-runs/{b}").text
        assert logged_in_client.get(f"/admin/deleted-runs/{a}").status_code == 404

    def test_unfinished_attempts_on_one_version_name_every_possible_deleter(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _archived("r-tie")
        _copy(ctx, run, state="pending", at=T0, who="second")
        newest = _copy(ctx, run, state="pending", at=T0 + timedelta(minutes=1), who="first")
        text = logged_in_client.get("/admin/deleted-runs").text
        assert text.count('href="/admin/deleted-runs/') == 1
        assert "first or second" in text
        assert "first or second" in logged_in_client.get(f"/admin/deleted-runs/{newest}").text

    def test_a_delete_that_finishes_while_the_page_is_read_shows_as_deleted(
            self, logged_in_client, fresh_app, monkeypatch):
        # Second review, P2: the page has read the copies (only a stale pending
        # one); before it checks the run, another attempt deletes the run and
        # completes its copy.
        _app, ctx, _db = fresh_app
        run = _archived("r-race")
        ctx.run_repo.save(run)
        _copy(ctx, run, state="pending", at=T0, who="first")
        real_get = ctx.run_repo.get_by_id

        def another_attempt_finishes_first(run_id):
            loaded = real_get(run_id)
            if run_id == "r-race" and loaded is not None:
                done = DeletedRun.of(loaded, "second", T0 + timedelta(minutes=5))
                ctx.deleted_run_repo.start(done)
                assert ctx.run_repo.delete_if_unchanged(loaded)
                ctx.deleted_run_repo.mark_completed(done.copy_id, T0 + timedelta(minutes=5))
            return real_get(run_id)

        monkeypatch.setattr(ctx.run_repo, "get_by_id", another_attempt_finishes_first)
        text = logged_in_client.get("/admin/deleted-runs").text
        assert "not confirmed" not in text
        assert text.count('href="/admin/deleted-runs/') == 1
        row = text.split('href="/admin/deleted-runs/')[1].split("</tr>")[0]
        assert "second" in row and "first" not in row


class TestOneDeletedRun:
    def test_shows_the_state_the_details_the_sample_ids_and_the_history_panel(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _archived("r-detail", name="Detail run")
        run.run_description = "Why this run existed"
        cid = _copy(ctx, run)
        text = logged_in_client.get(f"/admin/deleted-runs/{cid}").text
        for part in ("Detail run", "Why this run existed", "Deleted", "Archived",
                     "NovaSeq X Series", "PT-001", "PT-002", "maker", "admin-test"):
            assert part in text, part
        assert text.index("PT-001") < text.index("PT-002")
        assert f'hx-get="/admin/deleted-runs/{cid}/history"' in text

    def test_unknown_id_is_404(self, logged_in_client):
        resp = logged_in_client.get("/admin/deleted-runs/nope")
        assert resp.status_code == 404
        assert "No deleted run with that id." in resp.text

    def test_html_in_a_run_name_is_escaped(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        cid = _copy(ctx, _archived("r-html", name="<script>alert(1)</script>"))
        for url in ("/admin/deleted-runs", f"/admin/deleted-runs/{cid}"):
            text = logged_in_client.get(url).text
            assert "<script>alert(1)</script>" not in text, url
            assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text, url


class TestHistory:
    def test_serves_the_runs_history_and_pages_older(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        cid = _copy(ctx, _archived("r-hist"))
        for i in range(60):   # more than one page of 50
            ctx.run_history_repo.append(RunHistoryEntry(
                run_id="r-hist", timestamp=T0 + timedelta(minutes=i), actor="maker", kind="updated",
                field_changes=[{"field": "run_description", "before": f"v{i}", "after": f"v{i + 1}"}]))
        first = logged_in_client.get(f"/admin/deleted-runs/{cid}/history")
        assert first.status_code == 200
        assert "v59 → v60" in first.text
        found = re.search(r'hx-get="(/admin/deleted-runs/[^"?]+/history\?before_ts=[^"]+)"', first.text)
        assert found, "Load older must point at the deleted run's own history URL"
        older = logged_in_client.get(html.unescape(found.group(1)))
        assert older.status_code == 200
        assert "v0 → v1" in older.text

    def test_half_a_cursor_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        cid = _copy(ctx, _archived("r-cursor"))
        resp = logged_in_client.get(f"/admin/deleted-runs/{cid}/history?before_ts=2026-01-01T00:00:00")
        assert resp.status_code == 400

    def test_the_live_run_history_route_still_404s_for_a_deleted_run(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _copy(ctx, _archived("r-gone2"))
        assert logged_in_client.get("/runs/r-gone2/history").status_code == 404
