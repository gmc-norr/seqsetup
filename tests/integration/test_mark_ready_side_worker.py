"""Mark Ready no longer stops the app for everyone else (outside review of
7f858e0, the size checker's new finding; the user's choice "Side worker",
2026-10-14).

Mark Ready draws the check report's charts, which took 107 seconds for 96
samples on all 8 lanes. It ran on the one loop that serves every request,
so nobody could load a page until it ended. It now runs on a side worker.
"""

import re
import threading
from pathlib import Path

from seqsetup.models.sequencing_run import RunStatus
from seqsetup.services.validation_report import ValidationReportPDF

from .conftest import disable_repos, mark_ready
from .test_group_a3 import ORIGIN
from .test_scheduled_sync_instrument_cache import _scheduled_sync, _seed_run


class TestOthersAreServedWhileMarkReadyRuns:

    def test_a_page_loads_while_the_report_is_drawn(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        _scheduled_sync(ctx, monkeypatch, "forward")
        run_id = _seed_run(ctx, "side-worker")
        drawing, drawn = threading.Event(), threading.Event()
        real_export = ValidationReportPDF.export

        def slow_export(run, result):
            drawing.set()
            drawn.wait(timeout=30)
            return real_export(run, result)

        monkeypatch.setattr(ValidationReportPDF, "export", slow_export)
        pressed, loaded = {}, {}
        presser = threading.Thread(
            target=lambda: pressed.update(response=mark_ready(logged_in_client, run_id, ORIGIN)))
        visitor = threading.Thread(
            target=lambda: loaded.update(status=logged_in_client.get("/").status_code))

        # One event loop for both requests, as in the app.
        with logged_in_client:
            presser.start()
            try:
                assert drawing.wait(timeout=30), "Mark Ready never reached the report"
                visitor.start()
                visitor.join(timeout=5)
                served_meanwhile = not visitor.is_alive()
            finally:
                drawn.set()
                presser.join(timeout=60)
                if visitor.ident:
                    visitor.join(timeout=60)

        assert served_meanwhile, "no page could load while Mark Ready drew the report"
        assert loaded["status"] == 200
        assert pressed["response"].status_code == 200
        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.READY


class TestTheProxyExampleWaitsForMarkReady:
    """nginx gives up on an answer after 60 seconds unless told otherwise; the
    person then sees an error while the run still turns Ready."""

    def test_the_nginx_example_waits_ten_minutes(self):
        """Two large Mark Readys at once each took about 2.5 times as long
        (review of e0d0d95, P3-1): the report's drawing shares one CPU."""
        guide = Path(__file__).resolve().parents[2] / "docs" / "getting-started" / "deployment.rst"
        found = re.findall(r"^       proxy_read_timeout (\d+)s;", guide.read_text(), re.M)
        assert len(found) == 1
        assert int(found[0]) >= 600
