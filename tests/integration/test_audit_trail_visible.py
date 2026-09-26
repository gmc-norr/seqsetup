"""Audit events show up on the admin log page.

No test here raises a logger level: what the page shows is what the app
itself records.
"""

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)

from .conftest import disable_repos


ORIGIN = {"Origin": "http://testserver"}


def _field(key: str, value: str) -> str:
    """One key/value of an audit record's JSON, as the page shows it
    (HTML-escaped quotes). Matches only a logged record — never the
    username in the page header or a search term echoed in the form."""
    return f"&#34;{key}&#34;: &#34;{value}&#34;"


class TestAuditEventsOnAdminLogPage:
    """Who did what is visible to an admin at /admin/logs."""

    def test_login_is_recorded(self, logged_in_client):
        page = logged_in_client.get("/admin/logs").text

        assert _field("event", "login.success") in page
        assert _field("actor", "admin-test") in page

    def test_mark_ready_is_recorded(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run = SequencingRun(
            id="audit-visible",
            run_name="AuditVisible",
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            run_cycles=RunCycles(151, 151, 8, 8),
        )
        run.add_sample(Sample(
            sample_id="S1",
            index_pair=IndexPair(
                id="p1", name="p1",
                index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
                index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
            ),
        ))
        ctx.run_repo.save(run)
        resp = logged_in_client.post(f"/runs/{run.id}/status/ready", headers=ORIGIN)
        assert ctx.run_repo.get_by_id(run.id).status.value == "ready", resp.text[:300]

        page = logged_in_client.get("/admin/logs").text

        assert _field("event", "run.status.changed") in page
        assert _field("target", "audit-visible") in page
