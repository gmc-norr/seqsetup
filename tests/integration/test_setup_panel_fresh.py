"""The setup panel follows a status change.

``update_status`` answered with the status bar, the export panel, the sample
section and the ready-message slot, but not ``#run-config-panel``. That panel
shows an **Edit setup** link whenever the viewer holds the draft's edit lock,
and the run's "Updated" time. So after **Mark Ready** the page still offered
Edit setup on a Ready run -- following it only bounced, since
``routes/wizard.py`` redirects a non-Draft run away from the setup page, but
the page offered a step it could not take -- and after **Return to Draft** the
link was missing until a reload.

The response now refreshes that panel out of band too, as it does the other
four.
"""

import pytest

from seqsetup.models.index import Index, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (InstrumentPlatform, RunCycles, RunStatus,
                                            SequencingRun)

from .conftest import hold_edit_lock

ORIGIN = {"Origin": "http://testserver"}
HTMX = {"Origin": "http://testserver", "HX-Request": "true"}


def _store_profiles(ctx):
    """The WGS test profile and the application profile it names, so the Check
    passes and Mark Ready asks nothing."""
    from seqsetup.models.application_profile import ApplicationProfile
    from seqsetup.models.test_profile import ApplicationProfileReference, TestProfile
    ctx.app_profile_repo.save(ApplicationProfile(
        name="PanelBCL", version="1.0.0", application_type="Dragen",
        application_name="BCLConvert", settings={"SoftwareVersion": "4.3.6"},
        data={"BarcodeMismatchesIndex1": 1, "BarcodeMismatchesIndex2": 1},
        data_fields=["Sample_ID", "Lane", "Index", "Index2", "OverrideCycles",
                     "BarcodeMismatchesIndex1", "BarcodeMismatchesIndex2"],
    ))
    ctx.test_profile_repo.save(TestProfile(
        test_type="WGS", test_name="WGS", description="setup panel test",
        version="1.0.0",
        application_profiles=[ApplicationProfileReference(
            profile_name="PanelBCL", profile_version="1.0.0")],
    ))


def _ready_run(ctx, run_id="r", status=RunStatus.DRAFT):
    """A run that passes the Check and asks nothing on Mark Ready: four
    samples with distinct indexes, in every lane of the flowcell (a lane with
    no sample is a question of its own)."""
    run = SequencingRun(id=run_id, run_name=run_id,
                        instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 8, 8),
                        status=status)
    for n, (i7, i5) in enumerate((("ATTACTCG", "TATAGCCT"), ("TCCGGAGA", "ATAGAGGC"),
                                  ("CGCTCATT", "CCTATCCT"), ("GAGATTCC", "GGCTCTGA")),
                                 start=1):
        run.add_sample(Sample(
            id=f"{run_id}-s{n}", sample_id=f"PAT-{n}", lanes=list(range(1, 9)),
            test_id="WGS",
            test_version="1",
            index1=Index(name=f"i7-{n}", sequence=i7, index_type=IndexType.I7),
            index2=Index(name=f"i5-{n}", sequence=i5, index_type=IndexType.I5),
        ))
    _store_profiles(ctx)
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run_id)
    return run


def _panel(text: str) -> str:
    """The config panel fragment of a response or page."""
    start = text.index('id="run-config-panel"')
    start = text.rindex("<fieldset", 0, start)
    return text[start:text.index("</fieldset>", start) + 11]


class TestTheSetupPanelFollowsTheStatus:

    def test_mark_ready_sends_the_panel_without_edit_setup(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _ready_run(ctx)
        assert "Edit setup" in _panel(logged_in_client.get("/runs/r").text)

        answer = logged_in_client.post("/runs/r/status/ready", headers=HTMX)

        assert answer.status_code == 200, answer.text
        panel = _panel(answer.text)
        assert 'hx-swap-oob="true"' in panel, panel
        assert "Edit setup" not in panel, panel

    def test_return_to_draft_sends_the_panel_with_edit_setup(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _ready_run(ctx, status=RunStatus.READY)

        answer = logged_in_client.post("/runs/r/status/draft", headers=HTMX)

        assert answer.status_code == 200, answer.text
        panel = _panel(answer.text)
        assert 'hx-swap-oob="true"' in panel, panel
        assert "Edit setup" in panel, panel

    def test_archiving_sends_the_panel_without_edit_setup(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _ready_run(ctx, status=RunStatus.READY)

        answer = logged_in_client.post("/runs/r/status/archived", headers=HTMX)

        assert answer.status_code == 200, answer.text
        panel = _panel(answer.text)
        assert 'hx-swap-oob="true"' in panel, panel
        assert "Edit setup" not in panel, panel

    def test_the_panel_still_shows_the_runs_setup(self, logged_in_client, fresh_app):
        """It is the same panel, not a stub: the facts a reader needs after a
        status change are all there."""
        _app, ctx, _db = fresh_app
        _ready_run(ctx)

        answer = logged_in_client.post("/runs/r/status/ready", headers=HTMX)
        panel = _panel(answer.text)

        assert "NovaSeq X Series" in panel
        assert "10B" in panel
        assert "Read 1: 151" in panel and "Index 1: 8" in panel
        assert '<span class="uuid-value" title="r">r</span>' in panel

    def test_the_page_itself_sends_no_oob_panel(self, logged_in_client, fresh_app):
        """The panel is only out of band in a status answer; the full page
        must not carry the attribute, or htmx would swap it into itself."""
        _app, ctx, _db = fresh_app
        _ready_run(ctx)

        panel = _panel(logged_in_client.get("/runs/r").text)

        assert "hx-swap-oob" not in panel, panel

    def test_a_refused_mark_ready_sends_no_panel(self, logged_in_client, fresh_app):
        """A refusal is retargeted to #ready-message and changes nothing, so
        it must not carry a panel that says the run is still a Draft -- or
        anything else out of band."""
        _app, ctx, _db = fresh_app
        run = _ready_run(ctx)
        run.samples[1].index1 = run.samples[0].index1
        run.samples[1].index2 = run.samples[0].index2
        ctx.run_repo.save(run)

        answer = logged_in_client.post("/runs/r/status/ready", headers=HTMX)

        assert "run-config-panel" not in answer.text, answer.text
