"""Mark Ready checks the run, then writes the exports; the validation report
is made from a second check while they are written. A sync that lands in
between -- a lowered cycle limit, say -- can make that second check find an
error the first did not. Then nothing is stored and the run stays a Draft,
as for a profile or i5 rule that moves (review P3-2, 2026-10-13)."""

import copy

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.models.validation import ConfigurationError, ValidationSeverity
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter
from seqsetup.services.validation import ValidationService

from .conftest import disable_repos, mark_ready, nothing_stored
from .test_group_1c import _pair
from .conftest import hold_edit_lock

ORIGIN = {"Origin": "http://testserver"}


class TestTheReportsCheckMustPassToo:
    def test_an_error_found_while_the_exports_are_written_is_refused(
            self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        run = SequencingRun(id="late-error", run_name="Late error", instrument_platform=InstrumentPlatform.NOVASEQ_X,
                            flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10))
        # Every lane of the 10B, so Mark Ready asks nothing (lanes without samples).
        run.add_sample(Sample(sample_id="S1", index_pair=_pair("CCCCCCCC", "GGGGGGGG", "p1"),
                              lanes=list(range(1, 9))))
        ctx.run_repo.save(run)
        hold_edit_lock(ctx, run.id)

        real_check = ValidationService.validate_run
        real_write = SampleSheetV2Exporter.export
        synced = []

        def write(*args, **kwargs):
            synced.append(True)  # the sync lands as the exports start
            return real_write(*args, **kwargs)

        def check(run, **kwargs):
            result = real_check(run, **kwargs)
            if not synced:
                return result
            result = copy.deepcopy(result)  # the real one is cached
            result.configuration_errors.append(ConfigurationError(
                severity=ValidationSeverity.ERROR, category="too_many_cycles",
                message="Too many cycles: 322. Lower the cycles in Run Setup."))
            return result

        monkeypatch.setattr(SampleSheetV2Exporter, "export", write)
        monkeypatch.setattr(ValidationService, "validate_run", check)

        resp = mark_ready(logged_in_client, run.id, ORIGIN)

        assert resp.status_code == 409, resp.text[:300]
        assert "The checks found an error while the exports were being generated" in resp.text
        stored = ctx.run_repo.get_by_id(run.id)
        assert stored.status == RunStatus.DRAFT
        assert nothing_stored(ctx, stored)
        reasons = [e.details["reason"] for e in ctx.audit_event_repo.search(limit=50, event_prefix="run.status.denied")]
        assert reasons == ["checks_failed_during_export"], reasons
