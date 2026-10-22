"""``tests/sheet_through_profiles.py: sheet(run)`` writes the sheet for a copy.

The helper gives a sample without a test the one its profile is listed under,
because a sheet needs it. It did so on the run it was handed, so a test that
asked for a sheet and then checked the same run checked a run it had not built
(review leftover O10).
"""

from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import RunCycles, SequencingRun

from ..sheet_through_profiles import sheet


def _run():
    run = SequencingRun(id="helper-run", run_name="helper", run_cycles=RunCycles(151, 151, 8, 8))
    run.add_sample(Sample(id="s1", sample_id="S1", lanes=[1]))
    return run


def test_the_run_keeps_its_samples_as_they_were():
    run = _run()
    before = run.samples[0].to_dict()
    sheet(run)
    assert run.samples[0].to_dict() == before
    assert not run.samples[0].test_id


def test_the_sheet_still_has_the_sample():
    assert "\nS1,1," in sheet(_run())
