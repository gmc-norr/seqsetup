"""Ceilings on what one ordinary mistake can cost.

docs/design/2026-10-17-collision-report-grouped-design.md. "Give this same
index to all N samples" makes every sample in a lane collide with every
other. Before the grouped report, measured on main 7c95e76:

    300 x 1    44,850 findings   check 0.4 s   refusal 7.3 MiB
                                 Check panel 13.0 MiB   Issues tab 32.1 MiB (5.0 s)
    1,000 x 8  3,996,000         check 42.9 s  refusal 651.7 MiB
                                 Check panel 1,152.5 MiB
                                 Issues tab: did not finish in 10 minutes
                                 peak RSS of one request 6.6 GiB

The sizes and the comparison count below are exact and deterministic; they
are the real assertions. The wall-clock ceilings are deliberately loose
because the suite runs twelve ways at once.
"""

import json
import time

import pytest

from seqsetup.models.index import Index, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import RunCycles, SequencingRun
from seqsetup.services.index_collision_validator import IndexCollisionValidator
from seqsetup.services.validation import ValidationService, clear_validation_cache
from seqsetup.services.validation_summary import (
    error_messages, errors_by_sample, issue_rows,
)
from seqsetup.templating import templates

MIB = 1024 * 1024

#: samples, lanes -> (max pair comparisons, max findings, max refusal MiB,
#: max Check panel MiB, max Issues tab MiB, max check seconds)
CEILINGS = {
    (300, 1): (8, 4, 0.5, 1.0, 1.0, 5.0),
    (1000, 8): (32, 24, 2.0, 8.0, 16.0, 20.0),
}


def _shared_index_run(n, lanes):
    """n samples, all on one dual index pair, all on every one of ``lanes``."""
    run = SequencingRun(id=f"ceiling-{n}-{lanes}", run_name="Ceiling",
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10))
    for k in range(n):
        sample = Sample(sample_id=f"PAT{k:05d}-DNA", lanes=list(range(1, lanes + 1)))
        sample.assign_index1(Index(name="a", sequence="ATTACTCGAT", index_type=IndexType.I7))
        sample.assign_index2(Index(name="b", sequence="TATAGCCTGA", index_type=IndexType.I5))
        run.add_sample(sample)
    return run


@pytest.fixture
def counted(monkeypatch):
    """Count the pair comparisons the check makes."""
    calls = []
    original = IndexCollisionValidator._check_sample_pair_collision

    def counting(cls, *args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(IndexCollisionValidator, "_check_sample_pair_collision",
                        classmethod(counting))
    return calls


@pytest.mark.parametrize("n,lanes", sorted(CEILINGS))
def test_one_shared_index_stays_small_on_every_surface(n, lanes, counted):
    max_calls, max_findings, max_refusal, max_panel, max_issues, max_seconds = \
        CEILINGS[(n, lanes)]
    run = _shared_index_run(n, lanes)

    clear_validation_cache()
    started = time.perf_counter()
    result = ValidationService.validate_run(run)
    seconds = time.perf_counter() - started

    assert len(counted) <= max_calls, (
        f"{n} x {lanes}: {len(counted)} pair comparisons; the grouped scan "
        f"compares one representative per pair of groups")
    assert len(result.index_collision_groups) <= max_findings
    assert result.error_count > 0, "a shared index must still refuse the run"
    assert seconds <= max_seconds, f"{n} x {lanes}: the check took {seconds:.1f}s"

    messages = error_messages(result)
    refusal = templates.env.get_template("runs/_ready_refused.html").render(
        run=run, messages=messages)
    assert len(refusal.encode()) <= max_refusal * MIB, (
        f"{n} x {lanes}: Mark Ready refusal is "
        f"{len(refusal.encode()) / MIB:.1f} MiB")

    by_sample = errors_by_sample(run, result)
    panel = json.dumps(by_sample)
    assert len(panel.encode()) <= max_panel * MIB, (
        f"{n} x {lanes}: the Check panel's data-sample-errors is "
        f"{len(panel.encode()) / MIB:.1f} MiB")
    assert len(by_sample) == n, "every sample is still marked"

    errors, warnings = issue_rows(result)
    started = time.perf_counter()
    issues = templates.env.get_template("validation/_issues_tab.html").render(
        result=result, issue_errors=errors, issue_warnings=warnings)
    issues_seconds = time.perf_counter() - started
    assert len(issues.encode()) <= max_issues * MIB, (
        f"{n} x {lanes}: the Issues tab is {len(issues.encode()) / MIB:.1f} MiB")
    assert issues_seconds <= max_seconds, (
        f"{n} x {lanes}: the Issues tab took {issues_seconds:.1f}s")
