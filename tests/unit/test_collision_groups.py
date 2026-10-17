"""The grouped index-collision report: what a group is, and what each
surface says about it.

docs/design/2026-10-17-collision-report-grouped-design.md. The equivalence
with the old per-pair scan is proved in test_collision_groups_oracle.py; this
file plants the cases that equivalence must not paper over, and pins what the
Mark Ready refusal, the Check panel, the Issues tab and the report say.
"""

import json
import re
from pathlib import Path

import pytest

from seqsetup.models.index import Index, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.models.validation import MAX_LISTED_SAMPLE_NAMES
from seqsetup.services.index_collision_validator import IndexCollisionValidator
from seqsetup.services.validation import ValidationService, clear_validation_cache
from seqsetup.services.validation_report import ValidationReportJSON
from seqsetup.services.validation_summary import (
    MAX_SAMPLE_ERROR_MESSAGES,
    error_messages,
    errors_by_sample,
    issue_rows,
)
from seqsetup.templating import templates

TEMPLATES = Path(__file__).resolve().parents[2] / "src" / "seqsetup" / "templates"

I5 = "TATAGCCTGA"


def _run(*samples, m7=1, m5=1, index_cycles=10):
    run = SequencingRun(
        id="groups", run_name="Groups", instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B", run_cycles=RunCycles(151, 151, index_cycles, index_cycles),
        barcode_mismatches_index1=m7, barcode_mismatches_index2=m5)
    for spec in samples:
        run.add_sample(_sample(**spec))
    return run


def _sample(name, i7, i5="", lanes=(1,), m7=None, m5=None, override=""):
    sample = Sample(id=name.lower(), sample_id=name, lanes=list(lanes),
                    barcode_mismatches_index1=m7, barcode_mismatches_index2=m5)
    if i7:
        sample.assign_index1(Index(name=f"i7-{name}", sequence=i7, index_type=IndexType.I7))
    if i5:
        sample.assign_index2(Index(name=f"i5-{name}", sequence=i5, index_type=IndexType.I5))
    if override:
        sample.override_cycles = override
    return sample


def _groups(run):
    return IndexCollisionValidator.validate_index_collision_groups(run)


def _pairs(run):
    """The colliding (sample id, sample id) pairs the report means, lane 1."""
    found = set()
    for group in _groups(run):
        if group.sample2_ids:
            for one in group.sample1_ids:
                for other in group.sample2_ids:
                    found.add(tuple(sorted((one, other))))
        else:
            ids = group.sample1_ids
            for i in range(len(ids)):
                for j in range(i + 1, len(ids)):
                    found.add(tuple(sorted((ids[i], ids[j]))))
    return found


def _at_distance(seq, distance):
    """``seq`` with exactly ``distance`` bases changed, from the end."""
    chars = list(seq)
    for position in range(len(seq) - 1, len(seq) - 1 - distance, -1):
        chars[position] = "A" if chars[position] != "A" else "C"
    return "".join(chars)


class TestAPairThatCollidesOnlyBecauseOfTheTolerance:
    """Per index mode and tolerance: the pair at the tolerance's edge is
    found, the pair one base beyond it is not."""

    I7 = "ATTACTCGAT"

    @pytest.mark.parametrize("m", [0, 1, 2])
    def test_dual_index_pair_at_the_edge_is_one_finding(self, m):
        edge = _at_distance(self.I7, 2 * m)
        run = _run({"name": "A", "i7": self.I7, "i5": I5},
                   {"name": "B", "i7": edge, "i5": I5}, m7=m, m5=m)
        groups = _groups(run)
        assert len(groups) == 1, f"m={m}: {[g.collision_description for g in groups]}"
        assert _pairs(run) == {("a", "b")}
        assert groups[0].index_type == "i7+i5"
        assert groups[0].i7_distance == 2 * m

    @pytest.mark.parametrize("m", [0, 1, 2])
    def test_dual_index_pair_one_base_beyond_the_edge_is_no_finding(self, m):
        beyond = _at_distance(self.I7, 2 * m + 1)
        run = _run({"name": "A", "i7": self.I7, "i5": I5},
                   {"name": "B", "i7": beyond, "i5": I5}, m7=m, m5=m)
        assert _groups(run) == []

    @pytest.mark.parametrize("m", [0, 1, 2])
    def test_i7_only_pair_at_the_edge_is_one_finding(self, m):
        edge = _at_distance(self.I7, 2 * m)
        run = _run({"name": "A", "i7": self.I7}, {"name": "B", "i7": edge}, m7=m)
        groups = _groups(run)
        assert len(groups) == 1 and groups[0].index_type == "i7"
        assert _pairs(run) == {("a", "b")}

    @pytest.mark.parametrize("m", [0, 1, 2])
    def test_i7_only_pair_one_base_beyond_the_edge_is_no_finding(self, m):
        beyond = _at_distance(self.I7, 2 * m + 1)
        run = _run({"name": "A", "i7": self.I7}, {"name": "B", "i7": beyond}, m7=m)
        assert _groups(run) == []

    @pytest.mark.parametrize("m", [0, 1, 2])
    def test_exactly_one_pair_of_three_samples_collides(self, m):
        """A and B are at the edge; C is far from both."""
        run = _run({"name": "A", "i7": self.I7, "i5": I5},
                   {"name": "B", "i7": _at_distance(self.I7, 2 * m), "i5": I5},
                   {"name": "C", "i7": "GGGGGGGGGG", "i5": "CCCCCCCCCC"}, m7=m, m5=m)
        assert _pairs(run) == {("a", "b")}


class TestAPairThatCollidesOnlyOverTheCyclesRead:
    """The grouping must use the EFFECTIVE sequences — what demultiplexing
    compares — not the stored ones. Two indexes that differ only in a tail
    masked by OverrideCycles are the same barcode."""

    MASK = "Y151;I8N2;I10;Y151"

    @pytest.mark.parametrize("m", [0, 1, 2])
    def test_the_masked_tail_makes_one_group(self, m):
        run = _run({"name": "A", "i7": "ATTACTCGAT", "i5": I5, "override": self.MASK},
                   {"name": "B", "i7": "ATTACTCGCC", "i5": I5, "override": self.MASK},
                   m7=m, m5=m)
        groups = _groups(run)
        assert len(groups) == 1
        assert sorted(groups[0].sample_ids) == ["a", "b"]
        assert groups[0].i7_distance == 0, "the masked tail must not be compared"

    def test_without_the_mask_the_same_pair_does_not_collide(self):
        run = _run({"name": "A", "i7": "ATTACTCGAT", "i5": I5},
                   {"name": "B", "i7": "ATTACTCGCC", "i5": I5}, m7=0, m5=0)
        assert _groups(run) == []

    def test_i7_only_masked_tail(self):
        run = _run({"name": "A", "i7": "ATTACTCGAT", "override": self.MASK},
                   {"name": "B", "i7": "ATTACTCGCC", "override": self.MASK}, m7=0)
        assert _pairs(run) == {("a", "b")}

    def test_a_sample_whose_whole_i7_is_masked_away_is_left_out(self):
        """The old scan returned None for any pair whose effective i7 was
        empty; so must the grouped report."""
        run = _run({"name": "A", "i7": "ATTACTCGAT", "i5": I5, "override": "Y151;N10;I10;Y151"},
                   {"name": "B", "i7": "ATTACTCGAT", "i5": I5, "override": "Y151;N10;I10;Y151"},
                   m7=0, m5=0)
        assert _groups(run) == []


class TestGroupsAreNeverMergedByChaining:
    """Collisions within a tolerance are not transitive."""

    def test_a_middle_sequence_does_not_join_its_two_neighbours(self):
        #   A ... B is 2 bases, B ... C is 2 bases, A ... C is 4 bases.
        run = _run({"name": "A", "i7": "AAAAAAAAAA", "i5": I5},
                   {"name": "B", "i7": "AAAAAAAACC", "i5": I5},
                   {"name": "C", "i7": "AAAAAACCCC", "i5": I5}, m7=1, m5=1)
        assert _pairs(run) == {("a", "b"), ("b", "c")}, "A and C are 4 bases apart"

    def test_each_pair_of_groups_is_its_own_finding(self):
        run = _run({"name": "A", "i7": "AAAAAAAAAA", "i5": I5},
                   {"name": "B", "i7": "AAAAAAAACC", "i5": I5},
                   {"name": "C", "i7": "AAAAAACCCC", "i5": I5}, m7=1, m5=1)
        assert len(_groups(run)) == 2


class TestTheGroupingKeyHoldsEverythingTheComparisonReads:

    def test_samples_with_different_mismatch_numbers_are_not_lumped_together(self):
        """A's own tolerance is 2, so A collides with B at distance 3; B and
        C, both at 0, do not. Dropping the mismatch number from the key
        would decide both pairs from one representative."""
        run = _run({"name": "A", "i7": "AAAAAAAAAA", "i5": I5, "m7": 2, "m5": 2},
                   {"name": "B", "i7": "AAAAAAACCC", "i5": I5, "m7": 0, "m5": 0},
                   {"name": "C", "i7": "AAAAAAAAAA", "i5": I5, "m7": 0, "m5": 0},
                   m7=0, m5=0)
        # A and C share an index: distance 0 collides at any tolerance.
        # A ... B is 3, within 2*2; B ... C is 3, not within 2*0.
        assert _pairs(run) == {("a", "b"), ("a", "c")}

    def test_a_sample_with_an_i5_and_one_without_follow_the_i7_only_rule(self):
        run = _run({"name": "A", "i7": "AAAAAAAAAA", "i5": I5},
                   {"name": "B", "i7": "AAAAAAAACC"}, m7=1, m5=0)
        groups = _groups(run)
        assert len(groups) == 1 and groups[0].index_type == "i7"

    def test_samples_in_different_lanes_do_not_collide(self):
        run = _run({"name": "A", "i7": "AAAAAAAAAA", "i5": I5, "lanes": (1,)},
                   {"name": "B", "i7": "AAAAAAAAAA", "i5": I5, "lanes": (2,)})
        assert _groups(run) == []

    def test_one_finding_per_lane_for_samples_sharing_several_lanes(self):
        run = _run({"name": "A", "i7": "AAAAAAAAAA", "i5": I5, "lanes": (1, 2, 3)},
                   {"name": "B", "i7": "AAAAAAAAAA", "i5": I5, "lanes": (1, 2, 3)})
        groups = _groups(run)
        assert sorted(g.lane for g in groups) == [1, 2, 3]
        assert all(sorted(g.sample_ids) == ["a", "b"] for g in groups)


class TestManySamplesOnOneIndexAreOneFinding:

    def _shared(self, n, lanes=(1,)):
        return _run(*[{"name": f"S{k:03d}", "i7": "ATTACTCGAT", "i5": I5, "lanes": lanes}
                      for k in range(n)])

    def test_three_hundred_samples_make_one_finding_per_lane(self):
        groups = _groups(self._shared(300))
        assert len(groups) == 1
        group = groups[0]
        assert group.sample_count == 300
        assert group.pair_count == 300 * 299 // 2
        assert len(group.sample_ids) == 300, "every member is named, so every pair is derivable"
        assert group.sample2_ids == []

    def test_the_message_names_a_few_samples_and_counts_the_rest(self):
        group = _groups(self._shared(300))[0]
        text = group.collision_description
        assert "300 samples" in text
        assert f"and {300 - MAX_LISTED_SAMPLE_NAMES} more" in text
        assert text.count("S0") == MAX_LISTED_SAMPLE_NAMES, "no more names than the cap"
        assert "ATTACTCGAT+TATAGCCTGA" in text

    def test_two_samples_read_exactly_as_they_did_before(self):
        """The ordinary small case keeps its wording."""
        group = _groups(self._shared(2))[0]
        assert group.collision_description == (
            "i7+i5 collision in lane 1: S000 (ATTACTCGAT+TATAGCCTGA) vs "
            "S001 (ATTACTCGAT+TATAGCCTGA) - i7 distance 0 <= 2 and i5 distance 0 <= 2")

    def test_the_error_count_counts_findings(self):
        clear_validation_cache()
        result = ValidationService.validate_run(self._shared(300))
        assert len(result.index_collision_groups) == 1
        assert len(error_messages(result)) == result.error_count

    def test_every_sample_is_still_marked(self):
        run = self._shared(300)
        clear_validation_cache()
        by_id = errors_by_sample(run, ValidationService.validate_run(run))
        assert len([sid for sid in by_id if any("collision" in m for m in by_id[sid])]) == 300


class TestARunWithACollisionIsRefused:
    """A collision is a blocking error on its own. An *identical* index pair
    is also reported by the separate `duplicate_index_pair` configuration
    check, so the case that leans on the collision finding alone is a pair
    that collides only because of the tolerance."""

    def _near_pair(self):
        return _run({"name": "A", "i7": "ATTACTCGAT", "i5": I5},
                    {"name": "B", "i7": "ATTACTCGCC", "i5": I5}, m7=1, m5=1)

    def test_a_tolerance_only_collision_is_the_whole_error(self):
        clear_validation_cache()
        result = ValidationService.validate_run(self._near_pair())
        assert len(result.index_collision_groups) == 1
        assert error_messages(result) == [
            result.index_collision_groups[0].collision_description]
        assert result.error_count == 1
        assert result.has_errors is True


class TestTheSurfacesStaySmall:

    def test_a_sample_in_many_findings_has_its_messages_capped(self):
        """One sample within the tolerance of many different sequences."""
        samples = [{"name": "A", "i7": "AAAAAAAAAA", "i5": I5, "m7": 2}]
        for k in range(60):
            seq = list("AAAAAAAAAA")
            seq[k % 10] = "CGT"[k % 3]
            seq[(k + 3) % 10] = "CGT"[(k + 1) % 3]
            samples.append({"name": f"B{k:03d}", "i7": "".join(seq), "i5": I5, "m7": 2})
        run = _run(*samples, m7=0, m5=0)
        clear_validation_cache()
        result = ValidationService.validate_run(run)
        by_id = errors_by_sample(run, result)
        collisions = [m for m in by_id["a"] if "collision" in m or "more index collisions" in m]
        assert len(collisions) <= MAX_SAMPLE_ERROR_MESSAGES + 1
        hidden = [m for m in collisions if "more index collisions" in m]
        assert len(hidden) == 1, "a capped list must say how many it does not show"
        total = sum(1 for g in result.index_collision_groups if "a" in g.sample_ids)
        (count,) = re.findall(r"and (\d+) more index collisions", hidden[0])
        assert int(count) == total - MAX_SAMPLE_ERROR_MESSAGES

    def test_the_collision_detail_partial_caps_its_name_lists(self):
        run = _run(*[{"name": f"S{k:03d}", "i7": "ATTACTCGAT", "i5": I5} for k in range(300)])
        html = templates.env.get_template("validation/_collision_detail.html").render(
            group=_groups(run)[0])
        assert html.count("S0") == MAX_LISTED_SAMPLE_NAMES
        assert f"{300 - MAX_LISTED_SAMPLE_NAMES} more" in html
        assert "300" in html

    def test_the_issues_tab_list_is_built_in_python(self):
        source = (TEMPLATES / "validation" / "_issues_tab.html").read_text()
        assert "{% set ns.errors" not in source, (
            "the Issues tab must not grow its list inside a Jinja loop — that "
            "copies the whole list per error; validation_summary.issue_rows "
            "builds it in Python")
        assert "{% set ns.warnings" not in source
        assert "namespace(" not in source

    def test_issue_rows_lists_every_error_once_in_the_report_order(self):
        run = _run(*[{"name": f"S{k:03d}", "i7": "ATTACTCGAT", "i5": I5} for k in range(5)])
        clear_validation_cache()
        result = ValidationService.validate_run(run)
        errors, warnings = issue_rows(result)
        assert len(errors) == result.error_count
        assert [kind for kind, _ in errors].count("collision") == len(result.index_collision_groups)
        assert all(kind == "config_warning" for kind, _ in warnings)

    def test_the_issues_tab_renders_one_item_per_row(self):
        run = _run(*[{"name": f"S{k:03d}", "i7": "ATTACTCGAT", "i5": I5} for k in range(5)])
        clear_validation_cache()
        result = ValidationService.validate_run(run)
        errors, warnings = issue_rows(result)
        html = templates.env.get_template("validation/_issues_tab.html").render(
            result=result, issue_errors=errors, issue_warnings=warnings)
        assert html.count('class="validation-error-item"') == len(errors)
        assert f"Errors ({len(errors)})" in html


class TestTheReport:

    def test_the_json_row_names_the_whole_group(self):
        run = _run(*[{"name": f"S{k:03d}", "i7": "ATTACTCGAT", "i5": I5} for k in range(4)])
        clear_validation_cache()
        result = ValidationService.validate_run(run)
        (row,) = json.loads(ValidationReportJSON.export(run, result))["errors"]["index_collisions"]
        assert row["sample1_count"] == 4
        assert row["sample1_names"] == ["S000", "S001", "S002", "S003"]
        assert row["sample2_count"] == 0 and row["sample2_names"] == []
        assert row["sequence1"] == row["sequence2"] == "ATTACTCGAT+TATAGCCTGA"

    def test_a_clean_run_reports_no_collisions(self):
        run = _run({"name": "A", "i7": "AAAAAAAAAA", "i5": I5},
                   {"name": "B", "i7": "GGGGGGGGGG", "i5": "CCCCCCCCCC"})
        clear_validation_cache()
        result = ValidationService.validate_run(run)
        report = json.loads(ValidationReportJSON.export(run, result))
        assert report["errors"]["index_collisions"] == []
        assert report["summary"]["collision_count"] == 0
