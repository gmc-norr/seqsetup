"""Tests for the run diff engine."""

from seqsetup.services.run_diff import diff_run, is_empty


def _run_dict(**over):
    base = {
        "_id": "r1", "id": "r1",
        "run_name": "Run", "run_description": "",
        "status": "draft", "created_by": "bob", "updated_by": "bob",
        "created_at": "2026-06-11T10:00:00", "updated_at": "2026-06-11T10:00:00",
        "wizard_step": 1,
        "instrument_platform": "NovaSeq X Series", "flowcell_type": "10B",
        "reagent_cycles": 300, "run_cycles": {"read1_cycles": 151},
        "barcode_mismatches_index1": 1, "barcode_mismatches_index2": 1,
        "adapter_behavior": "trim", "create_fastq_for_index_reads": False,
        "no_lane_splitting": False, "samples": [], "analyses": [],
        "generated_samplesheet_v2": None, "generated_json": None,
    }
    base.update(over)
    return base


def _sample(sid_uuid="u1", sample_id="S1", **over):
    s = {
        "id": sid_uuid, "sample_id": sample_id, "sample_name": "", "project": "",
        "test_id": "", "worksheet_id": "", "lanes": [], "index_pair": None,
        "index1": None, "index2": None, "index_kit_name": None,
        "override_cycles": None, "barcode_mismatches_index1": 1,
        "barcode_mismatches_index2": 1, "index1_cycles": None, "index2_cycles": None,
        "index1_override_pattern": None, "index2_override_pattern": None,
        "read1_override_pattern": None, "read2_override_pattern": None,
        "analyses": [], "description": "", "metadata": {},
    }
    s.update(over)
    return s


class TestConfigDiff:
    def test_scalar_field_change(self):
        fc, sc = diff_run(_run_dict(), _run_dict(flowcell_type="25B"))
        assert sc == []
        assert {"field": "flowcell_type", "before": "10B", "after": "25B"} in fc

    def test_status_change(self):
        fc, _ = diff_run(_run_dict(), _run_dict(status="ready"))
        assert {"field": "status", "before": "draft", "after": "ready"} in fc

    def test_ignored_keys_excluded(self):
        after = _run_dict(updated_at="2026-06-11T11:00:00", updated_by="alice",
                          wizard_step=3, generated_samplesheet_v2="SHEET",
                          generated_json="J")
        fc, sc = diff_run(_run_dict(), after)
        assert fc == [] and sc == []

    def test_nested_run_cycles_whole_value(self):
        fc, _ = diff_run(_run_dict(), _run_dict(run_cycles={"read1_cycles": 100}))
        assert any(c["field"] == "run_cycles" for c in fc)


class TestSampleDiff:
    def test_added(self):
        fc, sc = diff_run(_run_dict(samples=[]), _run_dict(samples=[_sample()]))
        assert len(sc) == 1 and sc[0]["kind"] == "added" and sc[0]["sample_id"] == "S1"
        names = {f["name"] for f in sc[0]["fields"]}
        assert "sample_id" in names

    def test_removed(self):
        fc, sc = diff_run(_run_dict(samples=[_sample()]), _run_dict(samples=[]))
        assert sc[0]["kind"] == "removed" and sc[0]["sample_id"] == "S1"

    def test_index_reassignment_is_modified(self):
        before = _run_dict(samples=[_sample(index1={"name": "D701", "sequence": "ATTACTCG"})])
        after = _run_dict(samples=[_sample(index1={"name": "D702", "sequence": "TCCGGAGA"})])
        fc, sc = diff_run(before, after)
        assert sc[0]["kind"] == "modified"
        chg = next(f for f in sc[0]["fields"] if f["name"] == "index1")
        assert chg["before"]["name"] == "D701" and chg["after"]["name"] == "D702"

    def test_easily_forgotten_field_tracked(self):
        before = _run_dict(samples=[_sample(index1_cycles=8)])
        after = _run_dict(samples=[_sample(index1_cycles=10)])
        _, sc = diff_run(before, after)
        chg = next(f for f in sc[0]["fields"] if f["name"] == "index1_cycles")
        assert chg["before"] == 8 and chg["after"] == 10

    def test_sample_id_rename_same_uuid_is_modified_not_replace(self):
        before = _run_dict(samples=[_sample(sid_uuid="u1", sample_id="S1")])
        after = _run_dict(samples=[_sample(sid_uuid="u1", sample_id="S2")])
        _, sc = diff_run(before, after)
        assert len(sc) == 1 and sc[0]["kind"] == "modified"
        chg = next(f for f in sc[0]["fields"] if f["name"] == "sample_id")
        assert chg["before"] == "S1" and chg["after"] == "S2"


class TestIsEmpty:
    def test_empty_true_when_no_changes(self):
        fc, sc = diff_run(_run_dict(), _run_dict())
        assert is_empty(fc, sc) is True

    def test_empty_false_with_a_change(self):
        fc, sc = diff_run(_run_dict(), _run_dict(run_name="X"))
        assert is_empty(fc, sc) is False
