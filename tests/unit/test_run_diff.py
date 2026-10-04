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
        # Every volatile/ignored key changes -> still no diff. Exercises all
        # five generated_* blobs so removing any from the denylist would fail.
        after = _run_dict(updated_at="2026-06-11T11:00:00", updated_by="alice",
                          wizard_step=3, generated_samplesheet_v2="SHEET",
                          generated_samplesheet_v1="V1", generated_json="J",
                          generated_validation_json="VJ", generated_validation_pdf="PDF")
        fc, sc = diff_run(_run_dict(), after)
        assert fc == [] and sc == []

    def test_nested_run_cycles_whole_value(self):
        fc, _ = diff_run(_run_dict(), _run_dict(run_cycles={"read1_cycles": 100}))
        assert any(c["field"] == "run_cycles" for c in fc)

    def test_run_level_analyses_change_tracked(self):
        # analyses drives DRAGEN/pipeline config; it is deliberately NOT in the
        # ignore list, so a run-level change must be captured.
        fc, _ = diff_run(_run_dict(analyses=[]),
                         _run_dict(analyses=[{"name": "DRAGEN"}]))
        chg = next(c for c in fc if c["field"] == "analyses")
        assert chg["before"] == [] and chg["after"] == [{"name": "DRAGEN"}]


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

    def test_all_index_assignment_fields_tracked(self):
        # The denylist must track every field that index assignment mutates;
        # an allowlist would silently drop these clinically-relevant changes.
        for field, b, a in [
            ("index2_cycles", 8, 10),
            ("index1_override_pattern", None, "I8N2"),
            ("index2_override_pattern", None, "I8N2"),
            ("override_cycles", None, "Y151;I8N2;I8N2;Y151"),
        ]:
            before = _run_dict(samples=[_sample(**{field: b})])
            after = _run_dict(samples=[_sample(**{field: a})])
            _, sc = diff_run(before, after)
            chg = next(f for f in sc[0]["fields"] if f["name"] == field)
            assert chg["before"] == b and chg["after"] == a, field

    def test_sample_level_analyses_change_tracked(self):
        before = _run_dict(samples=[_sample(analyses=[])])
        after = _run_dict(samples=[_sample(analyses=["a1"])])
        _, sc = diff_run(before, after)
        chg = next(f for f in sc[0]["fields"] if f["name"] == "analyses")
        assert chg["before"] == [] and chg["after"] == ["a1"]

    def test_sample_id_rename_same_uuid_is_modified_not_replace(self):
        before = _run_dict(samples=[_sample(sid_uuid="u1", sample_id="S1")])
        after = _run_dict(samples=[_sample(sid_uuid="u1", sample_id="S2")])
        _, sc = diff_run(before, after)
        assert len(sc) == 1 and sc[0]["kind"] == "modified"
        chg = next(f for f in sc[0]["fields"] if f["name"] == "sample_id")
        assert chg["before"] == "S1" and chg["after"] == "S2"

    def test_two_samples_both_modified(self):
        before = _run_dict(samples=[
            _sample(sid_uuid="u1", sample_id="S1", project="A"),
            _sample(sid_uuid="u2", sample_id="S2", project="B"),
        ])
        after = _run_dict(samples=[
            _sample(sid_uuid="u1", sample_id="S1", project="A2"),
            _sample(sid_uuid="u2", sample_id="S2", project="B2"),
        ])
        _, sc = diff_run(before, after)
        assert len(sc) == 2
        assert all(c["kind"] == "modified" for c in sc)
        assert {c["sample_id"] for c in sc} == {"S1", "S2"}

    def test_modified_sample_multiple_changed_fields(self):
        before = _run_dict(samples=[_sample(project="A", barcode_mismatches_index1=1)])
        after = _run_dict(samples=[_sample(project="B", barcode_mismatches_index1=0)])
        _, sc = diff_run(before, after)
        names = {f["name"] for f in sc[0]["fields"]}
        assert {"project", "barcode_mismatches_index1"} <= names

    def test_unchanged_sample_not_reported(self):
        # A sample present in both snapshots with no tracked change must produce
        # NO entry — a phantom "this sample changed" line is a clinical hazard.
        s = _sample()
        fc, sc = diff_run(_run_dict(samples=[s]), _run_dict(samples=[s]))
        assert sc == []


class TestIsEmpty:
    def test_empty_true_when_no_changes(self):
        fc, sc = diff_run(_run_dict(), _run_dict())
        assert is_empty(fc, sc) is True

    def test_empty_false_with_a_change(self):
        fc, sc = diff_run(_run_dict(), _run_dict(run_name="X"))
        assert is_empty(fc, sc) is False


class TestSampleOrder:
    """Each kind of change lists its samples in the run's sample order (the
    sample table's), not by their internal IDs: those are random, so the
    order would differ from one run to the next."""

    _UUIDS = ["u3", "u1", "u2"]

    def _samples(self, **over):
        return [_sample(sid_uuid=u, sample_id=f"S{n}", **over)
                for n, u in enumerate(self._UUIDS, start=1)]

    def test_added_samples_in_table_order(self):
        _, sc = diff_run(_run_dict(samples=[]), _run_dict(samples=self._samples()))
        assert [(c["kind"], c["sample_id"]) for c in sc] == [
            ("added", "S1"), ("added", "S2"), ("added", "S3")]

    def test_removed_samples_in_the_old_table_order(self):
        _, sc = diff_run(_run_dict(samples=self._samples()), _run_dict(samples=[]))
        assert [(c["kind"], c["sample_id"]) for c in sc] == [
            ("removed", "S1"), ("removed", "S2"), ("removed", "S3")]

    def test_modified_samples_in_table_order(self):
        before = _run_dict(samples=self._samples(project="A"))
        after = _run_dict(samples=self._samples(project="B"))
        _, sc = diff_run(before, after)
        assert [(c["kind"], c["sample_id"]) for c in sc] == [
            ("modified", "S1"), ("modified", "S2"), ("modified", "S3")]

    def test_removed_then_added_then_modified(self):
        before = _run_dict(samples=[_sample(sid_uuid="u9", sample_id="OLD"),
                                    _sample(sid_uuid="u5", sample_id="KEPT", project="A")])
        after = _run_dict(samples=[_sample(sid_uuid="u5", sample_id="KEPT", project="B"),
                                   _sample(sid_uuid="u0", sample_id="NEW")])
        _, sc = diff_run(before, after)
        assert [(c["kind"], c["sample_id"]) for c in sc] == [
            ("removed", "OLD"), ("added", "NEW"), ("modified", "KEPT")]
