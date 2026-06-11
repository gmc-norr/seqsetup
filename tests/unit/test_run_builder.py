"""Tests for build_draft_run — the shared clone/template instantiation path."""

import pytest

from seqsetup.models.analysis import Analysis, AnalysisType, DRAGENPipeline
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    RunStatus,
    SequencingRun,
    MAX_SAMPLES_PER_RUN,
)
from seqsetup.services.run_builder import (
    assert_references_available,
    build_draft_run,
    RunInstantiationError,
)


def _pair(i7="ATTACTCG", i5="TATAGCCT", name="D701"):
    return IndexPair(
        id=f"kit_{name}",
        name=name,
        index1=Index(name=name, sequence=i7, index_type=IndexType.I7),
        index2=Index(name="D501", sequence=i5, index_type=IndexType.I5),
    )


def _source_run(samples=None, analyses=None):
    return SequencingRun(
        run_name="Source",
        run_description="src desc",
        status=RunStatus.READY,
        created_by="bob",
        updated_by="bob",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        reagent_cycles=300,
        run_cycles=RunCycles(151, 151, 10, 10),
        no_lane_splitting=True,
        samples=samples or [],
        analyses=analyses or [],
        generated_samplesheet_v2="STALE",
        generated_json="STALE",
    )


class TestBuildDraftRunBasics:
    def test_result_is_fresh_draft_with_no_exports(self):
        src = _source_run(samples=[Sample(sample_id="S1", index_pair=_pair())])
        run = build_draft_run(
            config_source=src, samples=src.samples, created_by="alice",
            run_name="New", instrument_config=None,
        )
        assert run.status == RunStatus.DRAFT
        assert run.id != src.id
        assert run.created_by == "alice" and run.updated_by == "alice"
        assert run._loaded_updated_at is None
        assert run.generated_samplesheet_v2 is None
        assert run.generated_json is None
        assert run.run_name == "New"

    def test_config_copied_from_source(self):
        src = _source_run()
        run = build_draft_run(
            config_source=src, samples=[], created_by="alice",
            run_name="x", instrument_config=None,
        )
        assert run.instrument_platform == InstrumentPlatform.NOVASEQ_X
        assert run.flowcell_type == "10B"
        assert run.reagent_cycles == 300
        assert run.run_cycles.read1_cycles == 151
        assert run.no_lane_splitting is True
        assert run.run_description == "src desc"

    def test_samples_deep_copied_and_ids_preserved(self):
        s1 = Sample(sample_id="S1", index_pair=_pair())
        src = _source_run(samples=[s1])
        run = build_draft_run(
            config_source=src, samples=src.samples, created_by="alice",
            run_name="x", instrument_config=None,
        )
        assert len(run.samples) == 1
        assert run.samples[0] is not s1
        assert run.samples[0].id == s1.id
        assert run.samples[0].sample_id == "S1"

    def test_config_only_passes_empty_samples(self):
        src = _source_run(samples=[Sample(sample_id="S1", index_pair=_pair())])
        run = build_draft_run(
            config_source=src, samples=[], created_by="alice",
            run_name="x", instrument_config=None,
        )
        assert run.samples == []


class TestSampleCountCap:
    def test_refuses_when_included_samples_exceed_cap(self, monkeypatch):
        monkeypatch.setattr("seqsetup.services.run_builder.MAX_SAMPLES_PER_RUN", 2)
        src = _source_run()
        too_many = [Sample(sample_id=f"S{i}", index_pair=_pair()) for i in range(3)]
        with pytest.raises(RunInstantiationError, match="maximum"):
            build_draft_run(
                config_source=src, samples=too_many, created_by="alice",
                run_name="x", instrument_config=None,
            )


class TestAnalysesFiltering:
    def test_config_only_clone_drops_all_analyses(self):
        analyses = [Analysis(
            name="g", analysis_type=AnalysisType.DRAGEN_ONBOARD,
            dragen_pipeline=DRAGENPipeline.GERMLINE, sample_ids=["S1"],
        )]
        src = _source_run(
            samples=[Sample(sample_id="S1", index_pair=_pair())], analyses=analyses,
        )
        run = build_draft_run(
            config_source=src, samples=[], created_by="alice",
            run_name="x", instrument_config=None,
        )
        assert run.analyses == []

    def test_include_samples_keeps_analyses_filtered_to_included(self):
        analyses = [Analysis(
            name="g", analysis_type=AnalysisType.DRAGEN_ONBOARD,
            dragen_pipeline=DRAGENPipeline.GERMLINE, sample_ids=["S1", "S2"],
        )]
        s1 = Sample(sample_id="S1", index_pair=_pair())
        src = _source_run(samples=[s1], analyses=analyses)
        run = build_draft_run(
            config_source=src, samples=[s1], created_by="alice",
            run_name="x", instrument_config=None,
        )
        assert len(run.analyses) == 1
        assert run.analyses[0].sample_ids == ["S1"]
        assert run.analyses[0] is not analyses[0]

    def test_analysis_with_no_surviving_samples_is_dropped(self):
        analyses = [Analysis(
            name="g", analysis_type=AnalysisType.DRAGEN_ONBOARD,
            dragen_pipeline=DRAGENPipeline.GERMLINE, sample_ids=["OTHER"],
        )]
        s1 = Sample(sample_id="S1", index_pair=_pair())
        src = _source_run(samples=[s1], analyses=analyses)
        run = build_draft_run(
            config_source=src, samples=[s1], created_by="alice",
            run_name="x", instrument_config=None,
        )
        assert run.analyses == []


class TestAssertReferencesAvailable:
    def test_refuses_when_instrument_unavailable(self, monkeypatch):
        monkeypatch.setattr(
            "seqsetup.services.run_builder.get_flowcells_for_instrument",
            lambda platform, cfg=None: {},
        )
        with pytest.raises(RunInstantiationError, match="no longer available"):
            assert_references_available(_source_run(), None)

    def test_refuses_when_flowcell_withdrawn(self, monkeypatch):
        monkeypatch.setattr(
            "seqsetup.services.run_builder.get_flowcells_for_instrument",
            lambda platform, cfg=None: {"SOME_OTHER_FC": {}},
        )
        with pytest.raises(RunInstantiationError, match="no longer offered"):
            assert_references_available(_source_run(), None)

    def test_refuses_when_reagent_kit_withdrawn(self, monkeypatch):
        monkeypatch.setattr(
            "seqsetup.services.run_builder.get_flowcells_for_instrument",
            lambda platform, cfg=None: {"10B": {}},
        )
        monkeypatch.setattr(
            "seqsetup.services.run_builder.get_reagent_kits_for_flowcell",
            lambda platform, flowcell, cfg=None: [500, 600],  # 300 not offered
        )
        with pytest.raises(RunInstantiationError, match="no longer offered"):
            assert_references_available(_source_run(), None)

    def test_passes_when_all_available(self, monkeypatch):
        monkeypatch.setattr(
            "seqsetup.services.run_builder.get_flowcells_for_instrument",
            lambda platform, cfg=None: {"10B": {}},
        )
        monkeypatch.setattr(
            "seqsetup.services.run_builder.get_reagent_kits_for_flowcell",
            lambda platform, flowcell, cfg=None: [300, 500],  # 300 offered
        )
        # Should not raise.
        assert_references_available(_source_run(), None)

    def test_passes_when_flowcell_has_no_defined_reagent_kits(self, monkeypatch):
        # Empty reagent-kit list = unconstrained flowcell; check is skipped.
        monkeypatch.setattr(
            "seqsetup.services.run_builder.get_flowcells_for_instrument",
            lambda platform, cfg=None: {"10B": {}},
        )
        monkeypatch.setattr(
            "seqsetup.services.run_builder.get_reagent_kits_for_flowcell",
            lambda platform, flowcell, cfg=None: [],
        )
        assert_references_available(_source_run(), None)
