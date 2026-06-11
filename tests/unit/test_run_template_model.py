"""Tests for the RunTemplate model."""

from datetime import datetime

from seqsetup.models.analysis import Analysis, AnalysisType, DRAGENPipeline
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles
from seqsetup.models.run_template import RunTemplate


def _pair():
    return IndexPair(
        id="kit_D701",
        name="D701",
        index1=Index(name="D701", sequence="ATTACTCG", index_type=IndexType.I7),
        index2=Index(name="D501", sequence="TATAGCCT", index_type=IndexType.I5),
    )


class TestRunTemplateModel:
    def test_round_trips_through_dict(self):
        tmpl = RunTemplate(
            name="WGS Standard",
            description="Standard whole-genome assay",
            created_by="alice",
            updated_by="alice",
            run_description="seeded run description",
            instrument_platform=InstrumentPlatform.NOVASEQ_X,
            flowcell_type="10B",
            reagent_cycles=300,
            run_cycles=RunCycles(151, 151, 10, 10),
            barcode_mismatches_index1=1,
            barcode_mismatches_index2=1,
            no_lane_splitting=True,
            analyses=[Analysis(
                name="Germline",
                analysis_type=AnalysisType.DRAGEN_ONBOARD,
                dragen_pipeline=DRAGENPipeline.GERMLINE,
                sample_ids=["CTRL_POS"],
            )],
            scaffold_samples=[Sample(sample_id="CTRL_POS", index_pair=_pair())],
        )
        restored = RunTemplate.from_dict(tmpl.to_dict())
        assert restored.name == "WGS Standard"
        assert restored.description == "Standard whole-genome assay"
        assert restored.instrument_platform == InstrumentPlatform.NOVASEQ_X
        assert restored.flowcell_type == "10B"
        assert restored.reagent_cycles == 300
        assert restored.run_cycles.read1_cycles == 151
        assert restored.no_lane_splitting is True
        assert restored.scaffold_samples[0].sample_id == "CTRL_POS"
        assert restored.scaffold_samples[0].has_index is True
        assert restored.analyses[0].sample_ids == ["CTRL_POS"]

    def test_name_caps_and_strips_crlf_on_assignment(self):
        tmpl = RunTemplate(name="ok")
        tmpl.name = "bad\r\nname"
        assert "\r" not in tmpl.name and "\n" not in tmpl.name
        tmpl.name = "x" * 500
        assert len(tmpl.name) == 256

    def test_description_caps_on_assignment(self):
        tmpl = RunTemplate(name="ok")
        tmpl.description = "y" * 5000
        assert len(tmpl.description) == 4096

    def test_id_is_assigned_by_default(self):
        assert RunTemplate(name="ok").id
