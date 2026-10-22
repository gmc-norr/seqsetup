"""Every section the v2 Sample Sheet writer names in its own code, and every
section a shipped profile writes, is named as Illumina names it. (A lab's own
profile writes its ApplicationName as it is; that is not checked here.)

docs/design/2026-10-17-rna-section-spelling-design.md. The DRAGEN RNA
section is [DragenRna_Settings] / [DragenRna_Data] in Illumina's NovaSeq X
and NextSeq 1000/2000 sample sheet version histories; the second writer, which
hardcoded its section names and is gone (review TH-1), wrote
[DragenRNA_Settings] / [DragenRNA_Data]. The spelling is now a profile's own
ApplicationName, so what holds it is the check over every shipped profile
below.
"""

from ..sheet_through_profiles import sheet as _sheet

import re
from pathlib import Path

import yaml

from seqsetup.models.analysis import Analysis, AnalysisType, DRAGENPipeline
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services import samplesheet_v2_exporter
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter

# The section names in Illumina's sample sheet v2 version histories for
# NovaSeq X and NextSeq 1000/2000 (help.connected.illumina.com, 2026-10-17).
ILLUMINA = {"Header", "Reads", "Cloud_Settings", "Cloud_Data"} | {
    f"{app}_{part}"
    for app in ("BCLConvert", "DragenGermline", "DragenSomatic", "DragenRna",
                "DragenEnrichment", "DragenMethylation")
    for part in ("Settings", "Data")
}

PROFILES = Path(__file__).resolve().parents[2] / "config" / "profiles" / "application_profiles"


def _rna_run() -> SequencingRun:
    run = SequencingRun(id="rna", run_name="RNA", instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10))
    sample = Sample(sample_id="R1", lanes=[1])
    run.add_sample(sample)
    run.analyses.append(Analysis(name="RNA", analysis_type=AnalysisType.DRAGEN_ONBOARD,
                                 dragen_pipeline=DRAGENPipeline.RNA,
                                 reference_genome="hg38", sample_ids=["R1"]))
    return run


class TestTheRnaSection:

    def test_the_shipped_rna_profiles_section_is_illuminas_spelling(self):
        """Through the writer, from the shipped profile: the spelling the
        sheet gets is the profile's ApplicationName, so the profile is what
        this reads. (It used to read the second writer's own hardcoded name;
        with that writer gone, a synthetic profile would only have proved the
        writer echoes the name the test handed it.)"""
        import yaml as _yaml

        profile = _yaml.safe_load((PROFILES / "dragen" / "DragenRnaIdt.yaml").read_text())
        assert profile["ApplicationName"] == "DragenRna", profile["ApplicationName"]

        sheet = _sheet(_rna_run())

        assert "[DragenRna_Settings]" in sheet
        assert "[DragenRna_Data]" in sheet
        assert "DragenRNA" not in sheet


class TestEverySectionName:

    def test_every_section_the_writer_names_in_its_code_is_illuminas(self):
        source = Path(samplesheet_v2_exporter.__file__).read_text()
        written = set(re.findall(r'"\[([A-Za-z0-9_]+)\]\\n"', source))
        assert written, "the scan found no section header in the writer"
        assert written <= ILLUMINA, sorted(written - ILLUMINA)

    def test_every_section_a_shipped_profile_writes_is_illuminas(self):
        apps = {yaml.safe_load(p.read_text())["ApplicationName"] for p in PROFILES.rglob("*.yaml")}
        assert apps
        assert {f"{app}_Settings" for app in apps} <= ILLUMINA
