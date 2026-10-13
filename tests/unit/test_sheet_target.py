"""Each stored Sample Sheet's target instrument and software (the user's
request, 2026-10-13): which instrument and which software the sheet was
written for, and how its i5 column was written. Worked out from the i5
direction the sheets were written with and the sheet text itself, never
from settings read later."""

import pytest

from seqsetup.data.instruments import I5Direction
from seqsetup.services.sheet_target import bclconvert_software_version, sheet_targets

V2 = (
    "[Header]\nFileFormatVersion,2\nInstrumentPlatform,NovaSeqXSeries\n\n"
    "[BCLConvert_Settings]\nSoftwareVersion,4.3.6\nFastqCompressionFormat,gzip\n\n"
    "[BCLConvert_Data]\nSample_ID,Index,Index2\nS1,AAAAAAAA,CCCCCCCC\n\n"
    "[DragenGermline_Settings]\nSoftwareVersion,4.4.1\n\n"
)
V1 = "[Header]\nIEMFileVersion,4\n\n[Data]\nSample_ID,index,index2\nS1,AAAAAAAA,CCCCCCCC\n"


def _direction(read, marks):
    return I5Direction(workflow="Some workflow", read_orientation=read, runinfo_marks_reversed=marks)


class TestTheV2Sheet:
    """BCL Convert reads the v2 sheet."""

    # (how the workflow reads the i5, does RunInfo.xml mark it) ->
    # (the Index2 column, does the sheet rely on BCL Convert acting on the mark)
    CASES = [
        ("forward", False, "forward", False),
        ("forward", True, "forward", False),
        ("reverse-complement", False, "reverse-complement", False),
        ("reverse-complement", True, "forward", True),
    ]

    @pytest.mark.parametrize("read,marks,column,needs_mark", CASES)
    def test_the_i5_column_follows_the_direction(self, read, marks, column, needs_mark):
        target = sheet_targets("NovaSeq X Series", _direction(read, marks), V2, None)["samplesheet_v2"]
        assert target == {
            "instrument": "NovaSeq X Series",
            "software": "BCL Convert",
            "software_version": "4.3.6",
            "i5_workflow": "Some workflow",
            "index2_column": column,
            "needs_runinfo_reverse_mark": needs_mark,
        }


class TestTheV1Sheet:
    """bcl2fastq reads the v1 sheet, and the i5 as the workflow reads it."""

    @pytest.mark.parametrize("read,marks,column", [
        ("forward", False, "forward"),
        ("reverse-complement", False, "reverse-complement"),
        ("reverse-complement", True, "reverse-complement"),
    ])
    def test_the_i5_column_is_as_the_workflow_reads_it(self, read, marks, column):
        target = sheet_targets("NovaSeq 6000", _direction(read, marks), V2, V1)["samplesheet_v1"]
        assert target == {
            "instrument": "NovaSeq 6000",
            "software": "bcl2fastq",
            "software_version": None,
            "i5_workflow": "Some workflow",
            "index2_column": column,
            "needs_runinfo_reverse_mark": False,
        }

    @pytest.mark.parametrize("v1", [None, ""])
    def test_no_v1_sheet_has_no_target(self, v1):
        assert sheet_targets("NovaSeq X Series", _direction("forward", False), V2, v1)["samplesheet_v1"] is None


class TestTheBclConvertVersion:
    """The version is the one the sheet's own [BCLConvert_Settings] states."""

    def test_only_the_bclconvert_section_counts(self):
        assert bclconvert_software_version(V2) == "4.3.6"

    def test_a_sheet_that_names_no_version(self):
        sheet = V2.replace("SoftwareVersion,4.3.6\n", "")
        assert bclconvert_software_version(sheet) is None

    def test_a_dragen_version_alone_is_not_a_bclconvert_version(self):
        sheet = "[Header]\nFileFormatVersion,2\n\n[DragenGermline_Settings]\nSoftwareVersion,4.4.1\n"
        assert bclconvert_software_version(sheet) is None
