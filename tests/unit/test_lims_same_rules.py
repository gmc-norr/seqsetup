"""A LIMS worklist field that looks like an index or a lane must be one
SeqSetup reads (index mix-up audit, 2026-10-14; the user's choice "Same
rules as paste").

A field called "index" (Illumina's own name for the i7) was ignored, so the
sample came in with only its i5, and a lane field was ignored with every
sample put on lane 1. Now such a field refuses the whole worklist, naming
it; an admin can map a LIMS field to one SeqSetup reads in the LIMS
settings, and lanes come from the import's lane picker.
"""

import pytest

from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.services.sample_api import parse_api_samples

I7, I5 = "ATTACTCG", "TATAGCCT"
NOT_READ = "SeqSetup does not read"

# Every field name in the iGene LIMS API (igene_openapi.json): none of them
# may be refused by this rule.
IGENE_FIELDS = [
    "ExternalRID", "ExternalSampleID", "Father", "Investigator", "JointAnalysisID",
    "LibrarySampleID", "LibraryWorksheetID", "Mother", "NormalTumor", "Panels",
    "ParentSampleID", "PatientID", "PhenotypeStatus", "ReferralID", "ReferralType",
    "RootSampleType", "SampleFluoroConc", "SampleID", "SampleOD260230", "SampleOD260280",
    "SampleObtained", "SampleSpectroConc", "Sex", "TestID", "TestNotes", "TestProfile",
    "WorksheetID",
]


class TestAnUnreadIndexOrLaneFieldRefusesTheWorklist:

    @pytest.mark.parametrize("field", ["index", "Index", "Index 2", "barcode", "i7_index_id",
                                       "SampleIndex", "index_kit_version"])
    def test_an_index_like_field(self, field):
        with pytest.raises(ValueError, match=rf'LIMS row\(s\) 2: the field\(s\) "{field}" look like '
                                             rf"an index or a lane, but {NOT_READ} them"):
            parse_api_samples([{"sample_id": "P1"}, {"sample_id": "P2", field: I7}])

    def test_a_lane_field_says_where_lanes_come_from(self):
        with pytest.raises(ValueError, match="Lanes come from the Lanes picker on the import"):
            parse_api_samples([{"sample_id": "P1", "lane": 2}])

    def test_the_message_says_what_is_read_and_how_to_map(self):
        with pytest.raises(ValueError, match=(
                r"It reads the i7 from index_i7, index1, i7, index_i7_sequence or i7_sequence, "
                r"and the i5 from index_i5, index2, i5, index_i5_sequence or i5_sequence\. "
                r"An admin can map a LIMS field to one of these in the LIMS settings\.")):
            parse_api_samples([{"sample_id": "P1", "index": I7}])

    def test_an_empty_index_field_still_refuses(self):
        with pytest.raises(ValueError, match=NOT_READ):
            parse_api_samples([{"sample_id": "P1", "index": None}])

    def test_rows_are_named(self):
        with pytest.raises(ValueError, match=r"LIMS row\(s\) 1, 3: "):
            parse_api_samples([{"sample_id": "P1", "lane": 1}, {"sample_id": "P2"},
                               {"sample_id": "P3", "lane": 2}])


class TestWhatIsReadIsStillRead:

    def test_the_names_that_are_read(self):
        [row] = parse_api_samples([{"sample_id": "P1", "index_i7": I7, "index2": I5,
                                    "i7_name": "D701", "index_pair_name": "UDP1"}])
        assert (row["index1_sequence"], row["index2_sequence"]) == (I7, I5)

    def test_a_field_an_admin_mapped_is_read(self):
        config = SampleApiConfig(field_mappings={"index1_sequence": "Index"})
        [row] = parse_api_samples([{"sample_id": "P1", "Index": I7}], config)
        assert row["index1_sequence"] == I7

    def test_every_igene_field_is_let_through(self):
        row = {name: "x" for name in IGENE_FIELDS}
        row["SampleID"] = "P1"
        [read] = parse_api_samples([row])
        assert read["sample_id"] == "P1"
