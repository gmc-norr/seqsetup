"""A LIMS worklist field that looks like an index or a lane must be one
SeqSetup reads (index mix-up audit, 2026-10-14; the user's choice "Same
rules as paste").

A field called "index" (Illumina's own name for the i7) was ignored, so the
sample came in with only its i5, and a lane field was ignored with every
sample put on lane 1. Now such a field refuses the whole worklist, naming
it, and so do two names for one index; lanes come from the import's lane
picker.
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

    def test_the_message_says_what_is_read_and_what_to_do(self):
        with pytest.raises(ValueError, match=(
                r"It reads the i7 from index_i7, index1, i7, index_i7_sequence or i7_sequence, "
                r"and the i5 from index_i5, index2, i5, index_i5_sequence or i5_sequence\. "
                r"Rename or remove the field\(s\) in the LIMS\.$")):
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

    def test_a_name_the_stored_settings_map_is_read(self):
        # The admin page maps only worksheet fields; a stored mapping for an
        # index is still read, as before this rule.
        config = SampleApiConfig(field_mappings={"index1_sequence": "Index"})
        [row] = parse_api_samples([{"sample_id": "P1", "Index": I7}], config)
        assert row["index1_sequence"] == I7

    def test_every_igene_field_is_let_through(self):
        row = {name: "x" for name in IGENE_FIELDS}
        row["SampleID"] = "P1"
        [read] = parse_api_samples([row])
        assert read["sample_id"] == "P1"


class TestTwoNamesForOneIndexRefuseTheWorklist:
    """The paste refuses a second column for an index; the LIMS import kept
    the first name's value and dropped the other without a word — an empty
    first one left the sample with no i7 (review of 69d910a, P1)."""

    @pytest.mark.parametrize("first, second, value, label", [
        ("index1", "i7", I7, "an i7 sequence"),
        ("index_i7", "i7", "", "an i7 sequence"),
        ("index_i7", "i7", None, "an i7 sequence"),
        ("index_i5", "i5_sequence", I5, "an i5 sequence"),
        ("i7_name", "index_name", "D701", "an i7 name"),
        ("i5_name", "index2_name", "D501", "an i5 name"),
        ("index_pair_name", "pair_name", "UDP1", "an index name"),
    ])
    def test_two_names(self, first, second, value, label):
        with pytest.raises(ValueError, match=(
                rf'^LIMS row 2 has more than one name for {label} \("{first}", "{second}"\), so '
                rf"the whole worklist was refused: SeqSetup would read only one of them\. "
                rf"Send only one\.$")):
            parse_api_samples([{"sample_id": "P1"},
                               {"sample_id": "P2", first: value, second: "CCCCCCCC"}])

    def test_a_name_the_stored_settings_map_counts(self):
        config = SampleApiConfig(field_mappings={"index1_sequence": "Index"})
        with pytest.raises(ValueError, match=r'more than one name for an i7 sequence \("Index", "i7"\)'):
            parse_api_samples([{"sample_id": "P1", "Index": I7, "i7": I7}], config)
