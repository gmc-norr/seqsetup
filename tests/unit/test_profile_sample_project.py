"""A profile's Sample_Project and Sample_Name columns hold the sample's own
project and name when it has them, and the profile's Data default only when it
does not (spec 2026-10-12 batch 2, 2b). Another spelling of either column is
refused, at Mark Ready and by the sync."""

import pytest

from seqsetup.input_rules.profiles import ProfileValidationError
from seqsetup.services.samplesheet_v2_exporter import SampleSheetV2Exporter

from .test_sheet_plan import BCL_FIELDS, _app, _dragen, _plan, _problems, _repos, _run, _sample
from .test_sheet_plan import _test as _test_profile


def check_application_profile(data, source_file=""):
    """The input rules for an application profile, through its one builder
    (input_rules/profiles.py; services/profile_validator.py was removed)."""
    from seqsetup.models.application_profile import ApplicationProfile

    ApplicationProfile.from_yaml(data, source_file)

BOTH = ["Sample_ID", "Lane", "Index", "Index2", "Sample_Name", "Sample_Project"]
DEFAULTS = {"Sample_Name": "PROFILE_NAME", "Sample_Project": "PROFILE_PROJECT"}


def _named(sample_id, name, project):
    sample = _sample(sample_id)
    sample.sample_name = name
    sample.project = project
    return sample


def _sheet(*samples, apps, test):
    test_repo, app_repo = _repos(apps, [test])
    return SampleSheetV2Exporter.export(_run(*samples), test_repo, app_repo)


def _bcl_sheet(profile, *samples):
    return _sheet(*samples, apps=[profile],
                  test=_test_profile("WGS", (profile.name, profile.version)))


def _section(sheet, application="BCLConvert"):
    """The application's data section: the header line, then its row lines."""
    lines = sheet.splitlines()
    start = lines.index(f"[{application}_Data]")
    rows = []
    for line in lines[start + 2:]:
        if not line:
            break
        rows.append(line)
    return lines[start + 1], rows


def _cells(sheet, application="BCLConvert"):
    """Each row of the application's data section as column -> cell. Only for
    sheets whose cells hold no comma."""
    header, rows = _section(sheet, application)
    return [dict(zip(header.split(","), row.split(","))) for row in rows]


class TestTheSamplesOwnValueWins:
    """The profile's default is the fallback, not the value."""

    def test_a_sample_with_its_own_project_and_name(self):
        sheet = _bcl_sheet(_app("BCLX", fields=BOTH, data=dict(DEFAULTS)),
                           _named("S1", "Patient-A", "ProjectA"))
        (row,) = _cells(sheet)
        assert row["Sample_ID"] == "S1"
        assert row["Sample_Name"] == "Patient-A"
        assert row["Sample_Project"] == "ProjectA"

    def test_a_sample_with_neither_takes_the_profiles_defaults(self):
        sheet = _bcl_sheet(_app("BCLX", fields=BOTH, data=dict(DEFAULTS)),
                           _named("S2", "", ""))
        (row,) = _cells(sheet)
        assert row["Sample_Name"] == "PROFILE_NAME"
        assert row["Sample_Project"] == "PROFILE_PROJECT"

    @pytest.mark.parametrize("name,project,written_name,written_project", [
        ("Patient-A", "", "Patient-A", "PROFILE_PROJECT"),
        ("", "ProjectA", "PROFILE_NAME", "ProjectA"),
    ])
    def test_each_cell_is_decided_on_its_own(self, name, project,
                                             written_name, written_project):
        sheet = _bcl_sheet(_app("BCLX", fields=BOTH, data=dict(DEFAULTS)),
                           _named("S1", name, project))
        (row,) = _cells(sheet)
        assert row["Sample_Name"] == written_name
        assert row["Sample_Project"] == written_project

    def test_both_samples_of_one_run_get_their_own(self):
        sheet = _bcl_sheet(_app("BCLX", fields=BOTH, data=dict(DEFAULTS)),
                           _named("S1", "Patient-A", "ProjectA"),
                           _named("S2", "", ""))
        first, second = _cells(sheet)
        assert (first["Sample_Name"], first["Sample_Project"]) == ("Patient-A", "ProjectA")
        assert (second["Sample_Name"], second["Sample_Project"]) == ("PROFILE_NAME",
                                                                    "PROFILE_PROJECT")

    def test_a_translated_field(self):
        """The dispatch reads the column the sheet gets, and the default still
        comes from the field's own Data key."""
        profile = _app("BCLX", fields=["Sample_ID", "Lane", "Index", "Index2", "Nm", "Proj"],
                       data={"Nm": "PROFILE_NAME", "Proj": "PROFILE_PROJECT"},
                       translate={"Nm": "Sample_Name", "Proj": "Sample_Project"})
        header, _ = _section(_bcl_sheet(profile, _named("S1", "Patient-A", "ProjectA")))
        assert header == "Sample_ID,Lane,Index,Index2,Sample_Name,Sample_Project"
        (row,) = _cells(_bcl_sheet(profile, _named("S1", "Patient-A", "ProjectA")))
        assert (row["Sample_Name"], row["Sample_Project"]) == ("Patient-A", "ProjectA")
        (empty,) = _cells(_bcl_sheet(profile, _named("S2", "", "")))
        assert (empty["Sample_Name"], empty["Sample_Project"]) == ("PROFILE_NAME",
                                                                  "PROFILE_PROJECT")

    def test_a_dragen_profile_too(self):
        dragen = _dragen("GermX", fields=["Sample_ID", "Sample_Name", "Sample_Project"],
                         data=dict(DEFAULTS))
        sheet = _sheet(_named("S1", "Patient-A", "ProjectA"), _named("S2", "", ""),
                       apps=[_app("BCLX"), dragen],
                       test=_test_profile("WGS", ("BCLX", "1.0.0"), ("GermX", "1.0.0")))
        first, second = _cells(sheet, "DragenGermline")
        assert (first["Sample_Name"], first["Sample_Project"]) == ("Patient-A", "ProjectA")
        assert (second["Sample_Name"], second["Sample_Project"]) == ("PROFILE_NAME",
                                                                     "PROFILE_PROJECT")

    def test_a_profile_with_no_default_leaves_the_cell_empty(self):
        sheet = _bcl_sheet(_app("BCLX", fields=BOTH, data={}), _named("S2", "", ""))
        (row,) = _cells(sheet)
        assert row["Sample_Name"] == ""
        assert row["Sample_Project"] == ""

    def test_a_column_the_writer_does_not_know_still_takes_the_default(self):
        sheet = _bcl_sheet(_app("BCLX", fields=BOTH + ["Comment"],
                                data=dict(DEFAULTS, Comment="FROM_PROFILE")),
                           _named("S1", "Patient-A", "ProjectA"))
        (row,) = _cells(sheet)
        assert row["Comment"] == "FROM_PROFILE"


class TestTheCellIsEscaped:
    def test_a_project_with_a_comma_does_not_shift_the_row(self):
        sheet = _bcl_sheet(_app("BCLX", fields=BOTH, data=dict(DEFAULTS)),
                           _named("S1", "Patient-A", "Project,A"))
        _, (row,) = _section(sheet)
        assert row == 'S1,1,ACGTACGTAC,TTGGCCAATT,Patient-A,"Project,A"'

    def test_a_project_in_the_identifier_alphabet_is_written_exactly(self):
        """A leading '-' must not pick up the formula guard's "'": that would
        change the directory BCL Convert writes the FASTQ files into."""
        sheet = _bcl_sheet(_app("BCLX", fields=BOTH, data=dict(DEFAULTS)),
                           _named("S1", "-Name_1", "-Project_1"))
        (row,) = _cells(sheet)
        assert row["Sample_Name"] == "-Name_1"
        assert row["Sample_Project"] == "-Project_1"


SPELLINGS = [
    ("sample_project", "Sample_Project"),
    ("SAMPLE_PROJECT", "Sample_Project"),
    ("Sample_name", "Sample_Name"),
]


class TestMarkReadyRefusesAnotherSpelling:
    """SeqSetup now fills both columns, so another spelling of one would get
    the profile's default in every row again."""

    @pytest.mark.parametrize("written,canonical", SPELLINGS)
    def test_in_a_bclconvert_profile(self, written, canonical):
        apps = [_app("BCLX", fields=BCL_FIELDS + [written], data={"BarcodeMismatchesIndex1": 1,
                                                                 "BarcodeMismatchesIndex2": 1,
                                                                 written: "x"}),
                _dragen("GermX")]
        plan = _plan(_run(_sample("S1")), apps,
                     [_test_profile("WGS", ("BCLX", "1.0.0"), ("GermX", "1.0.0"))])
        (problem,) = _problems(plan, "name_spelled_otherwise")
        assert problem.message == (
            f"Profile BCLX 1.0.0 spells {canonical} as '{written}' (in its columns). SeqSetup "
            f"fills and reads only the spelling {canonical}, so the Sample Sheet would not "
            f"carry what was checked.")

    @pytest.mark.parametrize("written,canonical", SPELLINGS)
    def test_in_a_dragen_profile(self, written, canonical):
        apps = [_app("BCLX"),
                _dragen("GermX", fields=["Sample_ID", written], data={written: "x"})]
        plan = _plan(_run(_sample("S1")), apps,
                     [_test_profile("WGS", ("BCLX", "1.0.0"), ("GermX", "1.0.0"))])
        (problem,) = _problems(plan, "name_spelled_otherwise")
        assert problem.message.startswith(
            f"Profile GermX 1.0.0 spells {canonical} as '{written}' (in its columns).")

    @pytest.mark.parametrize("column", ["Sample_Project", "Sample_Name"])
    def test_the_spelling_seqsetup_uses_is_not_refused(self, column):
        apps = [_app("BCLX"), _dragen("GermX", fields=["Sample_ID", column], data={column: "x"})]
        plan = _plan(_run(_sample("S1")), apps,
                     [_test_profile("WGS", ("BCLX", "1.0.0"), ("GermX", "1.0.0"))])
        assert _problems(plan, "name_spelled_otherwise") == []


class TestTheSyncRefusesAnotherSpelling:
    @pytest.mark.parametrize("written,canonical", SPELLINGS)
    def test_it_is_refused(self, written, canonical):
        profile = {
            "ApplicationProfileName": "P", "ApplicationProfileVersion": "1.0.0",
            "ApplicationName": "DragenGermline", "ApplicationType": "Dragen",
            "Settings": {"SoftwareVersion": "4.3.6"}, "Data": {written: "x"},
            "DataFields": ["Sample_ID", written], "Translate": {},
        }
        with pytest.raises(ProfileValidationError) as exc:
            check_application_profile(profile, "P.yaml")
        assert (f"DataFields > item 2: must be spelled {canonical}: SeqSetup fills and reads "
                f"{canonical} itself, in that spelling only") in exc.value.errors

    @pytest.mark.parametrize("column", ["Sample_Project", "Sample_Name"])
    def test_the_spelling_seqsetup_uses_passes(self, column):
        check_application_profile({
            "ApplicationProfileName": "P", "ApplicationProfileVersion": "1.0.0",
            "ApplicationName": "DragenGermline", "ApplicationType": "Dragen",
            "Settings": {"SoftwareVersion": "4.3.6"}, "Data": {column: "x"},
            "DataFields": ["Sample_ID", column], "Translate": {},
        }, "P.yaml")
