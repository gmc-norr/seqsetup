"""The rulebook for application and test profiles
(docs/design/2026-10-18-input-rules-design.md, "Step 2: application and test
profiles").

A profile's Settings and Data are copied into the Sample Sheet. Every key of
both documents is named and any other is refused; the keys inside Settings and
Data stay open, but their shape is checked: a plain name, and a value that is
text, a whole number or true/false.
"""

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


class TestTheNamesTheRulesUseLoadNoApp:
    """The names SeqSetup spells its one way lived beside the sheet plan,
    whose imports run the instrument start-up: with a broken
    INSTRUMENTS_CONFIG, importing them stopped, and the settings command
    could not have used them."""

    def test_they_import_without_the_instrument_start_up(self):
        code = ("from seqsetup.services.sheet_text import SPELLED_COLUMNS_ANY, "
                "SPELLED_COLUMNS_BCLCONVERT, SPELLED_SETTINGS_ANY, SPELLED_SETTINGS_BCLCONVERT\n"
                "import sys\n"
                "print([m for m in ('seqsetup.data.instruments', 'seqsetup.services.sheet_plan')"
                " if m in sys.modules])\n")
        env = {**os.environ, "PYTHONPATH": str(REPO / "src"),
               "INSTRUMENTS_CONFIG": "/nonexistent/instruments.yaml",
               "MONGODB_URI": "mongodb://127.0.0.1:1"}

        done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                              env=env, timeout=60)

        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == "[]"

    def test_the_sheet_plan_uses_the_same_lists(self):
        from seqsetup.services import sheet_plan, sheet_text

        for name in ("SPELLED_SETTINGS_ANY", "SPELLED_COLUMNS_ANY",
                     "SPELLED_COLUMNS_BCLCONVERT", "SPELLED_SETTINGS_BCLCONVERT"):
            assert getattr(sheet_plan, name) is getattr(sheet_text, name)


import bson
import pytest
import yaml

from seqsetup.input_rules.problems import problem_line
from seqsetup.input_rules.profiles import (
    build_application_profile,
    check_application_profile_file,
    check_test_profile_file,
    repeated_app_versions,
    repeated_test_versions,
    build_test_profile,
    differing_only_in_capitals,
)
from seqsetup.models.application_profile import ApplicationProfile
from seqsetup.models.test_profile import TestProfile as StoredTestProfile

CONFIG = REPO / "config" / "profiles"
APPS = sorted((CONFIG / "application_profiles").rglob("*.yaml"))
TESTS = sorted((CONFIG / "test_profiles").rglob("*.yaml"))

APP = """\
ApplicationProfileName: BCLConvertTest
ApplicationProfileVersion: 1.0.0
ApplicationName: BCLConvert
ApplicationType: Dragen
Settings:
  SoftwareVersion: 4.3.6
  FastqCompressionFormat: gzip
Data:
  BarcodeMismatchesIndex1: 1
DataFields:
  - Sample_ID
  - IndexI7
  - BarcodeMismatchesIndex1
Translate:
  IndexI7: Index
"""

TEST = """\
TestType: WGS
TestName: WGS
Description: Whole Genome Sequencing
Version: 1.0.0
TestApplicationProfiles:
  OnInstrument:
    - ApplicationProfileName: BCLConvertTest
      ApplicationProfileVersion: "~=1.0.0"
"""


def _app(text):
    return check_application_profile_file(text, "app.yaml")


def _test(text):
    return check_test_profile_file(text, "test.yaml")


def _errors(result):
    return [(p.path, p.message) for p in result.problems if p.level == "error"]


def _only(result):
    (error,) = [p for p in result.problems if p.level == "error"]
    return error


def _external(text=APP):
    return text.replace("ApplicationType: Dragen", "ApplicationType: External")


class TestTheShippedProfiles:

    @pytest.mark.parametrize("path", APPS, ids=lambda p: p.name)
    def test_every_shipped_application_profile_passes(self, path):
        assert _errors(_app(path.read_text())) == []

    @pytest.mark.parametrize("path", TESTS, ids=lambda p: p.name)
    def test_every_shipped_test_profile_passes(self, path):
        assert _errors(_test(path.read_text())) == []

    def test_the_examples_here_pass(self):
        assert _errors(_app(APP)) == [] and _errors(_test(TEST)) == []


class TestUnknownKeys:
    """Ignored before: a misspelt section left the profile without it."""

    def test_at_the_top_of_an_application_profile(self):
        error = _only(_app(APP + "Setings:\n  X: 1\n"))

        assert (error.path, error.line) == (("Setings",), len(APP.splitlines()) + 1)
        assert error.message == "is not a key this file can have (check the spelling)"

    def test_at_the_top_of_a_test_profile(self):
        assert _only(_test(TEST + "Owner: lab\n")).path == ("Owner",)

    def test_in_a_reference(self):
        error = _only(_test(TEST + "      Note: x\n"))

        assert error.path == ("TestApplicationProfiles", "OnInstrument", 0, "Note")
        assert "TestApplicationProfiles > OnInstrument > item 1 > Note: is not a key" in problem_line(error)


class TestRequiredKeys:

    @pytest.mark.parametrize("key", ["ApplicationProfileName", "ApplicationProfileVersion",
                                     "ApplicationName", "ApplicationType"])
    def test_of_an_application_profile(self, key):
        text = "".join(r for r in APP.splitlines(keepends=True) if not r.startswith(f"{key}:"))

        assert ((key,), "is required") in _errors(_app(text))

    @pytest.mark.parametrize("key", ["TestType", "TestName", "Description", "Version",
                                     "TestApplicationProfiles"])
    def test_of_a_test_profile(self, key):
        rows = TEST.splitlines(keepends=True)
        if key == "TestApplicationProfiles":
            rows = rows[:4]
        text = "".join(r for r in rows if not r.startswith(f"{key}:"))

        assert ((key,), "is required") in _errors(_test(text))

    def test_a_reference_s_name(self):
        text = TEST.replace("    - ApplicationProfileName: BCLConvertTest\n      ApplicationProfileVersion",
                            "    - ApplicationProfileVersion")

        assert (("TestApplicationProfiles", "OnInstrument", 0, "ApplicationProfileName"), "is required") in _errors(_test(text))

    def test_a_reference_s_version(self):
        text = TEST.replace('      ApplicationProfileVersion: "~=1.0.0"\n', "")

        assert (("TestApplicationProfiles", "OnInstrument", 0, "ApplicationProfileVersion"), "is required") in _errors(_test(text))


class TestFilledText:
    """Text of spaces only is refused, as it is today; the value is stored as
    written, never trimmed."""

    @pytest.mark.parametrize("old, key", [
        ("TestType: WGS", "TestType"), ("TestName: WGS", "TestName"),
        ("Description: Whole Genome Sequencing", "Description"),
    ])
    def test_in_a_test_profile(self, old, key):
        assert ((key,), "must not be empty") in _errors(_test(TEST.replace(old, f"{key}: ' '")))

    @pytest.mark.parametrize("old, key", [
        ("ApplicationProfileName: BCLConvertTest", "ApplicationProfileName"),
        ("ApplicationType: Dragen", "ApplicationType"),
        ("ApplicationProfileVersion: 1.0.0", "ApplicationProfileVersion"),
    ])
    def test_in_an_application_profile(self, old, key):
        assert ((key,), "must not be empty") in _errors(_app(APP.replace(old, f"{key}: ' '")))

    @pytest.mark.parametrize("version", ["''", "' '"])
    def test_a_blank_version_in_a_reference(self, version):
        """SpecifierSet("") and SpecifierSet(" ") are valid specifiers."""
        text = TEST.replace('ApplicationProfileVersion: "~=1.0.0"', f"ApplicationProfileVersion: {version}")

        assert _only(_test(text)).path == ("TestApplicationProfiles", "OnInstrument", 0, "ApplicationProfileVersion")

    def test_text_with_spaces_around_is_kept_as_written(self):
        result = _test(TEST.replace("TestName: WGS", "TestName: ' WGS '"))

        assert build_test_profile(result.value, "test.yaml").test_name == " WGS "


class TestVersions:

    @pytest.mark.parametrize("version, says", [
        ("'not a version'", "is not a valid PEP 440 version"),
        ("'1.0+" + "a" * 253 + "'", "must be at most 256 characters"),
    ])
    def test_an_application_profile_version(self, version, says):
        error = _only(_app(APP.replace("ApplicationProfileVersion: 1.0.0", f"ApplicationProfileVersion: {version}")))

        assert error.path == ("ApplicationProfileVersion",) and says in error.message

    def test_a_version_of_256_characters_is_fine(self):
        version = "1.0+" + "a" * 252

        assert _errors(_app(APP.replace("ApplicationProfileVersion: 1.0.0", f"ApplicationProfileVersion: {version}"))) == []

    @pytest.mark.parametrize("version, says", [
        ("'not one'", "is not a valid PEP 440 version or specifier"),
        ("'===" + "a" * 254 + "'", "must be at most 256 characters"),
    ])
    def test_a_reference_version(self, version, says):
        text = TEST.replace('ApplicationProfileVersion: "~=1.0.0"', f"ApplicationProfileVersion: {version}")

        assert says in _only(_test(text)).message

    @pytest.mark.parametrize("version", ["'1.0'", "'1.0.0rc1'", "'01.0.0'"])
    def test_a_test_version_is_three_whole_numbers(self, version):
        error = _only(_test(TEST.replace("Version: 1.0.0", f"Version: {version}")))

        assert error.path == ("Version",) and "three whole numbers" in error.message

    @pytest.mark.parametrize("text, key", [
        ("ApplicationProfileVersion: 1", "ApplicationProfileVersion"), ("ApplicationType: 1", "ApplicationType"),
    ])
    def test_a_whole_number_where_text_belongs(self, text, key):
        old = next(r for r in APP.splitlines() if r.startswith(f"{key}:"))

        assert ((key,), "must be text: put it in quotes") in _errors(_app(APP.replace(old, text)))

    def test_test_type_5_is_refused_not_a_crash(self):
        assert (("TestType",), "must be text: put it in quotes") in _errors(_test(TEST.replace("TestType: WGS", "TestType: 5")))


class TestEveryBoundAtItsEdge:
    """Each length and range is taken at its edge and refused one past it
    (the fresh review of b21ea6f, P3 2): a whole number past 64 bits once
    passed the check and stopped the sync's save after it had deleted the
    stored profiles."""

    @pytest.mark.parametrize("old, key", [
        ("ApplicationProfileName: BCLConvertTest", ("ApplicationProfileName",)),
    ])
    def test_text_in_an_application_profile(self, old, key):
        name = key[0]

        assert _errors(_app(APP.replace(old, f"{name}: " + "a" * 256))) == []
        assert _errors(_app(APP.replace(old, f"{name}: " + "a" * 257))) == [
            (key, "must be at most 256 characters")]

    def test_the_type_of_an_application_profile(self):
        """Only a Dragen type is checked (a file of another type is skipped,
        docs/design/2026-10-19-lab-profile-layout-design.md), so the edge is
        taken on Dragen padded with spaces, which still reads as Dragen."""
        def typed(length):
            return APP.replace("ApplicationType: Dragen", f'ApplicationType: "Dragen{" " * (length - 6)}"')

        assert _errors(_app(typed(256))) == []
        assert _errors(_app(typed(257))) == [(("ApplicationType",), "must be at most 256 characters")]

    @pytest.mark.parametrize("old, key, most", [
        ("TestType: WGS", ("TestType",), 256),
        ("TestName: WGS", ("TestName",), 256),
        ("Description: Whole Genome Sequencing", ("Description",), 4096),
        ("    - ApplicationProfileName: BCLConvertTest",
         ("TestApplicationProfiles", "OnInstrument", 0, "ApplicationProfileName"), 256),
    ])
    def test_text_in_a_test_profile(self, old, key, most):
        start = old[:old.index(":") + 2]

        assert _errors(_test(TEST.replace(old, start + "a" * most))) == []
        assert _errors(_test(TEST.replace(old, start + "a" * (most + 1)))) == [
            (key, f"must be at most {most} characters")]

    @pytest.mark.parametrize("value, says", [
        (2**63, "must be at most 9223372036854775807"),
        (-2**63 - 1, "must be at least -9223372036854775808"),
    ])
    def test_a_whole_number_in_the_sheet(self, value, says):
        def written(number):
            return _errors(_app(APP.replace("FastqCompressionFormat: gzip",
                                            f"FastqCompressionFormat: {number}")))

        assert written(2**63 - 1) == [] and written(-2**63) == []
        assert written(value) == [(("Settings", "FastqCompressionFormat"), says)]


class TestAValueIsNeverQuoted:
    """A profile may hold a pipeline's address or key, so no message quotes a
    value, though the reader quotes one in an instrument file (the fresh
    review of b21ea6f, P3 7). The values are spellings the reader refuses:
    a key of digits with a leading 0, in hex, or with a decimal point."""

    SECRETS = ["0731554455", "0x5EC2E7", "31554455.0731"]

    @pytest.mark.parametrize("secret", SECRETS)
    def test_in_an_application_profile(self, secret):
        result = _app(APP.replace("FastqCompressionFormat: gzip", f"FastqCompressionFormat: {secret}"))

        assert [p.path for p in result.problems] == [("Settings", "FastqCompressionFormat")]
        assert secret not in problem_line(result.problems[0])

    @pytest.mark.parametrize("key", ["TestName", "Description"])
    @pytest.mark.parametrize("secret", SECRETS)
    def test_in_a_test_profile(self, key, secret):
        old = next(row for row in TEST.splitlines() if row.startswith(f"{key}:"))

        result = _test(TEST.replace(old, f"{key}: {secret}"))

        assert [p.path for p in result.problems] == [(key,)]
        assert secret not in problem_line(result.problems[0])


class TestSheetValues:
    """Settings and Data keys are open, but each is a plain name and each
    value is text, a whole number or true/false."""

    @pytest.mark.parametrize("value", ["true", "False", "4", "-1", "text", "''", "'012'"])
    def test_each_kind_is_taken(self, value):
        assert _errors(_app(APP.replace("FastqCompressionFormat: gzip", f"FastqCompressionFormat: {value}"))) == []

    @pytest.mark.parametrize("value, says", [
        ("[a, b]", "must be text, a whole number or true/false"),
        ("{a: 1}", "must be text, a whole number or true/false"),
        # Keys named as Pydantic names the kinds it tried (the fresh review
        # of b21ea6f, P3 5): one problem, at the value, never at "X > bool".
        ("{bool: 1, int: 2}", "must be text, a whole number or true/false"),
        ("", "needs a value: write '' if it should be empty"),
        ("'" + "x" * 4097 + "'", "must be at most 4096 characters"),
        ('"a\\tb"', "holds a hidden character: U+0009 (tab)"),
        ("' [Data]'", "cannot start with '['"),
    ])
    def test_a_value_that_cannot_be_written(self, value, says):
        error = _only(_app(APP.replace("FastqCompressionFormat: gzip", f"FastqCompressionFormat: {value}")))

        assert error.path == ("Settings", "FastqCompressionFormat")
        assert says in error.message

    @pytest.mark.parametrize("value", ["yes", "012", "2026-01-01", "4.10"])
    def test_a_value_yaml_would_change_is_refused_by_the_reader(self, value):
        error = _only(_app(APP.replace("FastqCompressionFormat: gzip", f"FastqCompressionFormat: {value}")))

        assert error.path == ("Settings", "FastqCompressionFormat")

    @pytest.mark.parametrize("key, shown", [
        ("true", "true"), ("false", "false"), ("~", "null"), ("null", "null"), ("5", "5"),
    ])
    def test_a_key_that_is_not_text_is_named_on_its_own_line(self, key, shown):
        """Pydantic names a key of true, false or null as 1, 0 or None (the
        fresh review of b21ea6f, P3 5)."""
        error = _only(_app(APP.replace("FastqCompressionFormat: gzip", f"{key}: gzip")))

        assert problem_line(error) == f"app.yaml:7:3: Settings > {shown}: must be text: put it in quotes"

    @pytest.mark.parametrize("key", ["'Fastq Format'", "'[BCLConvert_Data]'"])
    def test_a_name_that_is_not_plain(self, key):
        error = _only(_app(APP.replace("FastqCompressionFormat: gzip", f"{key}: gzip")))

        assert error.path[0] == "Settings"
        assert "may only hold letters, digits, '_' and '-'" in error.message

    def test_a_data_field_written_as_a_number(self):
        error = _only(_app(APP.replace("  - IndexI7\n", "  - 5\n").replace("  IndexI7: Index\n", "  X: Index\n")))

        assert error.path == ("DataFields", 1) and error.message == "must be text: put it in quotes"

    def test_a_translate_name_that_is_not_plain(self):
        assert _only(_app(APP.replace("IndexI7: Index", "IndexI7: 'In dex'"))).path == ("Translate", "IndexI7")


class TestTheDragenType:

    @pytest.mark.parametrize("key", ["Settings", "Data", "DataFields"])
    def test_a_section_left_out_is_refused(self, key):
        text = _without(APP, key)

        assert ((key,), "is required when the type is Dragen") in _errors(_app(text))

    @pytest.mark.parametrize("key", ["Settings", "Data", "DataFields"])
    def test_an_empty_section_is_refused(self, key):
        text = _without(APP, key) + f"{key}:\n"

        assert (key,) in [path for path, _ in _errors(_app(text))]

    def test_the_type_is_read_trimmed_and_in_any_case(self):
        text = _without(APP, "Settings").replace("ApplicationType: Dragen", "ApplicationType: ' dRaGeN '")

        assert (("Settings",), "is required when the type is Dragen") in _errors(_app(text))

    def test_an_empty_translate_means_none(self):
        result = _app(_without(APP, "Translate").replace("  - IndexI7\n", "") + "Translate:\n")

        assert _errors(result) == []
        assert build_application_profile(result.value, "app.yaml").translate == {}

    def test_another_type_is_skipped_whatever_its_sections(self):
        """A file whose type is not Dragen is left to other tools, unchecked
        (docs/design/2026-10-19-lab-profile-layout-design.md)."""
        text = _external(APP.replace("ApplicationName: BCLConvert", "ApplicationName: CloudGenomics"))
        for key in ("Settings", "Data", "Translate"):
            text = _without(text, key)
        text = text.replace("  - IndexI7\n", "").replace("  - BarcodeMismatchesIndex1\n", "") + "Settings:\n"

        result = _app(text)
        assert (result.skipped, result.problems) == ("External", [])

    def test_another_type_naming_an_illumina_application_is_refused(self):
        assert _errors(_app(_external(APP))) == [
            (("ApplicationType",), "must be Dragen: BCLConvert is one of Illumina's applications, "
                                   "which SeqSetup writes into the Sample Sheet")]


class TestApplicationNames:

    def test_a_dragen_profile_names_an_illumina_application(self):
        error = _only(_app(APP.replace("ApplicationName: BCLConvert", "ApplicationName: DragenGermlin")))

        assert error.path == ("ApplicationName",)
        assert "is not one of Illumina's application names" in error.message

    @pytest.mark.parametrize("name", ["CloudGenomics", "'Cloud Genomics'", "nf-core/raredisease"])
    def test_an_external_profile_s_name_is_not_checked(self, name):
        """It is skipped, never written into the sheet
        (docs/design/2026-10-19-lab-profile-layout-design.md)."""
        result = _app(_external(APP.replace("ApplicationName: BCLConvert", f"ApplicationName: {name}")))

        assert (result.skipped, result.problems) == ("External", [])


class TestSoftwareVersion:
    """The validation service compares SoftwareVersion with the instrument's
    versions and sorts a run's versions: 4 beside "4.3.6" stopped it with
    TypeError (sol's review of step 2's design, P2-1)."""

    @pytest.mark.parametrize("value", ["4", "true", "'4.3 beta'"])
    def test_must_be_a_version_written_as_text(self, value):
        error = _only(_app(APP.replace("SoftwareVersion: 4.3.6", f"SoftwareVersion: {value}")))

        assert error.path == ("Settings", "SoftwareVersion")
        assert "must be a version written as text" in error.message

    def test_a_version_written_as_text_is_fine(self):
        assert _errors(_app(APP.replace("SoftwareVersion: 4.3.6", "SoftwareVersion: '4.3.6-rc1'"))) == []


class TestTheRulesMovedFromTheOldValidator:

    @pytest.mark.parametrize("section, value", [("Settings", "3"), ("Settings", "na"), ("Data", "3"), ("Data", "true")])
    def test_a_mismatch_value_bcl_convert_does_not_take(self, section, value):
        if section == "Settings":
            text = APP.replace("  FastqCompressionFormat: gzip\n", f"  FastqCompressionFormat: gzip\n  BarcodeMismatchesIndex2: {value}\n")
        else:
            text = APP.replace("  BarcodeMismatchesIndex1: 1\n", f"  BarcodeMismatchesIndex1: {value}\n")

        error = _only(_app(text))
        assert error.path[0] == section and "BCL Convert allows at most 2 mismatches" in error.message

    @pytest.mark.parametrize("value", ["na", "''", "0", "'2'"])
    def test_a_data_default_may_be_blank_or_na(self, value):
        assert _errors(_app(APP.replace("  BarcodeMismatchesIndex1: 1\n", f"  BarcodeMismatchesIndex1: {value}\n"))) == []

    def test_a_data_key_is_checked_under_the_column_translate_gives_it(self):
        text = APP.replace("  BarcodeMismatchesIndex1: 1\n", "  MM1: 5\n").replace(
            "  - BarcodeMismatchesIndex1\n", "  - MM1\n") + "  MM1: BarcodeMismatchesIndex1\n"

        error = _only(_app(text))
        assert error.path == ("Data", "MM1") and "fills BarcodeMismatchesIndex1" in error.message

    def test_a_data_section_with_no_sample_id_column(self):
        error = _only(_app(APP.replace("  - Sample_ID\n", "")))

        assert "no Sample_ID column" in error.message

    def test_a_column_written_twice_whatever_its_case(self):
        errors = _errors(_app(APP.replace("  - IndexI7\n", "  - IndexI7\n  - index\n")))

        assert any("writes the column 'Index' more than once: from IndexI7, index" in m for _, m in errors)

    def test_a_bclconvert_name_both_in_settings_and_a_column(self):
        error = _only(_app(APP.replace("  FastqCompressionFormat: gzip\n", "  FastqCompressionFormat: gzip\n  BarcodeMismatchesIndex1: 1\n")))

        assert error.path == ("Settings", "BarcodeMismatchesIndex1") and "in one place only" in error.message

    def test_a_name_seqsetup_fills_spelled_another_way(self):
        errors = _errors(_app(APP.replace("  - Sample_ID\n", "  - sample_id\n")))

        assert (("DataFields", 0), "must be spelled Sample_ID: SeqSetup fills and reads Sample_ID "
                "itself, in that spelling only") in errors

    @pytest.mark.parametrize("setting", ["OverrideCycles", "indexorientation"])
    def test_a_bclconvert_setting_that_changes_how_the_i5_is_read(self, setting):
        text = APP.replace("  FastqCompressionFormat: gzip\n", f"  FastqCompressionFormat: gzip\n  {setting}: x\n")

        assert any("SeqSetup writes the i5 and OverrideCycles itself" in m for _, m in _errors(_app(text)))


def _typed(value):
    """A value with the type of every part and the order of every map: ``==``
    takes True for 1 and ignores the order of keys, and the sheet writes
    True, 1 and "1" differently, in the order the profile gives."""
    if isinstance(value, dict):
        return [(key, _typed(item)) for key, item in value.items()]
    if isinstance(value, list):
        return [_typed(item) for item in value]
    return (type(value).__name__, value)


def _sections(profile):
    return _typed([profile.settings, profile.data, profile.data_fields, profile.translate])


class TestTheConvertedProfile:
    """Every synced profile is built by the converter; the 78-sheet corpus
    loads its profiles without it, so only these tests see a value it would
    change (the fresh review of b21ea6f, P2 1)."""

    @pytest.mark.parametrize("path", APPS, ids=lambda p: p.name)
    def test_a_shipped_application_profile_is_the_file_as_written(self, path):
        raw = yaml.safe_load(path.read_text())
        profile = build_application_profile(_app(path.read_text()).value, path.name)

        assert (profile.name, profile.version, profile.application_type, profile.application_name) == (
            raw["ApplicationProfileName"], str(raw["ApplicationProfileVersion"]),
            raw["ApplicationType"], raw["ApplicationName"])
        assert _sections(profile) == _typed([
            raw.get("Settings") or {}, raw.get("Data") or {}, raw.get("DataFields") or [],
            raw.get("Translate") or {}])
        assert profile.source_file == path.name
        stored = ApplicationProfile.from_dict(bson.decode(bson.encode(profile.to_dict())))
        assert _sections(stored) == _sections(profile)

    def test_every_kind_of_value_keeps_its_type_and_its_place(self):
        text = APP.replace("  BarcodeMismatchesIndex1: 1\n", (
            "  BarcodeMismatchesIndex1: 1\n  Zeta: true\n  Alpha: '1'\n  Mid: -5\n"
            "  Beta: false\n  Empty: ''\n"))
        raw = yaml.safe_load(text)

        profile = build_application_profile(_app(text).value, "app.yaml")

        assert _typed(profile.data) == [
            ("BarcodeMismatchesIndex1", ("int", 1)), ("Zeta", ("bool", True)),
            ("Alpha", ("str", "1")), ("Mid", ("int", -5)), ("Beta", ("bool", False)),
            ("Empty", ("str", ""))]
        assert _typed(profile.data) == _typed(raw["Data"])
        stored = ApplicationProfile.from_dict(bson.decode(bson.encode(profile.to_dict())))
        assert _sections(stored) == _sections(profile)

    @pytest.mark.parametrize("path", TESTS, ids=lambda p: p.name)
    def test_a_shipped_test_profile_is_the_file_as_written(self, path):
        raw = yaml.safe_load(path.read_text())
        profile = build_test_profile(_test(path.read_text()).value, path.name)

        assert (profile.test_type, profile.test_name, profile.description, profile.version) == (
            raw["TestType"], raw["TestName"], raw["Description"], raw["Version"])
        assert [(r.profile_name, r.profile_version) for r in profile.application_profiles] == [
            (r["ApplicationProfileName"], r["ApplicationProfileVersion"]) for r in raw["TestApplicationProfiles"]["OnInstrument"]]
        stored = StoredTestProfile.from_dict(bson.decode(bson.encode(profile.to_dict())))
        assert stored.to_dict() == profile.to_dict()

    def test_from_yaml_uses_the_same_rules(self):
        from seqsetup.input_rules.profiles import ProfileValidationError

        data = yaml.safe_load(APP)
        data["Setings"] = {}
        with pytest.raises(ProfileValidationError, match="Setings: is not a key"):
            ApplicationProfile.from_yaml(data, "app.yaml")


class TestRulesAcrossFiles:

    def _apps(self, *versions):
        return [build_application_profile(_app(APP.replace("ApplicationProfileVersion: 1.0.0",
                                                           f"ApplicationProfileVersion: '{v}'")).value,
                                          f"a{n}.yaml")
                for n, v in enumerate(versions)]

    def test_a_profile_name_and_version_in_two_files(self):
        (problem,) = repeated_app_versions(self._apps("1.0", "1.0.0"), ["x/a.yaml", "y/a.yaml"])

        assert "BCLConvertTest 1.0 = 1.0.0 is in x/a.yaml and y/a.yaml" in problem

    def test_a_test_and_version_in_two_files(self):
        tests = [build_test_profile(_test(TEST).value, "t.yaml")] * 2

        (problem,) = repeated_test_versions(tests, ["x/t.yaml", "y/t.yaml"])
        assert problem == "WGS 1.0.0 is in x/t.yaml and y/t.yaml"

    def test_two_differing_only_in_capitals(self):
        tests = [build_test_profile(_test(TEST).value, "a.yaml"),
                 build_test_profile(_test(TEST.replace("TestName: WGS", "TestName: Wgs")).value, "b.yaml")]

        (problem,) = differing_only_in_capitals(tests, ["a.yaml", "b.yaml"])
        assert problem == "WGS in a.yaml and Wgs in b.yaml differ only in capitals"

    def _named(self, name, test_type="WGS"):
        text = TEST.replace("TestName: WGS", f"TestName: {name}").replace(
            "TestType: WGS", f"TestType: {test_type}")
        return build_test_profile(_test(text).value, f"{name}.yaml")

    def test_two_names_of_one_type_and_version_are_two_tests(self):
        """The lab's two WGS tests, one per downstream pipeline (the user's
        word, 2026-10-21; docs/design/2026-10-21-tests-by-name-design.md)."""
        tests = [self._named("WGSRareDisease_1"), self._named("WGSRareDiseaseResearch_1")]

        assert repeated_test_versions(tests, ["a.yaml", "b.yaml"]) == []
        assert differing_only_in_capitals(tests, ["a.yaml", "b.yaml"]) == []

    def test_one_name_and_version_of_two_types_is_one_test_given_twice(self):
        tests = [self._named("Exome", "WES"), self._named("Exome", "WGS")]

        (problem,) = repeated_test_versions(tests, ["x/a.yaml", "y/b.yaml"])
        assert problem == "Exome 1.0.0 is in x/a.yaml and y/b.yaml"

    def test_two_names_differing_only_in_capitals(self):
        tests = [self._named("Exome"), self._named("EXOME", "WES")]

        (problem,) = differing_only_in_capitals(tests, ["a.yaml", "b.yaml"])
        assert problem == "EXOME in b.yaml and Exome in a.yaml differ only in capitals"


def _without(text, key):
    out, skipping = [], False
    for row in text.splitlines(keepends=True):
        if row.startswith(f"{key}:"):
            skipping = True
            continue
        if skipping and row.startswith((" ", "-")):
            continue
        skipping = False
        out.append(row)
    return "".join(out)


class TestMessagesKeepTheOldDetail:

    def test_a_name_with_a_hidden_character_says_so(self):
        error = _only(_app(APP.replace("FastqCompressionFormat: gzip", '"Fastq\\tFormat": gzip')))

        assert error.message == "holds a hidden character: U+0009 (tab)"

    def test_a_decimal_sheet_value_given_as_data_says_yaml_may_have_changed_it(self):
        from seqsetup.input_rules.profiles import check_application_profile_data

        data = yaml.safe_load(APP)
        data["Settings"]["FastqCompressionFormat"] = 4.1

        (error,) = check_application_profile_data(data, "app.yaml").problems
        assert error.path == ("Settings", "FastqCompressionFormat")
        assert error.message.startswith("is a number with a decimal point")


class TestTheRunCheckTakesAStoredWholeNumberVersion:
    """A profile stored before SoftwareVersion had to be text can hold 4.
    Beside "4.3.6" in another profile of the same application, the run check
    sorted the two and stopped with TypeError: '<' not supported between
    instances of 'str' and 'int' (sol's review of step 2's design, P2-1)."""

    def test_the_two_versions_are_reported_not_a_crash(self):
        from seqsetup.models.application_profile import ApplicationProfile
        from seqsetup.models.sample import Sample
        from seqsetup.models.sequencing_run import InstrumentPlatform, SequencingRun
        from seqsetup.models.test_profile import ApplicationProfileReference
        from seqsetup.services.application_profile_validator import ApplicationProfileValidator

        def stored_app(name, version):
            return ApplicationProfile(name=name, version="1.0.0", application_type="Dragen",
                                      application_name="DragenGermline",
                                      settings={"SoftwareVersion": version})

        def stored_test(test, app):
            return StoredTestProfile(test_type=test, test_name=test, version="1.0.0", application_profiles=[
                ApplicationProfileReference(profile_name=app, profile_version="1.0.0")])

        class Tests:
            profiles = [stored_test("A", "OldApp"), stored_test("B", "NewApp")]

            def list_by_test_name(self, test):
                return [p for p in self.profiles if p.test_name == test]

        class Apps:
            profiles = {"OldApp": stored_app("OldApp", 4), "NewApp": stored_app("NewApp", "4.3.6")}

            def get_by_name_version(self, name, version):
                return self.profiles.get(name)

        run = SequencingRun(instrument_platform=InstrumentPlatform.NOVASEQ_X, samples=[
            Sample(sample_id="S1", test_id="A", test_version="1.0.0"),
            Sample(sample_id="S2", test_id="B", test_version="1.0.0")])

        errors = ApplicationProfileValidator.validate_application_profiles(run, Tests(), Apps())

        mixed = [e for e in errors if "4 (from OldApp)" in e.detail and "4.3.6 (from NewApp)" in e.detail]
        assert len(mixed) == 1
