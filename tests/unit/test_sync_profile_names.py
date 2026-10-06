"""The sync refuses a profile file whose names would not reach the Sample
Sheet as checked (spec 2026-10-05 group A3, §1): a column written twice, a
BCLConvert setting also written as a column, and another spelling of a name
SeqSetup fills or reads itself. Names are compared ignoring case."""

from pathlib import Path

import pytest
import yaml

from seqsetup.services.profile_validator import (
    ProfileValidationError,
    validate_application_profile_yaml,
)

SHIPPED = sorted((Path(__file__).resolve().parents[2] / "config" / "profiles"
                  / "application_profiles").rglob("*.yaml"))
FIELDS = ["Sample_ID", "Lane", "Index", "Index2", "OverrideCycles",
          "BarcodeMismatchesIndex1", "BarcodeMismatchesIndex2"]


def _profile(app="BCLConvert", settings=None, data=None, fields=None, translate=None) -> dict:
    return {
        "ApplicationProfileName": "P", "ApplicationProfileVersion": "1.0.0",
        "ApplicationName": app, "ApplicationType": "Dragen",
        "Settings": {"SoftwareVersion": "4.3.6"} if settings is None else settings,
        "Data": {"BarcodeMismatchesIndex1": 1, "BarcodeMismatchesIndex2": 1}
        if data is None else data,
        "DataFields": list(FIELDS) if fields is None else fields,
        "Translate": translate or {},
    }


def _errors(profile: dict) -> list[str]:
    with pytest.raises(ProfileValidationError) as exc:
        validate_application_profile_yaml(profile, "P.yaml")
    return exc.value.errors


class TestARepeatedColumn:
    def test_a_translate_typo(self):
        profile = _profile(fields=["Sample_ID", "IndexI7", "IndexI5"],
                           translate={"IndexI7": "Index", "IndexI5": "Index"}, data={})
        assert _errors(profile) == [
            "The data section writes the column 'Index' more than once: from IndexI7, IndexI5. "
            "Each column may appear once (check DataFields and Translate)."]

    def test_the_same_column_in_another_case(self):
        profile = _profile("DragenGermline", fields=["Sample_ID", "Bed", "bed"], data={})
        assert _errors(profile) == [
            "The data section writes the column 'Bed' more than once: from Bed, bed. Each "
            "column may appear once (check DataFields and Translate)."]


class TestASettingInTwoPlaces:
    @pytest.mark.parametrize("key", ["BarcodeMismatchesIndex1", "AdapterRead1"])
    def test_a_bclconvert_setting_that_is_also_a_column(self, key):
        fields = FIELDS + ["AdapterRead1"]
        profile = _profile(settings={"SoftwareVersion": "4.3.6", key: 1}, fields=fields)
        assert _errors(profile) == [
            f"'{key}' is both in Settings and a data column. BCL Convert allows a setting in "
            f"one place only."]

    def test_in_another_case(self):
        profile = _profile(settings={"SoftwareVersion": "4.3.6", "OverrideCYCLES": "x"})
        errors = _errors(profile)
        assert ("'OverrideCYCLES' is both in Settings and a data column. BCL Convert allows "
                "a setting in one place only.") in errors

    def test_another_application_may(self):
        validate_application_profile_yaml(
            _profile("DragenGermline", settings={"SoftwareVersion": "4.3.6", "Bed": "x"},
                     fields=["Sample_ID", "Bed"], data={}))


class TestAnotherSpelling:
    @pytest.mark.parametrize("profile,written,canonical", [
        (_profile(fields=["Sample_ID", "Lane", "index", "index2"], data={}), "index", "Index"),
        (_profile(fields=["Sample_ID", "Index", "Index2", "Mm1"], data={"Mm1": 1},
                  translate={"Mm1": "barcodemismatchesindex1"}),
         "barcodemismatchesindex1", "BarcodeMismatchesIndex1"),
        (_profile(settings={"SoftwareVersion": "4.3.6", "barcodeMismatchesIndex1": 2},
                  fields=FIELDS[:5], data={}),
         "barcodeMismatchesIndex1", "BarcodeMismatchesIndex1"),
        (_profile(settings={"SoftwareVersion": "4.3.6", "nolanesplitting": "true"}),
         "nolanesplitting", "NoLaneSplitting"),
        (_profile(settings={"softwareversion": "999.0"}), "softwareversion", "SoftwareVersion"),
        (_profile("DragenGermline", settings={"softwareversion": "999.0"},
                  fields=["Sample_ID"], data={}), "softwareversion", "SoftwareVersion"),
    ])
    def test_it_is_refused(self, profile, written, canonical):
        assert (f"'{written}' must be spelled {canonical}: SeqSetup fills and reads "
                f"{canonical} itself, in that spelling only.") in _errors(profile)

    def test_a_dragen_profile_may_have_an_index_column_in_any_case(self):
        validate_application_profile_yaml(
            _profile("DragenGermline", fields=["Sample_ID", "index"], data={}))


@pytest.mark.parametrize("path", SHIPPED, ids=lambda p: p.name)
def test_every_shipped_profile_passes(path):
    validate_application_profile_yaml(yaml.safe_load(path.read_text()), path.name)
