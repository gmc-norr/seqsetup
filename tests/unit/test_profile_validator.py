"""Tests for profile YAML validators."""

from pathlib import Path

import pytest
import yaml

from seqsetup.services.profile_validator import (
    ProfileValidationError,
    validate_application_profile_yaml,
    validate_test_profile_yaml,
)


# --- TestProfile validation ---


class TestValidateTestProfile:
    """Tests for validate_test_profile_yaml."""

    VALID_TEST_PROFILE = {
        "TestType": "WGS",
        "TestName": "WGS",
        "Description": "Whole Genome Sequencing",
        "Version": "1.0.0",
        "ApplicationProfiles": [
            {
                "ApplicationProfileName": "BCLConvert",
                "ApplicationProfileVersion": "~=1.0.0",
            },
        ],
    }

    def test_valid_profile_passes(self):
        validate_test_profile_yaml(self.VALID_TEST_PROFILE)

    def test_missing_test_type(self):
        data = {**self.VALID_TEST_PROFILE}
        del data["TestType"]
        with pytest.raises(ProfileValidationError, match="Missing required field 'TestType'"):
            validate_test_profile_yaml(data)

    def test_missing_test_name(self):
        data = {**self.VALID_TEST_PROFILE}
        del data["TestName"]
        with pytest.raises(ProfileValidationError, match="Missing required field 'TestName'"):
            validate_test_profile_yaml(data)

    def test_missing_description(self):
        data = {**self.VALID_TEST_PROFILE}
        del data["Description"]
        with pytest.raises(ProfileValidationError, match="Missing required field 'Description'"):
            validate_test_profile_yaml(data)

    def test_missing_version(self):
        data = {**self.VALID_TEST_PROFILE}
        del data["Version"]
        with pytest.raises(ProfileValidationError, match="Missing required field 'Version'"):
            validate_test_profile_yaml(data)

    def test_empty_test_type(self):
        data = {**self.VALID_TEST_PROFILE, "TestType": ""}
        with pytest.raises(ProfileValidationError, match="'TestType' must not be empty"):
            validate_test_profile_yaml(data)

    def test_invalid_version(self):
        data = {**self.VALID_TEST_PROFILE, "Version": "not-a-version"}
        with pytest.raises(ProfileValidationError, match="not a valid PEP 440 version"):
            validate_test_profile_yaml(data)

    def test_missing_application_profiles(self):
        data = {**self.VALID_TEST_PROFILE}
        del data["ApplicationProfiles"]
        with pytest.raises(ProfileValidationError, match="Missing required field 'ApplicationProfiles'"):
            validate_test_profile_yaml(data)

    def test_application_profiles_not_list(self):
        data = {**self.VALID_TEST_PROFILE, "ApplicationProfiles": "not-a-list"}
        with pytest.raises(ProfileValidationError, match="must be a list"):
            validate_test_profile_yaml(data)

    def test_application_profiles_empty_list(self):
        data = {**self.VALID_TEST_PROFILE, "ApplicationProfiles": []}
        with pytest.raises(ProfileValidationError, match="must contain at least one entry"):
            validate_test_profile_yaml(data)

    def test_application_profile_missing_name(self):
        data = {
            **self.VALID_TEST_PROFILE,
            "ApplicationProfiles": [
                {"ApplicationProfileVersion": "~=1.0.0"},
            ],
        }
        with pytest.raises(ProfileValidationError, match="missing 'ApplicationProfileName'"):
            validate_test_profile_yaml(data)

    def test_application_profile_missing_version(self):
        data = {
            **self.VALID_TEST_PROFILE,
            "ApplicationProfiles": [
                {"ApplicationProfileName": "BCLConvert"},
            ],
        }
        with pytest.raises(ProfileValidationError, match="missing 'ApplicationProfileVersion'"):
            validate_test_profile_yaml(data)

    def test_application_profile_invalid_version_constraint(self):
        data = {
            **self.VALID_TEST_PROFILE,
            "ApplicationProfiles": [
                {
                    "ApplicationProfileName": "BCLConvert",
                    "ApplicationProfileVersion": "not-valid",
                },
            ],
        }
        with pytest.raises(ProfileValidationError, match="not a valid PEP 440"):
            validate_test_profile_yaml(data)

    def test_application_profile_valid_specifier(self):
        """Version constraints like ~=1.0.0 should be accepted."""
        data = {
            **self.VALID_TEST_PROFILE,
            "ApplicationProfiles": [
                {
                    "ApplicationProfileName": "BCLConvert",
                    "ApplicationProfileVersion": "~=1.0.0",
                },
            ],
        }
        validate_test_profile_yaml(data)

    def test_application_profile_valid_range(self):
        """Range specifiers like >=1.0,<2.0 should be accepted."""
        data = {
            **self.VALID_TEST_PROFILE,
            "ApplicationProfiles": [
                {
                    "ApplicationProfileName": "BCLConvert",
                    "ApplicationProfileVersion": ">=1.0,<2.0",
                },
            ],
        }
        validate_test_profile_yaml(data)

    def test_application_profile_exact_version_accepted(self):
        """Exact versions like 1.0.0 should be accepted as constraints."""
        data = {
            **self.VALID_TEST_PROFILE,
            "ApplicationProfiles": [
                {
                    "ApplicationProfileName": "BCLConvert",
                    "ApplicationProfileVersion": "1.0.0",
                },
            ],
        }
        validate_test_profile_yaml(data)

    def test_multiple_errors_collected(self):
        """All errors should be reported, not just the first."""
        data = {}
        with pytest.raises(ProfileValidationError) as exc_info:
            validate_test_profile_yaml(data)
        assert len(exc_info.value.errors) >= 5  # 4 missing fields + missing ApplicationProfiles

    def test_source_file_in_error(self):
        with pytest.raises(ProfileValidationError) as exc_info:
            validate_test_profile_yaml({}, source_file="Wgs.yaml")
        assert exc_info.value.source_file == "Wgs.yaml"
        assert "Wgs.yaml" in str(exc_info.value)


# --- ApplicationProfile validation ---


class TestValidateApplicationProfile:
    """Tests for validate_application_profile_yaml."""

    VALID_DRAGEN_PROFILE = {
        "ApplicationProfileName": "DragenGermline",
        "ApplicationProfileVersion": "1.0.0",
        "ApplicationName": "DragenGermline",
        "ApplicationType": "Dragen",
        "Settings": {"SoftwareVersion": "4.1.23"},
        "Data": {"ReferenceGenomeDir": "hg38"},
        "DataFields": ["Sample_ID", "ReferenceGenomeDir"],
    }

    VALID_NON_DRAGEN_PROFILE = {
        "ApplicationProfileName": "CustomApp",
        "ApplicationProfileVersion": "1.0.0",
        "ApplicationName": "CustomApp",
        "ApplicationType": "Custom",
    }

    def test_valid_dragen_profile_passes(self):
        validate_application_profile_yaml(self.VALID_DRAGEN_PROFILE)

    def test_valid_non_dragen_profile_passes(self):
        validate_application_profile_yaml(self.VALID_NON_DRAGEN_PROFILE)

    def test_missing_name(self):
        data = {**self.VALID_DRAGEN_PROFILE}
        del data["ApplicationProfileName"]
        with pytest.raises(ProfileValidationError, match="Missing required field 'ApplicationProfileName'"):
            validate_application_profile_yaml(data)

    def test_missing_version(self):
        data = {**self.VALID_DRAGEN_PROFILE}
        del data["ApplicationProfileVersion"]
        with pytest.raises(ProfileValidationError, match="Missing required field 'ApplicationProfileVersion'"):
            validate_application_profile_yaml(data)

    def test_missing_application_name(self):
        data = {**self.VALID_DRAGEN_PROFILE}
        del data["ApplicationName"]
        with pytest.raises(ProfileValidationError, match="Missing required field 'ApplicationName'"):
            validate_application_profile_yaml(data)

    def test_missing_application_type(self):
        data = {**self.VALID_DRAGEN_PROFILE}
        del data["ApplicationType"]
        with pytest.raises(ProfileValidationError, match="Missing required field 'ApplicationType'"):
            validate_application_profile_yaml(data)

    def test_empty_name(self):
        data = {**self.VALID_DRAGEN_PROFILE, "ApplicationProfileName": ""}
        with pytest.raises(ProfileValidationError, match="'ApplicationProfileName' must not be empty"):
            validate_application_profile_yaml(data)

    def test_invalid_version(self):
        data = {**self.VALID_DRAGEN_PROFILE, "ApplicationProfileVersion": "not-valid"}
        with pytest.raises(ProfileValidationError, match="not a valid PEP 440 version"):
            validate_application_profile_yaml(data)

    def test_dragen_missing_settings(self):
        data = {**self.VALID_DRAGEN_PROFILE}
        del data["Settings"]
        with pytest.raises(ProfileValidationError, match="Missing required field 'Settings'"):
            validate_application_profile_yaml(data)

    def test_dragen_missing_data(self):
        data = {**self.VALID_DRAGEN_PROFILE}
        del data["Data"]
        with pytest.raises(ProfileValidationError, match="Missing required field 'Data'"):
            validate_application_profile_yaml(data)

    def test_dragen_missing_data_fields(self):
        data = {**self.VALID_DRAGEN_PROFILE}
        del data["DataFields"]
        with pytest.raises(ProfileValidationError, match="Missing required field 'DataFields'"):
            validate_application_profile_yaml(data)

    def test_dragen_settings_not_dict(self):
        data = {**self.VALID_DRAGEN_PROFILE, "Settings": "not-a-dict"}
        with pytest.raises(ProfileValidationError, match="'Settings' must be a mapping"):
            validate_application_profile_yaml(data)

    def test_dragen_data_not_dict(self):
        data = {**self.VALID_DRAGEN_PROFILE, "Data": "not-a-dict"}
        with pytest.raises(ProfileValidationError, match="'Data' must be a mapping"):
            validate_application_profile_yaml(data)

    def test_dragen_data_fields_not_list(self):
        data = {**self.VALID_DRAGEN_PROFILE, "DataFields": "not-a-list"}
        with pytest.raises(ProfileValidationError, match="'DataFields' must be a list"):
            validate_application_profile_yaml(data)

    def test_non_dragen_no_settings_required(self):
        """Non-Dragen profiles should not require Settings/Data/DataFields."""
        validate_application_profile_yaml(self.VALID_NON_DRAGEN_PROFILE)

    def test_dragen_case_insensitive(self):
        """ApplicationType matching should be case-insensitive."""
        data = {**self.VALID_NON_DRAGEN_PROFILE, "ApplicationType": "dragen"}
        with pytest.raises(ProfileValidationError, match="Missing required field 'Settings'"):
            validate_application_profile_yaml(data)

    def test_multiple_errors_collected(self):
        data = {}
        with pytest.raises(ProfileValidationError) as exc_info:
            validate_application_profile_yaml(data)
        assert len(exc_info.value.errors) >= 4

    def test_source_file_in_error(self):
        with pytest.raises(ProfileValidationError) as exc_info:
            validate_application_profile_yaml({}, source_file="DragenGermline.yaml")
        assert exc_info.value.source_file == "DragenGermline.yaml"


# --- Integration with from_yaml ---


class TestFromYamlValidation:
    """Test that from_yaml methods call validators."""

    def test_test_profile_from_yaml_validates(self):
        from seqsetup.models.test_profile import TestProfile

        with pytest.raises(ProfileValidationError):
            TestProfile.from_yaml({})

    def test_application_profile_from_yaml_validates(self):
        from seqsetup.models.application_profile import ApplicationProfile

        with pytest.raises(ProfileValidationError):
            ApplicationProfile.from_yaml({})

    def test_test_profile_from_yaml_valid(self):
        from seqsetup.models.test_profile import TestProfile

        data = {
            "TestType": "WGS",
            "TestName": "WGS",
            "Description": "Whole Genome Sequencing",
            "Version": "1.0.0",
            "ApplicationProfiles": [
                {
                    "ApplicationProfileName": "BCLConvert",
                    "ApplicationProfileVersion": "~=1.0.0",
                },
            ],
        }
        tp = TestProfile.from_yaml(data, "Wgs.yaml")
        assert tp.test_type == "WGS"
        assert tp.test_name == "WGS"
        assert len(tp.application_profiles) == 1

    def test_application_profile_from_yaml_valid(self):
        from seqsetup.models.application_profile import ApplicationProfile

        data = {
            "ApplicationProfileName": "DragenGermline",
            "ApplicationProfileVersion": "1.0.0",
            "ApplicationName": "DragenGermline",
            "ApplicationType": "Dragen",
            "Settings": {"SoftwareVersion": "4.1.23"},
            "Data": {"ReferenceGenomeDir": "hg38"},
            "DataFields": ["Sample_ID"],
        }
        ap = ApplicationProfile.from_yaml(data, "DragenGermline.yaml")
        assert ap.name == "DragenGermline"
        assert ap.version == "1.0.0"


class TestApplicationNameCharacters:
    """ApplicationName becomes a Sample Sheet section name, written as is, so
    only letters, digits, '_' and '-' are allowed (audit 2026-09 N-10)."""

    BASE = {
        "ApplicationProfileName": "P",
        "ApplicationProfileVersion": "1.0.0",
        "ApplicationName": "BCLConvert",
        "ApplicationType": "Custom",
    }

    @pytest.mark.parametrize("name", [
        "BCLConvert]\n[BCLConvert_Data]", "a,b", "Dragen Germline", "App]", "App\x00", "Äpp",
    ])
    def test_non_plain_application_name_is_refused(self, name):
        with pytest.raises(ProfileValidationError, match="ApplicationName' may only contain"):
            validate_application_profile_yaml({**self.BASE, "ApplicationName": name})

    @pytest.mark.parametrize("name", ["BCLConvert", "DragenGermline", "Custom_App-2"])
    def test_plain_application_name_is_accepted(self, name):
        validate_application_profile_yaml({**self.BASE, "ApplicationName": name})


class TestProfileValuesHiddenCharacters:
    """Settings, Data, DataFields and Translate are written into the Sample
    Sheet as cells. A quoted line break still starts a new line for a
    line-oriented reader, so no hidden character is allowed in them."""

    BASE = {
        "ApplicationProfileName": "P",
        "ApplicationProfileVersion": "1.0.0",
        "ApplicationName": "BCLConvert",
        "ApplicationType": "Custom",
        "Settings": {"SoftwareVersion": "4.3.6"},
        "Data": {"Extra": "x"},
        "DataFields": ["Sample_ID", "Index", "Extra"],
        "Translate": {"IndexI7": "Index"},
    }

    @pytest.mark.parametrize("char", [
        pytest.param("\n", id="LF"),
        pytest.param("\r", id="CR"),
        pytest.param("\t", id="TAB"),
        pytest.param("\x00", id="NUL"),
        pytest.param("\u2028", id="LINE-SEPARATOR"),
    ])
    @pytest.mark.parametrize("field,make", [
        pytest.param("Settings", lambda c: {"SoftwareVersion": f"4.3.6{c}[Junk]"}, id="settings-value"),
        pytest.param("Settings", lambda c: {f"Soft{c}ware": "4.3.6"}, id="settings-key"),
        pytest.param("Data", lambda c: {"Extra": f"x{c}y"}, id="data-value"),
        pytest.param("Data", lambda c: {"Extra": {"nested": [f"x{c}y"]}}, id="data-nested"),
        pytest.param("DataFields", lambda c: ["Sample_ID", f"Ex{c}tra"], id="datafields"),
        pytest.param("Translate", lambda c: {"IndexI7": f"Ind{c}ex"}, id="translate-value"),
        pytest.param("Translate", lambda c: {f"Index{c}I7": "Index"}, id="translate-key"),
    ])
    def test_hidden_character_in_profile_values_is_refused(self, field, make, char):
        with pytest.raises(ProfileValidationError, match=f"Field '{field}' has a hidden character"):
            validate_application_profile_yaml({**self.BASE, field: make(char)})

    def test_dragen_profile_is_checked_too(self):
        data = {
            **self.BASE,
            "ApplicationType": "Dragen",
            "Settings": {"SoftwareVersion": "4.3.6\n[BCLConvert_Data]"},
        }
        with pytest.raises(ProfileValidationError, match="U\\+000A"):
            validate_application_profile_yaml(data)

    def test_plain_values_are_accepted(self):
        validate_application_profile_yaml(self.BASE)

    def test_numbers_booleans_and_empty_values_are_accepted(self):
        validate_application_profile_yaml({
            **self.BASE,
            "Settings": {"Threads": 8, "Trim": True, "Empty": None},
            "Data": {"Extra": 1.5},
        })


class TestProfileNames:
    """Every name in Settings, Data, DataFields and Translate becomes a line
    start or a column name in the Sample Sheet. Quoting cannot stop a name
    like '[BCLConvert_Data]' from starting a new section, so only letters,
    digits, '_' and '-' are allowed (found by the second review)."""

    BASE = TestProfileValuesHiddenCharacters.BASE

    @pytest.mark.parametrize("field,value", [
        pytest.param("Settings", {"[BCLConvert_Data]": "x"}, id="settings-section-name"),
        pytest.param("Settings", {"Soft ware": "4.3.6"}, id="settings-space"),
        pytest.param("Settings", {"a,b": "x"}, id="settings-comma"),
        pytest.param("Settings", {7: "x"}, id="settings-number"),
        pytest.param("Data", {"[Junk]": "x"}, id="data-key"),
        pytest.param("DataFields", ["Sample_ID", "Ex tra"], id="datafields-space"),
        pytest.param("DataFields", ["Sample_ID", 5], id="datafields-number"),
        pytest.param("DataFields", ["Sample_ID", {"a": "b"}], id="datafields-mapping"),
        pytest.param("Translate", {"IndexI7": "[Junk]"}, id="translate-value"),
        pytest.param("Translate", {"Index I7": "Index"}, id="translate-key"),
    ])
    def test_non_plain_name_is_refused(self, field, value):
        with pytest.raises(ProfileValidationError, match=f"Field '{field}' has a name that may only contain"):
            validate_application_profile_yaml({**self.BASE, field: value})

    def test_name_with_hidden_character_is_reported_once(self):
        with pytest.raises(ProfileValidationError) as exc:
            validate_application_profile_yaml({**self.BASE, "Settings": {"Soft\nware": "4.3.6"}})
        assert len(exc.value.errors) == 1
        assert "hidden character" in exc.value.errors[0]

    def test_number_application_name_is_refused(self):
        with pytest.raises(ProfileValidationError, match="ApplicationName' may only contain"):
            validate_application_profile_yaml({**self.BASE, "ApplicationName": 123})

    def test_plain_names_are_accepted(self):
        validate_application_profile_yaml({
            **self.BASE,
            "Settings": {"SoftwareVersion": "4.3.6", "Adapter_Read-1": "x"},
            "Translate": {"IndexI7": "Index", "IndexI5": "Index2"},
        })


class TestProfileValuesStartingABracket:
    """A value is written as a cell. First on its line (a data default in the
    first column), a value starting with '[' would start a new section."""

    BASE = TestProfileValuesHiddenCharacters.BASE

    @pytest.mark.parametrize("field,value", [
        pytest.param("Settings", {"SoftwareVersion": "[Junk]"}, id="settings-value"),
        pytest.param("Data", {"Extra": "[BCLConvert_Settings]"}, id="data-value"),
        pytest.param("Data", {"Extra": " [Junk]"}, id="data-value-space"),
        pytest.param("Data", {"Extra": ["a"]}, id="data-list-value"),
    ])
    def test_value_starting_a_section_is_refused(self, field, value):
        with pytest.raises(ProfileValidationError, match=f"Field '{field}' value .* cannot start with"):
            validate_application_profile_yaml({**self.BASE, field: value})

    def test_bracket_inside_a_value_is_accepted(self):
        validate_application_profile_yaml({**self.BASE, "Data": {"Extra": "a[b]"}})


class TestProfileSectionShapes:
    """The Sample Sheet writer reads Settings, Data and Translate as mappings
    and DataFields as a list, for every ApplicationType. Another shape was
    skipped by the checks above, so it is refused (found by the second
    review)."""

    BASE = TestValidateApplicationProfile.VALID_NON_DRAGEN_PROFILE

    @pytest.mark.parametrize("field,value,kind", [
        pytest.param("Settings", "SoftwareVersion,4.3.6", "a mapping", id="settings"),
        pytest.param("Data", ["Extra"], "a mapping", id="data"),
        pytest.param("DataFields", "Sample_ID", "a list", id="datafields"),
        pytest.param("Translate", ["Index"], "a mapping", id="translate"),
    ])
    def test_wrong_shape_is_refused(self, field, value, kind):
        with pytest.raises(ProfileValidationError, match=f"'{field}' must be {kind}"):
            validate_application_profile_yaml({**self.BASE, field: value})

    def test_empty_translate_is_accepted(self):
        """A YAML 'Translate:' key with no entries loads as None."""
        validate_application_profile_yaml({**self.BASE, "Translate": None})

    def test_dragen_wrong_shape_is_reported_once(self):
        data = {**TestValidateApplicationProfile.VALID_DRAGEN_PROFILE, "Settings": "x"}
        with pytest.raises(ProfileValidationError) as exc:
            validate_application_profile_yaml(data)
        assert exc.value.errors == ["Field 'Settings' must be a mapping"]

    def test_dragen_empty_settings_is_still_refused(self):
        data = {**TestValidateApplicationProfile.VALID_DRAGEN_PROFILE, "Settings": None}
        with pytest.raises(ProfileValidationError, match="'Settings' must be a mapping"):
            validate_application_profile_yaml(data)


_SHIPPED_PROFILES = sorted(
    (Path(__file__).parents[2] / "config" / "profiles" / "application_profiles").rglob("*.yaml")
)


@pytest.mark.parametrize("path", _SHIPPED_PROFILES, ids=lambda p: p.name)
def test_shipped_application_profiles_pass(path):
    """The profiles in config/ follow every rule above."""
    validate_application_profile_yaml(yaml.safe_load(path.read_text()), path.name)


def test_shipped_application_profiles_are_found():
    assert len(_SHIPPED_PROFILES) >= 6
