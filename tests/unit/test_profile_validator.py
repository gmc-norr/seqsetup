"""Tests for profile YAML validators."""

from pathlib import Path

import pytest
import yaml

from seqsetup.models.application_profile import ApplicationProfile
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
        "DataFields": ["Sample_ID"],
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
        "DataFields": ["Sample_ID"],
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

    def test_numbers_and_booleans_are_accepted(self):
        validate_application_profile_yaml({
            **self.BASE,
            "Settings": {"Threads": 8, "Trim": True, "Empty": ""},
            "Data": {"Extra": 2},
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


# --- Sample Sheet follow-ups (spec 2026-09-29) ---

APP = {
    "ApplicationProfileName": "P",
    "ApplicationProfileVersion": "1.0.0",
    "ApplicationName": "BCLConvert",
    "ApplicationType": "Custom",
    "Settings": {"SoftwareVersion": "4.3.6"},
    "Data": {"Sample_ID": ""},
}
TEST = TestValidateTestProfile.VALID_TEST_PROFILE
DECIMAL_VALUE = (
    "is a number with a decimal point, which YAML may have changed (4.10 is read "
    'as 4.1). Put the value in quotes, for example "4.10".'
)
DECIMAL_VERSION = (
    "is a number with a decimal point, which YAML may have changed (1.10 is read "
    'as 1.1). Put the version in quotes, for example "1.10".'
)


def _errors(data: dict) -> list[str]:
    """The application-profile check's messages; [] when it passes."""
    try:
        validate_application_profile_yaml(data)
    except ProfileValidationError as e:
        return e.errors
    return []


def _test_profile_errors(data: dict) -> list[str]:
    """The test-profile check's messages; [] when it passes."""
    try:
        validate_test_profile_yaml(data)
    except ProfileValidationError as e:
        return e.errors
    return []


def _with(field: str, **entries) -> dict:
    """APP with more entries in its Settings or Data."""
    return {**APP, field: {**APP[field], **entries}}


class TestProfileValueKinds:
    """A Settings or Data value is written into the Sample Sheet with str().
    YAML has already changed a decimal number (4.10 is read as 4.1), an empty
    value is None, and a mapping, a list, a date, bytes or a set would be
    written in Python's own form, so these are refused. Only text, whole
    numbers and true/false pass, as today (spec 2026-09-29 Sample Sheet
    follow-ups, §1)."""

    @pytest.mark.parametrize("field", ["Settings", "Data"])
    @pytest.mark.parametrize("value", [
        pytest.param(4.1, id="4.10"),
        pytest.param(1.0, id="1.0"),
        pytest.param(float("inf"), id="inf"),
        pytest.param(float("nan"), id="nan"),
    ])
    def test_decimal_number_is_refused(self, field, value):
        assert _errors(_with(field, Extra=value)) == [
            f"Field '{field}' value for 'Extra' {DECIMAL_VALUE}"
        ]

    @pytest.mark.parametrize("field", ["Settings", "Data"])
    @pytest.mark.parametrize("value,kind", [
        pytest.param({"SoftwareVersion": "4.10"}, "mapping", id="mapping"),
        pytest.param(["a", "b"], "list", id="list"),
    ])
    def test_mapping_or_list_is_refused(self, field, value, kind):
        assert (
            f"Field '{field}' value for 'Extra' is a {kind}; a value must be text, "
            "a whole number or true/false."
        ) in _errors(_with(field, Extra=value))

    def test_a_mapping_holding_a_decimal_is_refused_as_a_mapping(self):
        # Astra review P6: it was written as "{'SoftwareVersion': 4.1, 'Unset': None}".
        assert _errors(_with("Data", Options={"SoftwareVersion": 4.1, "Unset": None})) == [
            "Field 'Data' value for 'Options' is a mapping; a value must be text, "
            "a whole number or true/false."
        ]

    @pytest.mark.parametrize("field", ["Settings", "Data"])
    def test_empty_value_is_refused(self, field):
        assert _errors(_with(field, Extra=None)) == [
            f"Field '{field}' value for 'Extra' is empty. Write '' if it should be empty."
        ]

    @pytest.mark.parametrize("field", ["Settings", "Data"])
    @pytest.mark.parametrize("text,kind", [
        pytest.param("2024-01-01", "date", id="date"),
        pytest.param("2024-01-01T10:00:00Z", "datetime", id="timestamp"),
        pytest.param("!!binary NC4xMA==", "bytes", id="binary"),
        pytest.param("!!set {a: null}", "set", id="set"),
    ])
    def test_any_other_kind_is_refused(self, field, text, kind):
        # Astra plan review P1: these passed, and !!binary NC4xMA== was
        # written as b'4.10'.
        value = yaml.safe_load(f"v: {text}")["v"]
        assert _errors(_with(field, Extra=value)) == [
            f"Field '{field}' value for 'Extra' is not text, a whole number or true/false: "
            f"YAML read it as {kind} ({value!r}). Put the value in quotes."
        ]

    @pytest.mark.parametrize("value", [
        pytest.param("4.10", id="quoted-4.10"),
        pytest.param("", id="empty-text"),
        pytest.param(8, id="8"),
        pytest.param(0, id="0"),
        pytest.param(True, id="true"),
        pytest.param(False, id="false"),
    ])
    def test_text_whole_numbers_and_true_false_pass(self, value):
        data = {
            **APP,
            "Settings": {**APP["Settings"], "Extra": value},
            "Data": {**APP["Data"], "Extra": value},
        }
        assert _errors(data) == []


class TestProfileVersions:
    """A version YAML read as a decimal number may have changed (1.10 is read
    as 1.1), so two versions could collide; it must be quoted (spec
    2026-09-29 Sample Sheet follow-ups, §1)."""

    def test_application_profile_version_is_refused(self):
        assert _errors({**APP, "ApplicationProfileVersion": 1.1}) == [
            f"Field 'ApplicationProfileVersion' {DECIMAL_VERSION}"
        ]

    def test_test_profile_version_is_refused(self):
        assert _test_profile_errors({**TEST, "Version": 1.1}) == [
            f"Field 'Version' {DECIMAL_VERSION}"
        ]

    def test_reference_version_is_refused(self):
        refs = [{"ApplicationProfileName": "P", "ApplicationProfileVersion": 1.1}]
        assert _test_profile_errors({**TEST, "ApplicationProfiles": refs}) == [
            f"Field 'ApplicationProfiles[0].ApplicationProfileVersion' {DECIMAL_VERSION}"
        ]

    def test_unquoted_1_10_and_1_1_can_no_longer_collide(self):
        # Astra review P1: both were stored as the version "1.1".
        first = yaml.safe_load("v: 1.10")["v"]
        second = yaml.safe_load("v: 1.1")["v"]
        assert first == second == 1.1
        assert _errors({**APP, "ApplicationProfileVersion": first})
        assert _errors({**APP, "ApplicationProfileVersion": second})

    @pytest.mark.parametrize("version", [
        pytest.param("1.10", id="quoted"),
        pytest.param("1.0.0", id="three-part"),
        pytest.param(2, id="whole-number"),
    ])
    def test_quoted_and_whole_versions_pass(self, version):
        assert _errors({**APP, "ApplicationProfileVersion": version}) == []
        assert _test_profile_errors({**TEST, "Version": version}) == []


class TestEmptyRequiredFields:
    """A required field left empty is None to YAML, and passed as the text
    "None" (spec 2026-09-29 Sample Sheet follow-ups, §1)."""

    @pytest.mark.parametrize("field", [
        "ApplicationProfileName", "ApplicationProfileVersion", "ApplicationName", "ApplicationType",
    ])
    def test_application_profile_field(self, field):
        assert f"Field '{field}' must not be empty" in _errors({**APP, field: None})

    @pytest.mark.parametrize("field", ["TestType", "TestName", "Description", "Version"])
    def test_test_profile_field(self, field):
        assert f"Field '{field}' must not be empty" in _test_profile_errors({**TEST, field: None})

    @pytest.mark.parametrize("key", ["ApplicationProfileName", "ApplicationProfileVersion"])
    def test_reference_field(self, key):
        ref = {"ApplicationProfileName": "P", "ApplicationProfileVersion": "~=1.0.0", key: None}
        assert (
            f"ApplicationProfiles[0]: '{key}' must not be empty"
            in _test_profile_errors({**TEST, "ApplicationProfiles": [ref]})
        )


class TestMismatchValues:
    """BCL Convert allows at most 2 mismatches. A Settings entry takes 0, 1 or
    2; a Data default may also be blank or na: Illumina's DRAGEN sample sheet
    guide says a per-sample setting that does not apply "must be blank or na"
    (spec 2026-09-29 Sample Sheet follow-ups, §1)."""

    @staticmethod
    def _settings_error(key, column, value):
        return (
            f"Field 'Settings' value for '{key}' fills {column} and must be 0, 1 or 2 "
            f"(BCL Convert allows at most 2 mismatches): {value!r}"
        )

    @staticmethod
    def _data_error(key, column, value):
        return (
            f"Field 'Data' value for '{key}' fills {column} and must be 0, 1, 2, blank or na "
            f"(BCL Convert allows at most 2 mismatches): {value!r}"
        )

    @pytest.mark.parametrize("column", ["BarcodeMismatchesIndex1", "BarcodeMismatchesIndex2"])
    @pytest.mark.parametrize("value", [
        pytest.param(3, id="3"),
        pytest.param(-1, id="minus-1"),
        pytest.param("3", id="text-3"),
        pytest.param(True, id="true"),
        pytest.param("na", id="na"),
        pytest.param("", id="blank"),
    ])
    def test_settings_value_outside_0_to_2_is_refused(self, column, value):
        assert _errors(_with("Settings", **{column: value})) == [
            self._settings_error(column, column, value)
        ]

    @pytest.mark.parametrize("column", ["BarcodeMismatchesIndex1", "BarcodeMismatchesIndex2"])
    @pytest.mark.parametrize("value", [
        pytest.param(3, id="3"),
        pytest.param("3", id="text-3"),
        pytest.param(True, id="true"),
        pytest.param("NA", id="upper-NA"),
        pytest.param(" 1", id="space-1"),
    ])
    def test_data_default_outside_the_allowed_values_is_refused(self, column, value):
        assert _errors(_with("Data", **{column: value})) == [
            self._data_error(column, column, value)
        ]

    def test_a_translated_data_column_is_checked(self):
        data = {**_with("Data", Mm1=3), "Translate": {"Mm1": "BarcodeMismatchesIndex1"}}
        assert _errors(data) == [self._data_error("Mm1", "BarcodeMismatchesIndex1", 3)]

    @pytest.mark.parametrize("value", [0, 1, 2, "0", "1", "2"])
    def test_settings_0_1_2_pass(self, value):
        assert _errors(_with("Settings", BarcodeMismatchesIndex1=value)) == []

    @pytest.mark.parametrize("value", [0, 2, "1", "", "na"])
    def test_data_0_1_2_blank_and_na_pass(self, value):
        assert _errors(_with("Data", BarcodeMismatchesIndex2=value)) == []


class TestSampleIdColumn:
    """Every data row names its sample in the Sample_ID column. The columns
    are found the way the sheet writer finds them: DataFields when it has
    entries, else the Data keys, each renamed by Translate (spec 2026-09-29
    Sample Sheet follow-ups, §1)."""

    MESSAGE = (
        "The data section has no Sample_ID column. Add Sample_ID to DataFields "
        "(or to Data when DataFields is missing or empty)."
    )
    BARE = {key: value for key, value in APP.items() if key != "Data"}

    @pytest.mark.parametrize("sections", [
        pytest.param({}, id="no-data-no-datafields"),
        pytest.param({"Data": {"Extra": "x"}}, id="data-without-sample-id"),
        pytest.param({"Data": {"Sample_ID": ""}, "DataFields": ["Extra"]}, id="datafields-without-sample-id"),
        pytest.param({"Data": {"Sample_ID": ""}, "Translate": {"Sample_ID": "Name"}}, id="renamed-by-translate"),
    ])
    def test_no_sample_id_column_is_refused(self, sections):
        assert _errors({**self.BARE, **sections}) == [self.MESSAGE]

    @pytest.mark.parametrize("sections", [
        pytest.param({"Data": {"Sample_ID": ""}}, id="data-keys"),
        pytest.param({"Data": {"Sample_ID": ""}, "DataFields": None}, id="datafields-empty"),
        pytest.param({"Data": {"Sample_ID": ""}, "DataFields": []}, id="datafields-empty-list"),
        pytest.param({"DataFields": ["Sample_ID"]}, id="datafields"),
        pytest.param({"DataFields": ["SampleID"], "Translate": {"SampleID": "Sample_ID"}}, id="reached-by-translate"),
    ])
    def test_sample_id_column_passes(self, sections):
        assert _errors({**self.BARE, **sections}) == []

    def test_dragen_empty_sections_are_still_refused(self):
        # Decision 7 of the spec: only a non-DRAGEN profile reads an empty
        # section as "none".
        data = {
            **TestValidateApplicationProfile.VALID_DRAGEN_PROFILE,
            "Settings": None, "Data": None, "DataFields": None,
        }
        errors = _errors(data)
        assert "Field 'Settings' must be a mapping" in errors
        assert "Field 'Data' must be a mapping" in errors
        assert "Field 'DataFields' must be a list" in errors


STORED = {
    "_id": "p1", "name": "P", "version": "1.0.0", "application_type": "Dragen",
    "application_name": "DragenGermline", "settings": {"A": "b"},
    "data": {"Sample_ID": ""}, "data_fields": ["Sample_ID"], "translate": {"X": "Y"},
}


class TestEmptySections:
    """An empty Settings:, Data: or Translate: means none ({}), and an empty
    DataFields: means none ([]): for a non-DRAGEN profile read from YAML, and
    for any profile read from the database. Mark Ready used to fail on
    None.items() (spec 2026-09-29 Sample Sheet follow-ups, §1)."""

    def test_from_yaml_reads_empty_sections_as_none(self):
        data = {**APP, "Settings": None, "DataFields": None, "Translate": None}
        profile = ApplicationProfile.from_yaml(data)
        assert (profile.settings, profile.data_fields, profile.translate) == ({}, [], {})

    def test_from_yaml_reads_an_empty_data_as_none(self):
        data = {**APP, "Data": None, "DataFields": ["Sample_ID"]}
        assert ApplicationProfile.from_yaml(data).data == {}

    def test_from_dict_reads_empty_sections_as_none(self):
        profile = ApplicationProfile.from_dict({
            **STORED, "settings": None, "data": None, "data_fields": None, "translate": None,
        })
        assert (profile.settings, profile.data, profile.data_fields, profile.translate) == (
            {}, {}, [], {}
        )

    def test_from_dict_keeps_what_is_there(self):
        profile = ApplicationProfile.from_dict(STORED)
        assert (profile.settings, profile.data, profile.data_fields, profile.translate) == (
            {"A": "b"}, {"Sample_ID": ""}, ["Sample_ID"], {"X": "Y"}
        )
