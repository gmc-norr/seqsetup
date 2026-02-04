"""Tests for profile YAML validators."""

import pytest

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
