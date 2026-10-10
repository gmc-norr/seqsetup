"""A test profile's Version is three whole numbers, each at most 9 digits,
checked at sync (spec 2026-10-07 group A4, §1)."""

import pytest

from seqsetup.services.profile_validator import ProfileValidationError, validate_test_profile_yaml

RULE = "Field 'Version' must be three whole numbers joined by dots, each at most 9 digits, like 1.0.0"


def _test(version) -> dict:
    return {
        "TestType": "WGS", "TestName": "WGS", "Description": "Whole genome", "Version": version,
        "ApplicationProfiles": [
            {"ApplicationProfileName": "BCLConvertNextera", "ApplicationProfileVersion": "~=1.0.0"}],
    }


def _errors(version) -> list[str]:
    with pytest.raises(ProfileValidationError) as caught:
        validate_test_profile_yaml(_test(version), "Wgs.yaml")
    return caught.value.errors


class TestTheVersionRule:
    """Before this rule each of the refused values synced (measured on
    e65c60d); only three whole numbers pass now."""

    @pytest.mark.parametrize("version", ["1.0.0", "0.0.0", "10.20.30", "999999999.0.0"])
    def test_three_whole_numbers_pass(self, version):
        validate_test_profile_yaml(_test(version), "Wgs.yaml")

    @pytest.mark.parametrize("version", [
        "1.0", "1", "1.0.0rc1", "01.0.0", "1.0.0.0", "v1.0.0", 1, "1.0.0+local",
        "1234567890.0.0", " 1.0.0",
    ])
    def test_anything_else_is_refused(self, version):
        assert f"{RULE}: {str(version)!r}" in _errors(version)

    def test_a_long_version_is_shown_cut_to_40_characters(self):
        # The PEP 440 check raised a plain ValueError on 4,301 digits before
        # this change; now both messages come back, each cut.
        version = "9" * 4301 + ".0.0"
        errors = _errors(version)
        assert f"{RULE}: '{'9' * 40}…'" in errors
        assert f"Field 'Version' is not a valid PEP 440 version: '{'9' * 40}…'" in errors

    def test_a_decimal_number_gets_both_messages(self):
        errors = _errors(1.0)
        assert f"{RULE}: '1.0'" in errors
        assert any("number with a decimal point" in e for e in errors)
