"""A test profile's Version is three whole numbers, each at most 9 digits,
checked at sync (spec 2026-10-07 group A4, §1)."""

import pytest

from seqsetup.input_rules.profiles import ProfileValidationError


def check_test_profile(data, source_file=""):
    """The input rules for a test profile, through its one builder."""
    from seqsetup.models.test_profile import TestProfile as Built

    Built.from_yaml(data, source_file)

RULE = "Version: must be three whole numbers joined by dots, each at most 9 digits, like 1.0.0"


def _test(version) -> dict:
    return {
        "TestType": "WGS", "TestName": "WGS", "Description": "Whole genome", "Version": version,
        "TestApplicationProfiles": {"OnInstrument": [
            {"ApplicationProfileName": "BCLConvertNextera", "ApplicationProfileVersion": "~=1.0.0"}]},
    }


def _errors(version) -> list[str]:
    with pytest.raises(ProfileValidationError) as caught:
        check_test_profile(_test(version), "Wgs.yaml")
    return caught.value.errors


class TestTheVersionRule:
    """Before this rule each of the refused values synced (measured on
    e65c60d); only three whole numbers pass now."""

    @pytest.mark.parametrize("version", ["1.0.0", "0.0.0", "10.20.30", "999999999.0.0"])
    def test_three_whole_numbers_pass(self, version):
        check_test_profile(_test(version), "Wgs.yaml")

    @pytest.mark.parametrize("version", [
        "1.0", "1", "1.0.0rc1", "01.0.0", "1.0.0.0", "v1.0.0", "1.0.0+local",
        "1234567890.0.0", " 1.0.0",
    ])
    def test_anything_else_is_refused(self, version):
        assert _errors(version) == [RULE]

    def test_a_whole_number_is_refused(self):
        assert _errors(1) == ["Version: must be text: put it in quotes"]

    def test_a_long_version_is_refused_by_its_bound(self):
        # The PEP 440 check raised a plain ValueError on 4,301 digits before
        # the input rules; the bound of 256 characters now comes first.
        assert _errors("9" * 4301 + ".0.0") == ["Version: must be at most 256 characters"]

    def test_a_decimal_number_says_yaml_may_have_changed_it(self):
        (error,) = _errors(1.0)
        assert error.startswith("Version: is a number with a decimal point")
