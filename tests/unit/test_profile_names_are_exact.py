"""An application profile's name is exactly what it reads as.

A test profile names the application profiles it uses by
``ApplicationProfileName``. With a space at an end, or a hidden character, the
name read the same on every page as the profile it meant, but named no profile
at all: Mark Ready was refused with "Application profile 'X ' not found", which
does not say what is wrong (review leftover O7). Every other name a person
picks is ``ExactName256`` already.
"""

from pathlib import Path

import pytest

from seqsetup.input_rules.profiles import check_application_profile_file, check_test_profile_file

ROOT = Path(__file__).resolve().parents[2]
APP = (ROOT / "config/profiles/application_profiles/dragen/BCLConvertNextera.yaml").read_text()
TEST = (ROOT / "config/profiles/test_profiles/Wgs.yaml").read_text()
APP_LINE = "ApplicationProfileName: BCLConvertNextera\n"
REF_LINE = "- ApplicationProfileName: BCLConvertNextera\n"

BAD_ENDS = {
    "a space at the end": '"BCLConvertNextera "',
    "a space at the start": '" BCLConvertNextera"',
    "a zero-width space": '"BCLConvert​Nextera"',
}


def _errors(result) -> list[str]:
    return [f"{'/'.join(map(str, p.path))}: {p.message}" for p in result.problems if p.level == "error"]


def test_the_shipped_files_pass():
    assert APP_LINE in APP and REF_LINE in TEST
    assert _errors(check_application_profile_file(APP, "BCLConvertNextera.yaml")) == []
    assert _errors(check_test_profile_file(TEST, "Wgs.yaml")) == []


@pytest.mark.parametrize("case", sorted(BAD_ENDS))
def test_the_application_profiles_own_name(case):
    text = APP.replace(APP_LINE, f"ApplicationProfileName: {BAD_ENDS[case]}\n", 1)
    errors = _errors(check_application_profile_file(text, "BCLConvertNextera.yaml"))
    assert [e for e in errors if e.startswith("ApplicationProfileName:")], errors


@pytest.mark.parametrize("case", sorted(BAD_ENDS))
def test_the_name_a_test_profile_uses(case):
    text = TEST.replace(REF_LINE, f"- ApplicationProfileName: {BAD_ENDS[case]}\n", 1)
    errors = _errors(check_test_profile_file(text, "Wgs.yaml"))
    assert [e for e in errors if "ApplicationProfileName:" in e], errors
