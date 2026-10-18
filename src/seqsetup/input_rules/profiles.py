"""The rulebooks for application and test profiles
(docs/design/2026-10-18-input-rules-design.md, "Step 2: application and test
profiles").

A profile's Settings and Data are copied into the Sample Sheet. Every key of
both documents is named here and any other is refused (a misspelt
``Setings:`` was ignored before). The keys inside Settings and Data stay
open, as the user decided: Illumina's key lists change with each DRAGEN
version. Their shape is checked: each is a plain name, and each value is
text, a whole number or true/false that the sheet writes as it is.

The rules relating several keys are the ones ``services/profile_validator.py``
held, moved here with their substance; the rules across files are pure
functions the sync and the settings command both call.
"""

from typing import Annotated, Optional, Union

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from pydantic import AfterValidator, Field, StringConstraints

from ..models.application_profile import ApplicationProfile
from ..models.test_profile import TestProfile
from ..services.sheet_text import (
    MISMATCH_COLUMNS,
    PLAIN_VERSION_RE,
    SPELLED_COLUMNS_ANY,
    SPELLED_COLUMNS_BCLCONVERT,
    SPELLED_SETTINGS_ANY,
    SPELLED_SETTINGS_BCLCONVERT,
    describe,
    hidden_characters,
    is_allowed_mismatch,
    is_i5_rule_setting,
    starts_a_section,
)
from ..services.versioned_tests import PROFILE_VERSION_RE, PROFILE_VERSION_RULE
from .base import (
    ILLUMINA_APPLICATION_NAMES,
    STORAGE_MAX_INT,
    FilledText256,
    FilledText4096,
    PlainName,
    StrictRules,
    _filled,
    whole,
)
from .check import CheckResult, Finding, check_data, reader_refusal
from .problems import InputProblem, path_text
from .reader import Locations, read_yaml

BCLCONVERT = "BCLConvert"


def _pep440_version(value: str) -> str:
    try:
        Version(value)
    except (InvalidVersion, ValueError):
        # ValueError: a number too long for Python to read.
        raise ValueError("is not a valid PEP 440 version") from None
    return value


def _version_or_specifier(value: str) -> str:
    try:
        SpecifierSet(value)
        return value
    except InvalidSpecifier:
        pass
    try:
        Version(value)
    except (InvalidVersion, ValueError):
        raise ValueError("is not a valid PEP 440 version or specifier") from None
    return value


def _test_version(value: str) -> str:
    # A sample's test version picks among these by number (spec 2026-10-07
    # group A4, §1).
    if not PROFILE_VERSION_RE.match(value):
        raise ValueError(PROFILE_VERSION_RULE)
    return value


def _sheet_text(value: str) -> str:
    chars = hidden_characters(value)
    if chars:
        # A quoted line break still starts a new line for a line-oriented
        # reader of the Sample Sheet.
        raise ValueError(f"holds a hidden character: {describe(chars)}")
    if starts_a_section(value):
        raise ValueError(
            "cannot start with '[': written first on a line, it would start a new "
            "section of the Sample Sheet"
        )
    return value


_Bounded = Annotated[str, StringConstraints(min_length=1, max_length=256), AfterValidator(_filled)]
ProfileVersion = Annotated[_Bounded, AfterValidator(_pep440_version)]
VersionOrSpecifier = Annotated[_Bounded, AfterValidator(_version_or_specifier)]
TestVersion = Annotated[_Bounded, AfterValidator(_test_version)]
SheetText = Annotated[str, StringConstraints(max_length=4096), AfterValidator(_sheet_text)]
# What the sheet writer writes as it is (str()): text, a whole number within
# what MongoDB stores, or true/false.
SheetValue = Union[bool, whole(-STORAGE_MAX_INT - 1), SheetText]


class ApplicationProfileRules(StrictRules):
    """One application profile. Settings, Data and DataFields are required
    when the type is Dragen (see the checks below); an empty section means
    none."""

    ApplicationProfileName: FilledText256
    ApplicationProfileVersion: ProfileVersion
    ApplicationName: PlainName
    ApplicationType: FilledText256
    Settings: Optional[dict[PlainName, SheetValue]] = None
    Data: Optional[dict[PlainName, SheetValue]] = None
    DataFields: Optional[list[PlainName]] = None
    Translate: Optional[dict[PlainName, PlainName]] = None


class ApplicationProfileReferenceRules(StrictRules):
    ApplicationProfileName: FilledText256
    ApplicationProfileVersion: VersionOrSpecifier


class TestProfileRules(StrictRules):
    __test__ = False  # not a test class, for pytest

    TestType: FilledText256
    TestName: FilledText256
    Description: FilledText4096
    Version: TestVersion
    ApplicationProfiles: Annotated[list[ApplicationProfileReferenceRules], Field(min_length=1)]


def _is_dragen(value: ApplicationProfileRules) -> bool:
    return value.ApplicationType.strip().lower() == "dragen"


def _columns(value: ApplicationProfileRules) -> list[tuple[tuple, str, str]]:
    """(path, name, column) for each column of the data section, found the
    way the sheet writer finds them: DataFields when it has entries, else the
    Data keys, each renamed by Translate."""
    translate = value.Translate or {}
    if value.DataFields:
        return [(("DataFields", n), name, translate.get(name, name))
                for n, name in enumerate(value.DataFields)]
    return [(("Data", name), name, translate.get(name, name)) for name in (value.Data or {})]


def _application_findings(value: ApplicationProfileRules) -> list[Finding]:
    found = []
    settings = value.Settings or {}
    data = value.Data or {}
    translate = value.Translate or {}

    if _is_dragen(value):
        for key, kind in (("Settings", "a map of keys and values ({} for none)"),
                          ("Data", "a map of keys and values ({} for none)"),
                          ("DataFields", "a list ([] for none)")):
            if key not in value.model_fields_set:
                found.append(Finding((key,), "is required when the type is Dragen"))
            elif getattr(value, key) is None:
                found.append(Finding((key,), f"must be {kind} when the type is Dragen"))
        if value.ApplicationName not in ILLUMINA_APPLICATION_NAMES:
            found.append(Finding(
                ("ApplicationName",),
                "is not one of Illumina's application names ("
                + ", ".join(ILLUMINA_APPLICATION_NAMES)
                + "), which a profile whose type is Dragen must use",
            ))

    # The validation service compares it with the instrument's versions and
    # sorts a run's versions (sol's review of step 2's design, P2-1).
    if "SoftwareVersion" in settings:
        version = settings["SoftwareVersion"]
        if not (isinstance(version, str) and len(version) <= 256 and PLAIN_VERSION_RE.fullmatch(version)):
            found.append(Finding(
                ("Settings", "SoftwareVersion"),
                "must be a version written as text, of letters, digits, '.', '_' and '-' "
                "(put a number in quotes)",
            ))

    # BCL Convert allows at most 2 mismatches; a Data default is checked
    # under the column it becomes (spec 2026-09-29 Sample Sheet follow-ups, §1).
    for key, setting in settings.items():
        if key in MISMATCH_COLUMNS and not is_allowed_mismatch(setting, per_sample=False):
            found.append(Finding(("Settings", key),
                                 f"fills {key} and must be 0, 1 or 2 (BCL Convert allows at most 2 mismatches)"))
    for key, default in data.items():
        column = translate.get(key, key)
        if column in MISMATCH_COLUMNS and not is_allowed_mismatch(default, per_sample=True):
            found.append(Finding(("Data", key),
                                 f"fills {column} and must be 0, 1, 2, blank or na "
                                 "(BCL Convert allows at most 2 mismatches)"))

    columns = _columns(value)
    section = ("DataFields",) if value.DataFields else ("Data",)
    if "Sample_ID" not in [column for _, _, column in columns]:
        found.append(Finding(section, "has no Sample_ID column: add Sample_ID to DataFields "
                                      "(or to Data when DataFields is missing or empty)"))

    # Names compared ignoring case (spec 2026-10-05 group A3, §1).
    by_lower: dict[str, list] = {}
    for path, name, column in columns:
        by_lower.setdefault(column.lower(), []).append((path, name, column))
    for group in by_lower.values():
        if len(group) > 1:
            found.append(Finding(
                group[1][0],
                f"writes the column '{group[0][2]}' more than once: from "
                f"{', '.join(name for _, name, _ in group)}; each column may appear once "
                "(check DataFields and Translate)",
            ))
    spelled = [(("Settings", key), key, SPELLED_SETTINGS_ANY) for key in settings]
    spelled += [(path, column, SPELLED_COLUMNS_ANY) for path, _, column in columns]
    if value.ApplicationName == BCLCONVERT:
        column_lower = {column.lower() for _, _, column in columns}
        for key in settings:
            if key.lower() in column_lower:
                found.append(Finding(("Settings", key), "is both in Settings and a data column: "
                                                        "BCL Convert allows a setting in one place only"))
        spelled += [(("Settings", key), key, SPELLED_SETTINGS_BCLCONVERT) for key in settings]
        spelled += [(path, column, SPELLED_COLUMNS_BCLCONVERT) for path, _, column in columns]
        # They change how BCL Convert reads the i5 or the OverrideCycles
        # SeqSetup writes (spec 2026-10-04 group A2, §2).
        for key in settings:
            if is_i5_rule_setting(key):
                found.append(Finding(("Settings", key), "may not be set in the BCLConvert profile: "
                                                        "SeqSetup writes the i5 and OverrideCycles itself"))
    for path, written, canonical_names in spelled:
        for canonical in canonical_names:
            if written.lower() == canonical.lower() and written != canonical:
                found.append(Finding(path, f"must be spelled {canonical}: SeqSetup fills and reads "
                                           f"{canonical} itself, in that spelling only"))
    return found


def _application_check(data, locations: Locations, file: str) -> CheckResult:
    return check_data(data, locations, file, ApplicationProfileRules,
                      cross_checks=[_application_findings])


def check_application_profile_file(text: str, file: str) -> CheckResult:
    """Check one application profile file. A profile may hold a pipeline's
    address or key in Settings, so no message quotes a value."""
    read = read_yaml(text, file)
    if read.problems:
        return reader_refusal(read.problems, ApplicationProfileRules)
    return _application_check(read.data, read.locations, file)


def check_test_profile_file(text: str, file: str) -> CheckResult:
    """Check one test profile file."""
    read = read_yaml(text, file)
    if read.problems:
        return reader_refusal(read.problems, TestProfileRules)
    return check_data(read.data, read.locations, file, TestProfileRules)


def check_application_profile_data(data, file: str) -> CheckResult:
    """The same check for data already read (``ApplicationProfile.from_yaml``),
    without lines."""
    return _application_check(data, Locations(), file)


def check_test_profile_data(data, file: str) -> CheckResult:
    return check_data(data, Locations(), file, TestProfileRules)


class ProfileValidationError(Exception):
    """A profile the rules refuse: ``problems`` has each one, ``errors`` the
    text of each error, "place: problem"."""

    def __init__(self, problems: list[InputProblem], source_file: str = ""):
        self.problems = problems
        self.errors = [f"{path_text(p.path)}: {p.message}" for p in problems if p.level == "error"]
        self.source_file = source_file
        message = (f"Profile validation failed for '{source_file}': " if source_file
                   else "Profile validation failed: ")
        super().__init__(message + "; ".join(self.errors))


def build_application_profile(value: ApplicationProfileRules, file: str) -> ApplicationProfile:
    """The application profile a checked file describes, built from the
    checked value only: exactly the keys written."""
    return ApplicationProfile.from_yaml(value.model_dump(exclude_unset=True), file)


def build_test_profile(value: TestProfileRules, file: str) -> TestProfile:
    """The test profile a checked file describes, built from the checked
    value only."""
    return TestProfile.from_yaml(value.model_dump(exclude_unset=True), file)


def repeated_app_versions(profiles: list[ApplicationProfile], paths: list[str]) -> list[str]:
    """Each application profile name and version in more than one file: a
    test's reference would get whichever was stored first (outside review of
    f490536, F10). Versions are compared as versions, so "1.0" and "1.0.0"
    are one. ``paths`` are the files' paths, in step with ``profiles``."""
    files: dict[tuple, list[tuple[str, str]]] = {}
    for profile, where in zip(profiles, paths, strict=True):
        files.setdefault((profile.name, Version(profile.version)), []).append((where, profile.version))
    problems = []
    for (name, _version), found in files.items():
        if len(found) > 1:
            names = sorted(where for where, _spelled in found)
            spellings = " = ".join(sorted({spelled for _where, spelled in found}))
            problems.append(f"{name} {spellings} is in {', '.join(names[:-1])} and {names[-1]}")
    return problems


def repeated_test_versions(profiles: list[TestProfile], paths: list[str]) -> list[str]:
    """Each test and version in more than one file, since a sample could get
    any of them (spec 2026-10-07 group A4, §1). strict=True: a plain zip stops
    at the shorter list and would drop profiles out of this check."""
    files: dict[tuple, list[str]] = {}
    for profile, where in zip(profiles, paths, strict=True):
        files.setdefault((profile.test_type, profile.version), []).append(where)
    problems = []
    for (test, version), names in files.items():
        if len(names) > 1:
            names = sorted(names)
            problems.append(f"{test} {version} is in {', '.join(names[:-1])} and {names[-1]}")
    return problems


def differing_only_in_capitals(profiles: list[TestProfile], paths: list[str]) -> list[str]:
    """Two tests whose TestType differs only in letter case: a test is
    matched exactly, while every page and the Sample Sheet show what a reader
    takes for one test (spec 2026-10-07 group A4)."""
    files: dict[str, dict[str, list[str]]] = {}
    for profile, where in zip(profiles, paths, strict=True):
        spellings = files.setdefault(profile.test_type.lower(), {})
        spellings.setdefault(profile.test_type, []).append(where)
    problems = []
    for spellings in files.values():
        if len(spellings) < 2:
            continue
        parts = [f"{test} in {', '.join(sorted(names))}" for test, names in sorted(spellings.items())]
        problems.append(f"{', '.join(parts[:-1])} and {parts[-1]} differ only in capitals")
    return problems
