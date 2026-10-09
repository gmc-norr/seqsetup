"""The plan of a run's v2 Sample Sheet application sections (spec 2026-10-05
group A3, §1): which samples go in which section, from which profile, the
mismatch numbers the sheet gives BCL Convert, and every reason the sheet
cannot be written. Mark Ready's checks and the v2 writer both use it, so they
cannot disagree about which samples go where."""

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Optional

from ..models.application_profile import ApplicationProfile
from ..models.sample import Sample
from ..models.sequencing_run import SequencingRun
from .cycle_calculator import CycleCalculator
from .sheet_text import MISMATCH_COLUMNS, is_allowed_mismatch
from .versioned_tests import resolve_test

BCLCONVERT = "BCLConvert"

# Names SeqSetup fills or reads itself, in the one spelling it uses. Another
# spelling of one of them is refused (spec §1 problem 7).
SPELLED_SETTINGS_ANY = ("SoftwareVersion",)
SPELLED_COLUMNS_BCLCONVERT = (
    "Sample_ID", "Lane", "Index", "Index2", "OverrideCycles",
    "BarcodeMismatchesIndex1", "BarcodeMismatchesIndex2",
)
SPELLED_SETTINGS_BCLCONVERT = (
    "BarcodeMismatchesIndex1", "BarcodeMismatchesIndex2",
    "NoLaneSplitting", "CreateFastqForIndexReads", "AdapterBehavior",
)

# What every sync renews; left out of the fingerprint so a sync that changes
# nothing else is not a change.
_RENEWED_BY_SYNC = ("_id", "id", "synced_at", "source_file")

PROFILES_CHANGED = (
    "The profiles changed while the exports were being generated, so the Sample Sheet "
    "would not match what was checked. The run is still a Draft. Mark it Ready again."
)


class SheetPlanProblem(ValueError):
    """The writer's stop on a plan problem (spec §1): the sheet would leave
    a sample out, write one twice, or not carry what was checked."""


class SheetPlanChanged(Exception):
    """The plan the writer would write from is not the plan Mark Ready's
    checks passed: a profile changed in between (spec §1, The plan's
    fingerprint)."""

    def __init__(self):
        super().__init__(PROFILES_CHANGED)


@dataclass(frozen=True)
class SheetProblem:
    """One reason the sheet cannot be written, or a warning. ``category`` is
    empty for the writer's own texts (problem 1), which the checks report as
    missing_test_id, test_profile_not_found and profile_not_found."""

    category: str
    message: str
    sample_names: tuple[str, ...] = ()


@dataclass
class PlannedSection:
    """One [<application>_Settings] and [<application>_Data] pair: the
    distinct resolved profiles (first seen first) and the rows, each sample
    with its own profile."""

    application: str
    profiles: list[ApplicationProfile] = field(default_factory=list)
    rows: list[tuple[Sample, ApplicationProfile]] = field(default_factory=list)


@dataclass
class SheetPlan:
    sections: list[PlannedSection] = field(default_factory=list)
    # Every problem stops the writer; those with a category are check errors.
    problems: list[SheetProblem] = field(default_factory=list)
    warnings: list[SheetProblem] = field(default_factory=list)
    # (sample.id, index number) -> the mismatch number the sheet gives BCL
    # Convert, for each sample in the BCLConvert section (spec §2).
    mismatches: dict[tuple[str, int], int] = field(default_factory=dict)
    fingerprint: str = ""
    # Each test and version text, and the exact version it found (spec
    # 2026-10-07 group A4, §3): {"test", "asked", "version", "file"}.
    test_versions: list[dict] = field(default_factory=list)

    @property
    def check_errors(self) -> list[SheetProblem]:
        return [problem for problem in self.problems if problem.category]


def profile_label(profile: ApplicationProfile) -> str:
    return f"{profile.name} {profile.version}"


def data_columns(profile: ApplicationProfile) -> list[tuple[str, str]]:
    """(field, column) for each column of the profile's data section, the
    way the writer finds them: DataFields when it has entries, else the Data
    keys, each renamed by Translate (a YAML "Translate:" with no entries
    loads as None)."""
    translate = profile.translate or {}
    fields = profile.data_fields or list(profile.data.keys())
    return [(name, translate.get(name, name)) for name in fields]


def full_reads(run: SequencingRun) -> str:
    """The run's reads as an OverrideCycles with nothing masked, e.g.
    Y151;I10;I10;Y151 — what BCL Convert reads without an OverrideCycles."""
    return ";".join(
        f"{letter}{cycles}" for _, letter, cycles in CycleCalculator.read_structure(run.run_cycles)
    )


def _name(sample: Sample) -> str:
    return sample.sample_id or sample.id


def _ids(names: list[str]) -> str:
    preview = ", ".join(names[:5])
    return preview + (f", and {len(names) - 5} more" if len(names) > 5 else "")


def _settings_text(profile: ApplicationProfile) -> dict[str, str]:
    """The Settings lines as written: name and the text of the cell (the
    writer escapes that text the same way for every profile)."""
    return {
        str(key): str(value) if isinstance(value, (str, int)) else repr(value)
        for key, value in profile.settings.items()
    }


def _content(model) -> Optional[dict]:
    if model is None:
        return None
    return {key: value for key, value in model.to_dict().items() if key not in _RENEWED_BY_SYNC}


def _run_settings(run: SequencingRun, profile: ApplicationProfile) -> list[str]:
    """The run's BCL Convert settings the writer adds to this profile's
    [BCLConvert_Settings]: those the profile's Settings do not name."""
    from .samplesheet_v2_exporter import SampleSheetV2Exporter

    keys = [line.split(",", 1)[0]
            for line in SampleSheetV2Exporter._format_bclconvert_run_settings(run)]
    return [key for key in keys if key not in {str(k) for k in profile.settings}]


def _override_cycles(sample: Sample, run: SequencingRun) -> Optional[str]:
    if sample.override_cycles:
        return sample.override_cycles
    if sample.has_index and run.run_cycles:
        return CycleCalculator.calculate_override_cycles(sample, run.run_cycles)
    return None


class _Grouped:
    """Problems that name samples, grouped by their text before the IDs."""

    def __init__(self):
        self.groups: dict[tuple, list[str]] = {}

    def add(self, key: tuple, name: str) -> None:
        names = self.groups.setdefault(key, [])
        if name not in names:
            names.append(name)


def plan_sheet(
    run: SequencingRun,
    test_profile_repo,
    app_profile_repo,
    lanes: int,
) -> SheetPlan:
    """Resolve the run's tests and profiles into the sheet's application
    sections, with every problem (spec §1, problems 1-8), the mismatch
    numbers (§2), the warning for numbers the sheet cannot carry, and the
    fingerprint of what was read (§1, The plan's fingerprint). ``lanes`` is
    the flow cell's lane count."""
    plan = SheetPlan()

    # Problem 1: a sample without a test or its version (the writer's own
    # texts). Samples are grouped by test and version text (spec 2026-10-07
    # group A4, §3).
    tests: dict[tuple[str, str], list[Sample]] = {}
    for sample in run.samples:
        if not sample.test_id:
            plan.problems.append(SheetProblem(
                "", f"Sample {_name(sample)} has no test, so it would not be on the Sample Sheet."))
            continue
        if not sample.test_version:
            plan.problems.append(SheetProblem(
                "", f"Sample {_name(sample)} has no test version, so it would not be on the "
                    f"Sample Sheet."))
            continue
        tests.setdefault((sample.test_id, sample.test_version), []).append(sample)

    profile_cache: dict = {}
    fingerprint_tests = []
    sections: dict[str, PlannedSection] = {}
    first_test: dict[tuple[str, str], str] = {}
    bclconvert_of: dict[str, ApplicationProfile] = {}

    for (test, asked), samples in tests.items():
        test_profile = resolve_test(test_profile_repo, test, asked).profile
        if test_profile is None:
            plan.problems.append(SheetProblem("", f"Test '{test}' {asked} has no test profile."))
            fingerprint_tests.append([test, asked, None, []])
            continue

        resolved: list[tuple] = []  # (reference, profile)
        refs_content = []
        unresolved = False
        for ref in test_profile.application_profiles:
            key = (ref.profile_name, ref.profile_version)
            if key not in profile_cache:
                profile_cache[key] = app_profile_repo.get_by_name_version(*key)
            profile = profile_cache[key]
            refs_content.append([ref.profile_name, ref.profile_version, _content(profile)])
            if profile is None:
                unresolved = True
                plan.problems.append(SheetProblem(
                    "", f"Test '{test}' {asked} lists {ref.profile_name} {ref.profile_version}, "
                        f"which is not stored."))
                continue
            resolved.append((ref, profile))
        fingerprint_tests.append([test, asked, _content(test_profile), refs_content])
        plan.test_versions.append({"test": test, "asked": asked, "version": test_profile.version,
                                   "file": test_profile.source_file})

        by_application: dict[str, list[tuple]] = {}
        for ref, profile in resolved:
            by_application.setdefault(profile.application_name, []).append((ref, profile))

        # Problem 2: no BCLConvert profile (not when a reference is missing).
        names = [_name(s) for s in samples]
        if not unresolved and BCLCONVERT not in by_application:
            plan.problems.append(SheetProblem(
                "test_without_bclconvert_profile",
                f"Test '{test}' {asked} has no BCLConvert profile, so its {len(names)} sample(s) "
                f"would not be demultiplexed: {_ids(names)}. Add one BCLConvert profile to "
                f"the test profile.",
                tuple(names),
            ))

        # Problem 3: one application listed twice (the same profile too).
        for application, pairs in by_application.items():
            if len(pairs) > 1:
                listed = ", ".join(f"{ref.profile_name} {ref.profile_version}" for ref, _ in pairs)
                plan.problems.append(SheetProblem(
                    "test_with_two_profiles_for_one_application",
                    f"Test '{test}' {asked} lists {len(pairs)} profiles for {application}: {listed}. "
                    f"A test may list one profile per application, once.",
                    tuple(names),
                ))

        for application, pairs in by_application.items():
            section = sections.setdefault(application, PlannedSection(application))
            seen_here = []
            for _ref, profile in pairs:
                identity = (profile.name, profile.version)
                if identity in seen_here:
                    continue
                seen_here.append(identity)
                if identity not in first_test:
                    # The test and the version asked, so two versions of one
                    # test can be told apart (spec 2026-10-07 group A4, §3).
                    first_test[identity] = f"{test} {asked}"
                    section.profiles.append(profile)
                section.rows.extend((sample, profile) for sample in samples)
                if application == BCLCONVERT:
                    for sample in samples:
                        bclconvert_of.setdefault(sample.id, profile)

    plan.sections = list(sections.values())
    distinct = [profile for section in plan.sections for profile in section.profiles]

    for profile in distinct:
        label = profile_label(profile)
        columns = data_columns(profile)
        is_bclconvert = profile.application_name == BCLCONVERT

        # Problem 5: a column written twice, whatever its case.
        by_lower: dict[str, list[tuple[str, str]]] = {}
        for name, column in columns:
            by_lower.setdefault(str(column).lower(), []).append((name, column))
        for pairs in by_lower.values():
            if len(pairs) > 1:
                fields = ", ".join(name for name, _ in pairs)
                plan.problems.append(SheetProblem(
                    "repeated_column",
                    f"Profile {label} writes the column {pairs[0][1]} more than once (from "
                    f"{fields}). Each column may appear once, whatever its case; check its "
                    f"DataFields and Translate.",
                ))

        # Problem 7: another spelling of a name SeqSetup fills or reads.
        spelled = [("Settings", str(key), SPELLED_SETTINGS_ANY) for key in profile.settings]
        if is_bclconvert:
            spelled += [("Settings", str(key), SPELLED_SETTINGS_BCLCONVERT)
                        for key in profile.settings]
            spelled += [("its columns", str(column), SPELLED_COLUMNS_BCLCONVERT)
                        for _, column in columns]
        for where, written, canonical_names in spelled:
            for canonical in canonical_names:
                if written.lower() == canonical.lower() and written != canonical:
                    plan.problems.append(SheetProblem(
                        "name_spelled_otherwise",
                        f"Profile {label} spells {canonical} as '{written}' (in {where}). "
                        f"SeqSetup fills and reads only the spelling {canonical}, so the "
                        f"Sample Sheet would not carry what was checked.",
                    ))

        # Problem 6: a setting in [BCLConvert_Settings] and a column.
        if is_bclconvert:
            column_lower = {str(column).lower() for _, column in columns}
            sources = [(str(key), f"profile {label}") for key in profile.settings]
            sources += [(key, "the run's setting") for key in _run_settings(run, profile)]
            for key, source in sources:
                if key.lower() in column_lower:
                    plan.problems.append(SheetProblem(
                        "setting_in_two_places",
                        f"{key} would be set both in [BCLConvert_Settings] ({source}) and as a "
                        f"column in [BCLConvert_Data] (profile {label}). BCL Convert allows a "
                        f"setting in one place only.",
                    ))

    # Problem 4: profiles in one section whose Settings or columns differ.
    for section in plan.sections:
        first = section.profiles[0] if section.profiles else None
        for profile in section.profiles[1:]:
            settings_differ = _settings_text(profile) != _settings_text(first)
            columns_differ = ([c for _, c in data_columns(profile)]
                              != [c for _, c in data_columns(first)])
            if not (settings_differ or columns_differ):
                continue
            what = ("Settings and columns" if settings_differ and columns_differ
                    else "Settings" if settings_differ else "columns")
            app = section.application
            plan.problems.append(SheetProblem(
                "profiles_differ_in_one_section",
                f"{app}: profiles {profile_label(first)} (test "
                f"{first_test[(first.name, first.version)]}) and {profile_label(profile)} (test "
                f"{first_test[(profile.name, profile.version)]}) have different {what}, and a "
                f"Sample Sheet has one [{app}_Settings] and one [{app}_Data] section. Put these "
                f"tests in separate runs, or give the profiles the same Settings and columns.",
            ))

    # Problem 8, the mismatch numbers and the warning: the BCLConvert section.
    missing = _Grouped()
    lanes_empty = _Grouped()
    cells_empty = _Grouped()
    not_carried = _Grouped()
    all_lanes = set(range(1, lanes + 1))
    plain = full_reads(run) if run.run_cycles else ""
    for section in plan.sections:
        if section.application != BCLCONVERT:
            continue
        for sample, profile in section.rows:
            if bclconvert_of.get(sample.id) is not profile:
                continue  # a test listing two BCLConvert profiles: refused above
            label = profile_label(profile)
            columns = {column: name for name, column in data_columns(profile)}
            name = _name(sample)
            if sample.index1_sequence and "Index" not in columns:
                missing.add((label, "Index", "they have an i7"), name)
            if sample.index2_sequence and "Index2" not in columns:
                missing.add((label, "Index2", "they have an i5"), name)
            if "Lane" in columns:
                if not sample.lanes:
                    lanes_empty.add((label,), name)
            elif sample.lanes and set(sample.lanes) != all_lanes:
                missing.add((label, "Lane", "they are on some lanes only"), name)
            oc = _override_cycles(sample, run)
            if (oc and plain and "OverrideCycles" not in columns
                    and ";".join(re.split(r"[;,]", oc.upper())) != plain):
                missing.add((label, "OverrideCycles",
                             f"their OverrideCycles is not the run's full reads ({plain})"), name)
            for index_num, column in ((1, MISMATCH_COLUMNS[0]), (2, MISMATCH_COLUMNS[1])):
                has_index = sample.index1_sequence if index_num == 1 else sample.index2_sequence
                own = (sample.barcode_mismatches_index1 if index_num == 1
                       else sample.barcode_mismatches_index2)
                if column in columns:
                    value = own if own is not None else profile.data.get(columns[column], "")
                    if value is None or value in ("", "na"):
                        if has_index:
                            cells_empty.add((label, column), name)
                        number = 1
                    elif is_allowed_mismatch(value, per_sample=True):
                        number = int(value)
                    else:
                        continue  # the writer refuses the value
                else:
                    setting = profile.settings.get(column)
                    number = (int(setting) if setting is not None
                              and is_allowed_mismatch(setting, per_sample=False) else 1)
                    if has_index and own is not None and own != number:
                        not_carried.add((label, column, own, number), name)
                plan.mismatches[(sample.id, index_num)] = number

    for (label, column, reason), names in missing.groups.items():
        plan.problems.append(SheetProblem(
            "bclconvert_column_missing",
            f"{len(names)} sample(s) need a {column} column that BCLConvert profile {label} "
            f"does not have, because {reason}: {_ids(names)}. Add {column} to the profile's "
            f"DataFields.",
            tuple(names),
        ))
    for (label,), names in lanes_empty.groups.items():
        plan.problems.append(SheetProblem(
            "lanes_not_picked",
            f"{len(names)} sample(s) have no lanes picked, but BCLConvert profile {label} has a "
            f"Lane column, so their Lane cell would be empty: {_ids(names)}. Pick their lanes.",
            tuple(names),
        ))
    for (label, column), names in cells_empty.groups.items():
        plan.problems.append(SheetProblem(
            "mismatch_cell_empty",
            f"{len(names)} sample(s) would get an empty {column} cell from BCLConvert profile "
            f"{label}: {_ids(names)}. Set their mismatch number, or give the profile a Data "
            f"default for {column}.",
            tuple(names),
        ))
    for (label, column, own, number), names in not_carried.groups.items():
        plan.warnings.append(SheetProblem(
            "mismatch_number_not_in_sheet",
            f"{len(names)} sample(s) have a mismatch number the Sample Sheet cannot carry, "
            f"because BCLConvert profile {label} has no {column} column: {_ids(names)} (their "
            f"number {own}; the sheet gives BCL Convert {number}). The checks use {number}. To "
            f"use the samples' numbers, add {column} to the profile's DataFields.",
            tuple(names),
        ))

    plan.fingerprint = hashlib.sha256(json.dumps(
        {"lanes": lanes, "tests": fingerprint_tests}, sort_keys=True, default=str,
    ).encode()).hexdigest()
    return plan
