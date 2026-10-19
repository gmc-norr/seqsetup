"""``pixi run check-settings <folder>``: check a settings folder with the rules
the configuration sync uses, with no database, no network and no running app
(docs/design/2026-10-18-input-rules-design.md, "7. The settings command").

A lab runs it on its settings repository before a sync, or on every change.
It prints one problem per line, ``file:line:column: place: problem``, warnings
marked, and exits 1 when there is an error. It checks instrument files,
application and test profiles and index kit files; each later step of the
input rules adds its files here.

``--schema <dir>`` writes a JSON Schema per document for editors. A schema is
a help, not the authority: it cannot express keys given twice, how a value is
spelled, anchors or the rules relating several keys. This command is.
"""

import argparse
import json
import os
import sys
from pathlib import Path, PurePosixPath

from .instruments import (
    InstrumentRules,
    InstrumentsFileRules,
    LocalInstrumentsFileRules,
    check_local_instruments_file,
    check_synced_instrument_file,
    definitions_from,
    duplicate_instruments,
)
from ..services.index_validator import IndexValidator
from .kits import KitRules, build_kit, check_index_kit_file, repeated_kit_versions
from .problems import problem_line
from .profiles import (
    ApplicationProfileRules,
    TestProfileRules,
    build_application_profile,
    build_test_profile,
    check_application_profile_file,
    check_test_profile_file,
    differing_only_in_capitals,
    repeated_app_versions,
    repeated_test_versions,
)

SCHEMAS = {
    "instrument.schema.json": (InstrumentRules, "A synced instrument file holding one instrument."),
    "instruments-file.schema.json": (
        InstrumentsFileRules, "A synced instrument file holding several instruments."),
    "local-instruments.schema.json": (
        LocalInstrumentsFileRules, "The local instruments file (config/instruments.yaml)."),
    "application-profile.schema.json": (ApplicationProfileRules, "An application profile."),
    "test-profile.schema.json": (TestProfileRules, "A test profile."),
    "index-kit.schema.json": (KitRules, "An index kit file."),
}
_NOT_THE_AUTHORITY = (
    " A help for editors, not the authority: keys given twice, how a value is "
    "spelled, YAML anchors and the rules relating several keys are checked by "
    "pixi run check-settings only."
)


def _write_schemas(folder: Path) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    for name, (rulebook, what) in SCHEMAS.items():
        schema = rulebook.model_json_schema()
        schema["description"] = what + _NOT_THE_AUTHORITY
        (folder / name).write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")


def _built_kit(value, filename: str):
    """The kit a checked file describes, as the sync builds it."""
    return build_kit(value, created_by="github_sync", source="github")


class _Tally:
    def __init__(self):
        self.files = self.errors = self.warnings = 0

    def report(self, problems) -> None:
        for problem in problems:
            print(problem_line(problem))
            if problem.level == "error":
                self.errors += 1
            else:
                self.warnings += 1

    def summary(self) -> str:
        errors = f"{self.errors} error{'' if self.errors == 1 else 's'}" if self.errors else "no errors"
        warnings = f", {self.warnings} warning{'' if self.warnings == 1 else 's'}" if self.warnings else ""
        return f"{self.files} files checked, {errors}{warnings}"


def _read(path: Path, shown: str, tally: _Tally):
    try:
        if path.is_symlink():
            # What GitHub serves for a link to a file: its target path.
            return os.readlink(path)
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        why = e.strerror if isinstance(e, OSError) else "not UTF-8 text"
        print(f"{shown}: cannot be read ({why})")
        tally.errors += 1
        return None


def _settings_files(folder: Path, any_case: bool = False) -> tuple[list[Path], list[Path]]:
    """The files the sync reads: every name ending .yaml or .yml (in any
    case for profiles, ``any_case``, as the sync takes it), in every folder
    below; and the folders that could not be read. GitHub lists a link to a
    folder as a link, which the sync skips, and a link to anything else as a
    file whose text is the link's target path, which the sync reads and
    refuses; ``_read`` reads it so. It lists a git submodule as one entry
    with no download link, never the files inside it."""
    found, unread = [], []
    # os.walk lists a link to a folder among the folders and does not go
    # into it; every other link is among the names.
    for root, folders, names in os.walk(folder, onerror=lambda error: unread.append(Path(error.filename))):
        folders[:] = [name for name in folders if not os.path.lexists(Path(root) / name / ".git")]
        for name in names:
            path = Path(root) / name
            ending = name.lower() if any_case else name
            if ending.endswith((".yaml", ".yml")) and (path.is_symlink() or path.is_file()):
                found.append(path)
    return sorted(found), sorted(unread)


def _check_folder(settings: Path, inside: PurePosixPath, option: str, kind: str, check, build,
                  tally: _Tally, any_case: bool = False, hint: str = "") -> tuple[list, list[str], str]:
    """Check every file of one folder: (what each good file gives, its path
    as the sync names it, the folder as shown)."""
    folder = settings / inside
    shown_folder = f"{inside.as_posix().rstrip('/')}/"
    if not folder.is_dir():
        print(f"{shown_folder}: is not there (name the folder with {option}{hint})")
        tally.errors += 1
        return [], [], shown_folder
    paths, unread = _settings_files(folder, any_case)
    for path in unread:
        print(f"{path.relative_to(settings).as_posix()}/: could not be read, so its files were not checked")
        tally.errors += 1
    if not paths and not unread:
        print(f"{shown_folder}: holds no {kind} file (.yaml or .yml)")
        tally.errors += 1
    built, where = [], []
    for path in paths:
        shown = path.relative_to(settings).as_posix()
        tally.files += 1
        text = _read(path, shown, tally)
        if text is None:
            continue
        result = check(text, shown)
        tally.report(result.problems)
        if result.ok:
            made = build(result.value, path.name)
            built += made if isinstance(made, list) else [made]
            where += [shown] * (len(made) if isinstance(made, list) else 1)
    return built, where, shown_folder


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="check-settings",
        description="Check a SeqSetup settings folder with the rules the configuration sync uses.",
    )
    parser.add_argument("folder", type=Path, nargs="?",
                        help="the settings folder, laid out as the sync reads it")
    parser.add_argument("--instruments", default="instruments",
                        help="the instrument folder inside FOLDER (default: instruments)")
    parser.add_argument("--no-instruments", action="store_true",
                        help="the sync does not read instruments: do not check an instrument folder")
    parser.add_argument("--application-profiles", default="profiles/application_profiles",
                        help="the application profile folder inside FOLDER "
                             "(default: profiles/application_profiles)")
    parser.add_argument("--test-profiles", default="profiles/test_profiles",
                        help="the test profile folder inside FOLDER (default: profiles/test_profiles)")
    parser.add_argument("--index-kits", default="index_kits",
                        help="the index kit folder inside FOLDER (default: index_kits)")
    parser.add_argument("--no-index-kits", action="store_true",
                        help="the sync does not read index kits: do not check an index kit folder")
    parser.add_argument("--local-instruments", type=Path,
                        help="also check a local instruments file, such as config/instruments.yaml")
    parser.add_argument("--schema", type=Path,
                        help="write a JSON Schema per document into this folder, and stop")
    args = parser.parse_args(argv)

    if args.schema is not None:
        _write_schemas(args.schema)
        return 0
    if args.folder is None:
        parser.error("name the settings folder")
    if not args.folder.is_dir():
        print(f"{args.folder} is not a folder", file=sys.stderr)
        return 2
    folders = {}
    for option, value in (("--instruments", args.instruments),
                          ("--application-profiles", args.application_profiles),
                          ("--test-profiles", args.test_profiles),
                          ("--index-kits", args.index_kits)):
        inside = PurePosixPath(value)
        if inside.is_absolute() or ".." in inside.parts:
            print(f"{option} names a folder inside {args.folder}, as the sync reads it", file=sys.stderr)
            return 2
        folders[option] = inside

    tally = _Tally()
    if not args.no_instruments:
        definitions, _where, shown = _check_folder(
            args.folder, folders["--instruments"], "--instruments", "instrument",
            check_synced_instrument_file, definitions_from, tally,
            hint=", or say --no-instruments when the sync does not read instruments")
        for problem in duplicate_instruments(definitions):
            print(f"{shown}: {problem}")
            tally.errors += 1

    apps, app_paths, shown = _check_folder(
        args.folder, folders["--application-profiles"], "--application-profiles", "profile",
        check_application_profile_file, build_application_profile, tally, any_case=True)
    for problem in repeated_app_versions(apps, app_paths):
        print(f"{shown}: {problem}; a profile name and version may be in one file only")
        tally.errors += 1

    tests, test_paths, shown = _check_folder(
        args.folder, folders["--test-profiles"], "--test-profiles", "profile",
        check_test_profile_file, build_test_profile, tally, any_case=True)
    for problem in repeated_test_versions(tests, test_paths) + differing_only_in_capitals(tests, test_paths):
        print(f"{shown}: {problem}")
        tally.errors += 1

    if not args.no_index_kits:
        kits, kit_paths, shown = _check_folder(
            args.folder, folders["--index-kits"], "--index-kits", "index kit",
            check_index_kit_file, _built_kit, tally, any_case=True,
            hint=", or say --no-index-kits when the sync does not read index kits")
        for kit, where in zip(kits, kit_paths, strict=True):
            # The same check the sync runs on each built kit
            # (github_sync._fetch_index_kits).
            validation = IndexValidator.validate(kit)
            for error in validation.errors:
                print(f"{where}: {error}")
                tally.errors += 1
            for warning in validation.warnings:
                print(f"{where}: warning: {warning}")
                tally.warnings += 1
        for problem in repeated_kit_versions(kits, kit_paths):
            print(f"{shown}: {problem}; a kit name and version may be in one file only")
            tally.errors += 1

    if args.local_instruments is not None:
        tally.files += 1
        shown = args.local_instruments.name
        text = _read(args.local_instruments, shown, tally)
        if text is not None:
            tally.report(check_local_instruments_file(text, shown).problems)

    print(tally.summary(), file=sys.stderr)
    return 1 if tally.errors else 0


if __name__ == "__main__":
    sys.exit(main())
