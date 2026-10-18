"""``pixi run check-settings <folder>``: check a settings folder with the rules
the configuration sync uses, with no database, no network and no running app
(docs/design/2026-10-18-input-rules-design.md, "7. The settings command").

A lab runs it on its settings repository before a sync, or on every change.
It prints one problem per line, ``file:line:column: place: problem``, warnings
marked, and exits 1 when there is an error. It checks instrument files; each
later step of the input rules adds its files here.

``--schema <dir>`` writes a JSON Schema per document for editors. A schema is
a help, not the authority: it cannot express keys given twice, how a value is
spelled, anchors or the rules relating several keys. This command is.
"""

import argparse
import json
import sys
from pathlib import Path

from .instruments import (
    InstrumentRules,
    InstrumentsFileRules,
    LocalInstrumentsFileRules,
    check_local_instruments_file,
    check_synced_instrument_file,
    definitions_from,
    duplicate_instruments,
)
from .problems import problem_line

SCHEMAS = {
    "instrument.schema.json": (InstrumentRules, "A synced instrument file holding one instrument."),
    "instruments-file.schema.json": (
        InstrumentsFileRules, "A synced instrument file holding several instruments."),
    "local-instruments.schema.json": (
        LocalInstrumentsFileRules, "The local instruments file (config/instruments.yaml)."),
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
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        why = e.strerror if isinstance(e, OSError) else "not UTF-8 text"
        print(f"{shown}: cannot be read ({why})")
        tally.errors += 1
        return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="check-settings",
        description="Check a SeqSetup settings folder with the rules the configuration sync uses.",
    )
    parser.add_argument("folder", type=Path, nargs="?",
                        help="the settings folder, laid out as the sync reads it")
    parser.add_argument("--instruments", default="instruments",
                        help="the instrument folder inside FOLDER (default: instruments)")
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

    tally = _Tally()
    definitions = []
    instruments = args.folder / args.instruments
    paths = sorted(p for p in instruments.rglob("*") if p.suffix in (".yaml", ".yml") and p.is_file())
    for path in paths:
        shown = path.relative_to(args.folder).as_posix()
        tally.files += 1
        text = _read(path, shown, tally)
        if text is None:
            continue
        result = check_synced_instrument_file(text, shown)
        tally.report(result.problems)
        if result.ok:
            definitions += definitions_from(result.value, path.name)
    for problem in duplicate_instruments(definitions):
        print(f"{args.instruments.rstrip('/')}/: {problem}")
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
