"""Read-only check: list Ready/Archived runs whose saved Sample Sheet v2 has
either of two profile-export bugs (fixed in samplesheet_v2_exporter):

  1. A [*_Data] header uses a profile field name that the profile's Translate
     mapping renames (e.g. IndexI7/IndexI5 instead of Index/Index2). BCL
     Convert does not recognise those columns.
  2. A sample on several lanes has a row for only some of them. Its reads
     from the missing lanes went to Undetermined.

Usage — Docker Compose (tools/ is in the image):
    docker compose exec app env PYTHONPATH=src pixi run python tools/check_broken_samplesheets.py

Usage — from a checkout of this repo that can reach the database:
    MONGODB_URI='mongodb://...' PYTHONPATH=src pixi run python tools/check_broken_samplesheets.py

Connects with the app's own settings (MONGODB_URI / MONGODB_DATABASE, or
config/mongodb.yaml). Only reads — it never changes the database.

Exit code 0 = no broken sheets found. 1 = at least one broken sheet.
"""

import csv
import io
import sys

DEFAULT_UNTRANSLATED = {"IndexI7", "IndexI5"}
CHECKED_STATUSES = ["ready", "archived"]


def untranslated_names(app_profile_docs) -> set[str]:
    """Translate source names from every profile, plus the shipped defaults."""
    names = set(DEFAULT_UNTRANSLATED)
    for doc in app_profile_docs:
        for source, target in (doc.get("translate") or {}).items():
            if source != target:
                names.add(str(source))
    return names


def _data_sections(sheet: str) -> dict[str, list[list[str]]]:
    """Return {section_name: non-empty CSV rows} for every [*_Data] section."""
    raw: dict[str, list[str]] = {}
    current = None
    for line in sheet.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1]
            raw[current] = []
        elif current is not None:
            raw[current].append(line)
    return {
        name: [row for row in csv.reader(io.StringIO("\n".join(lines))) if row]
        for name, lines in raw.items()
        if name.endswith("_Data")
    }


def find_problems(sheet: str, sample_docs: list[dict], untranslated: set[str]) -> list[str]:
    """Describe each occurrence of the two bugs in one saved v2 sheet."""
    problems = []
    for section, rows in _data_sections(sheet).items():
        if not rows:
            continue
        header = rows[0]
        bad = [h for h in header if h in untranslated]
        if bad:
            problems.append(
                f"[{section}] header has untranslated column(s): {', '.join(bad)}"
            )
        if "Sample_ID" not in header or "Lane" not in header:
            continue
        sid_i, lane_i = header.index("Sample_ID"), header.index("Lane")
        body = [row for row in rows[1:] if len(row) > max(sid_i, lane_i)]
        for sample in sample_docs:
            sid = sample.get("sample_id", "")
            # The exporter prefixes "'" to IDs starting with - + = @.
            written_as = {sid, "'" + sid}
            lanes_written = {row[lane_i] for row in body if row[sid_i] in written_as}
            # A sample absent from the section is a different question (not
            # every sample belongs to every application); this bug wrote one
            # row per sample, so look only at samples that do appear.
            if not lanes_written:
                continue
            missing = [
                str(lane) for lane in (sample.get("lanes") or [])
                if str(lane) not in lanes_written
            ]
            if missing:
                problems.append(
                    f"[{section}] sample {sid}: no row for lane(s) {', '.join(missing)}"
                )
    return problems


def check_runs(db) -> tuple[str, int]:
    """Check every Ready/Archived run. Returns (report text, broken run count)."""
    untranslated = untranslated_names(
        db["application_profiles"].find({}, {"translate": 1})
    )
    broken: dict[str, list[tuple[dict, list[str]]]] = {s: [] for s in CHECKED_STATUSES}
    checked = no_sheet = 0
    runs = db["runs"].find(
        {"status": {"$in": CHECKED_STATUSES}},
        {
            "run_name": 1,
            "status": 1,
            "generated_samplesheet_v2": 1,
            "generated_samplesheet": 1,
            "samples.sample_id": 1,
            "samples.lanes": 1,
        },
    )
    for doc in runs:
        sheet = doc.get("generated_samplesheet_v2") or doc.get("generated_samplesheet")
        if not sheet:
            no_sheet += 1
            continue
        checked += 1
        problems = find_problems(sheet, doc.get("samples") or [], untranslated)
        if problems:
            broken[doc["status"]].append((doc, problems))

    lines = [f"Checked {checked} Ready/Archived run(s) with a saved v2 Sample Sheet."]
    if no_sheet:
        lines.append(f"{no_sheet} run(s) have no saved v2 sheet (not checked).")
    total = sum(len(v) for v in broken.values())
    if not total:
        lines.append("No broken Sample Sheets found.")
        return "\n".join(lines), 0

    advice = {
        "ready": "Fix: after deploying the fix, move each run to Draft, then back to Ready.",
        "archived": "Cannot be changed. Check whether these runs were used for results.",
    }
    for status in CHECKED_STATUSES:
        lines.append("")
        lines.append(f"{status.upper()} - {len(broken[status])} broken. {advice[status]}")
        for doc, problems in broken[status]:
            lines.append(f"  {doc.get('run_name') or '(no name)'}  (id {doc.get('_id')})")
            lines.extend(f"    - {p}" for p in problems)
    return "\n".join(lines), total


def main() -> int:
    from seqsetup.services.database import init_db

    report, broken = check_runs(init_db())
    print(report)
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
