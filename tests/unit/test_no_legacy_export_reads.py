"""No reader of an export file goes round ``read_export``.

Mark Ready writes each file into its own record, and a run marked Ready by
this release carries no file in its own document. The ``generated_*`` fields
stay only to serve a run stored before that change — and exactly one function
may read them, so a reader can never fall back to a field a Ready run does
not have and serve bytes no check passed
(docs/design/2026-10-16-export-files-own-records-design.md). Written like
tests/unit/test_one_clock.py: a grep nobody has to remember.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src" / "seqsetup"
TOOLS = ROOT / "tools"

# The field names themselves live in the model, and that is the only file
# that may spell one. ``read_export`` reads them through the model's own
# mapping, so even it does not name them; nothing else in src/ or tools/ may
# name them at all -- not even in a comment, so no "just this once" read
# hides behind prose.
ALLOWED = {SRC / "models" / "sequencing_run.py"}

LEGACY = re.compile(r"generated_(?:samplesheet|json|validation)")


def _files():
    return [p for p in sorted(SRC.rglob("*.py")) + sorted(SRC.rglob("*.html"))
            + sorted(TOOLS.glob("*.py")) if p not in ALLOWED]


def _hits(paths):
    return [
        f"{path.relative_to(ROOT)}:{number}: {line.strip()}"
        for path in paths
        for number, line in enumerate(path.read_text().splitlines(), start=1)
        if LEGACY.search(line)
    ]


class TestOnlyOneFunctionReadsAStoredExport:

    def test_no_other_file_names_a_legacy_export_field(self):
        assert _hits(_files()) == []

    def test_the_one_allowed_file_is_really_there(self):
        """A rename that moved the fields would make the test above pass for
        the wrong reason."""
        for path in ALLOWED:
            assert path.exists(), path
            assert LEGACY.search(path.read_text()), f"{path} no longer names them"

    def test_read_export_is_the_only_function_that_reads_one(self):
        reader = (SRC / "services" / "run_exports.py").read_text()
        assert "LEGACY_EXPORT_FIELDS[kind]" in reader, (
            "read_export no longer reads the legacy field through the model's mapping")

    def test_the_pattern_finds_each_field(self):
        from seqsetup.models.sequencing_run import LEGACY_EXPORT_FIELDS
        for name in LEGACY_EXPORT_FIELDS.values():
            assert LEGACY.search(f"run.{name}"), name
            assert LEGACY.search(f'doc.get("{name}")'), name
        # The pre-rename name the model still reads.
        assert LEGACY.search('data.get("generated_samplesheet")')
        assert not LEGACY.search("run.exports"), "the manifest is not a legacy field"


class TestEveryKindIsRequiredExceptTheV1Sheet:
    """``read_export`` raises for a required kind a manifest does not name.
    If a kind fell off that list, a reader would get None for it and the UI
    would generate one afresh -- bytes no check passed."""

    def test_the_four_always_required_kinds_are_the_other_four(self):
        from seqsetup.models.sequencing_run import EXPORT_KINDS
        from seqsetup.services.run_exports import _ALWAYS_REQUIRED
        assert set(_ALWAYS_REQUIRED) == set(EXPORT_KINDS) - {"samplesheet_v1"}

    def test_every_kind_has_a_label_for_a_message(self):
        from seqsetup.models.sequencing_run import EXPORT_KINDS
        from seqsetup.services.run_exports import EXPORT_LABELS
        assert set(EXPORT_LABELS) == set(EXPORT_KINDS)
