"""The rulebook for application and test profiles
(docs/design/2026-10-18-input-rules-design.md, "Step 2: application and test
profiles").

A profile's Settings and Data are copied into the Sample Sheet. Every key of
both documents is named and any other is refused; the keys inside Settings and
Data stay open, but their shape is checked: a plain name, and a value that is
text, a whole number or true/false.
"""

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


class TestTheNamesTheRulesUseLoadNoApp:
    """The names SeqSetup spells its one way lived beside the sheet plan,
    whose imports run the instrument start-up: with a broken
    INSTRUMENTS_CONFIG, importing them stopped, and the settings command
    could not have used them."""

    def test_they_import_without_the_instrument_start_up(self):
        code = ("from seqsetup.services.sheet_text import SPELLED_COLUMNS_ANY, "
                "SPELLED_COLUMNS_BCLCONVERT, SPELLED_SETTINGS_ANY, SPELLED_SETTINGS_BCLCONVERT\n"
                "import sys\n"
                "print([m for m in ('seqsetup.data.instruments', 'seqsetup.services.sheet_plan')"
                " if m in sys.modules])\n")
        env = {**os.environ, "PYTHONPATH": str(REPO / "src"),
               "INSTRUMENTS_CONFIG": "/nonexistent/instruments.yaml",
               "MONGODB_URI": "mongodb://127.0.0.1:1"}

        done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                              env=env, timeout=60)

        assert done.returncode == 0, done.stderr
        assert done.stdout.strip() == "[]"

    def test_the_sheet_plan_uses_the_same_lists(self):
        from seqsetup.services import sheet_plan, sheet_text

        for name in ("SPELLED_SETTINGS_ANY", "SPELLED_COLUMNS_ANY",
                     "SPELLED_COLUMNS_BCLCONVERT", "SPELLED_SETTINGS_BCLCONVERT"):
            assert getattr(sheet_plan, name) is getattr(sheet_text, name)
