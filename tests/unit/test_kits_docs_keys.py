"""The admin guide names every key an index kit file can have.

The rulebook refuses any key it does not name, so a key the guide leaves out
is one a lab cannot learn about (docs/design/2026-10-18-input-rules-design.md,
step 3).
"""

from pathlib import Path

import pytest

from seqsetup.input_rules.kits import FORM_BOXES, IndexPairRules, IndexRules, KitRules

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "admin-guide" / "index-kits.rst"
RULEBOOKS = (KitRules, IndexRules, IndexPairRules)


@pytest.mark.parametrize("key", sorted({key for rulebook in RULEBOOKS
                                        for key in rulebook.model_fields}))
def test_the_guide_names_the_key(key):
    assert f"``{key}``" in GUIDE.read_text()


@pytest.mark.parametrize("box", sorted(FORM_BOXES.values()))
def test_the_guide_names_each_form_box(box):
    assert box in GUIDE.read_text(), box


def test_the_guide_names_the_settings_command_options():
    text = GUIDE.read_text()

    assert "--index-kits" in text and "--no-index-kits" in text
