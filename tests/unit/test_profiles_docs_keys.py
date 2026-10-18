"""The admin guide names every key a profile file can have.

The rulebook refuses any key it does not name, so a key the guide leaves out
is one a lab cannot learn about (docs/design/2026-10-18-input-rules-design.md,
step 2).
"""

from pathlib import Path

import pytest

from seqsetup.input_rules.profiles import (
    ApplicationProfileReferenceRules,
    ApplicationProfileRules,
    TestProfileRules,
)

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "admin-guide" / "profiles.rst"
RULEBOOKS = (ApplicationProfileRules, ApplicationProfileReferenceRules, TestProfileRules)


@pytest.mark.parametrize("key", sorted({key for rulebook in RULEBOOKS for key in rulebook.model_fields}))
def test_the_guide_names_the_key(key):
    assert f"``{key}``" in GUIDE.read_text()


def test_the_guide_names_illumina_s_applications():
    from seqsetup.input_rules.base import ILLUMINA_APPLICATION_NAMES

    for name in ILLUMINA_APPLICATION_NAMES:
        assert f"``{name}``" in GUIDE.read_text(), name
