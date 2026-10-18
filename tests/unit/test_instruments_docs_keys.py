"""The admin guide names every key an instrument file can have.

There was no full list: flow cells, the dye and base keys, ``default_cycles``
and ``index_cycle_options`` existed only in the code and the example files.
The rulebook now refuses any key it does not name, so a key the guide leaves
out is one a lab cannot learn about (docs/design/2026-10-18-input-rules-design.md).
"""

from pathlib import Path

import pytest

from seqsetup.input_rules.instruments import (
    CycleDefaultsRules,
    FlowcellRules,
    I5WorkflowRules,
    InstrumentRules,
    InstrumentsFileRules,
    LocalInstrumentsFileRules,
    OnboardApplicationRules,
)

GUIDE = Path(__file__).resolve().parents[2] / "docs" / "admin-guide" / "instruments.rst"
RULEBOOKS = (InstrumentRules, FlowcellRules, OnboardApplicationRules, I5WorkflowRules,
             InstrumentsFileRules, LocalInstrumentsFileRules, CycleDefaultsRules)


@pytest.mark.parametrize("key", sorted({key for rulebook in RULEBOOKS for key in rulebook.model_fields}))
def test_the_guide_names_the_key(key):
    assert f"``{key}``" in GUIDE.read_text()


def test_the_guide_names_the_settings_command():
    assert "pixi run check-settings" in GUIDE.read_text()
