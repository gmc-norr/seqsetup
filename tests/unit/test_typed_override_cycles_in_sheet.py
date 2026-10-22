"""A sample's own OverrideCycles -- one typed by hand, such as a UMI layout --
is the value the [BCLConvert_Data] OverrideCycles cell carries, through the
profile writer Mark Ready uses. No test said so: a change that let the value
worked out from the indexes win over a typed one passed all 736 tests that
mention override (project review of 7d970c7, 2026-10-21, TH-2), and the UMI
bases would have been read as Read 1."""

import yaml

from seqsetup.models.test_profile import TestProfile as _TestProfile

from .test_writer_uses_the_plan import SHIPPED, _export, _section, _shipped, _today_run

TYPED = "U8Y143;I10;I10;Y151"


def _profiles():
    apps = [_shipped(f.name) for f in
            sorted((SHIPPED / "application_profiles" / "dragen").glob("*.yaml"))]
    wgs = _TestProfile.from_yaml(
        yaml.safe_load((SHIPPED / "test_profiles" / "Wgs.yaml").read_text()), "Wgs.yaml")
    return apps, [wgs]


def test_a_typed_override_cycles_is_the_sheets_cell():
    run = _today_run()
    run.samples[0].override_cycles = TYPED
    apps, tests = _profiles()

    rows = _section(_export(run, apps, tests), "BCLConvert_Data")
    header = rows[0].split(",")
    cells = {}
    for row in rows[1:]:
        values = row.split(",")
        cells.setdefault(values[header.index("Sample_ID")], set()).add(
            values[header.index("OverrideCycles")])

    assert cells == {"S1": {TYPED}, "S2": {"Y151;I10;I10;Y151"}}
