"""What the run page shows for each sample row, read back the way app.js
reads it before a bulk action (design note
docs/design/2026-10-17-stale-page-checks-design.md).

The bulk panel sends what the page showed for the field it changes, one
entry per ticked row in the order the ids are sent, and the route refuses
the action when one has moved. A test that posts one of those routes must
send the same thing a real page would; these helpers read it off the
rendered page rather than guessing it, so they stay right when a fixture's
values change.
"""

import html
import json
import re


def _page(client, run_id: str) -> str:
    page = client.get(f"/runs/{run_id}")
    assert page.status_code == 200, page.text[:300]
    return page.text


def _row_attrs(text: str, sample_id: str) -> str:
    found = re.search(rf'<tr id="sample-row-{re.escape(sample_id)}"(.*?)>', text, re.S)
    assert found, f"the run page has no row {sample_id}"
    return found.group(1)


def _attr(attrs: str, name: str) -> str:
    found = re.search(rf'{name}="([^"]*)"', attrs)
    return html.unescape(found.group(1)) if found else ""


def _box(text: str, box_id: str) -> str:
    found = re.search(rf'id="{re.escape(box_id)}"[^>]*value="([^"]*)"', text)
    assert found, f"the run page has no box {box_id}"
    return html.unescape(found.group(1))


def shown_lanes(client, run_id: str, sample_ids) -> str:
    text = _page(client, run_id)
    return json.dumps([[int(lane) for lane in _attr(_row_attrs(text, sid), "data-lanes").split(",")
                        if lane] for sid in sample_ids])


def shown_mismatches(client, run_id: str, sample_ids) -> str:
    text = _page(client, run_id)
    return json.dumps([[_box(text, f"mismatch-i7-{sid}"), _box(text, f"mismatch-i5-{sid}")]
                       for sid in sample_ids])


def shown_override_cycles(client, run_id: str, sample_ids) -> str:
    text = _page(client, run_id)
    return json.dumps([_box(text, f"override-cycles-{sid}") for sid in sample_ids])


def shown_indexes(client, run_id: str, sample_ids) -> str:
    """What the assign, clear and delete routes take: [i7, i5] per row."""
    text = _page(client, run_id)
    return json.dumps([[_attr(_row_attrs(text, sid), "data-i7"),
                        _attr(_row_attrs(text, sid), "data-i5")]
                       for sid in sample_ids])


_BOXES = {"override_cycles": "override-cycles-{}",
          "barcode_mismatches_index1": "mismatch-i7-{}",
          "barcode_mismatches_index2": "mismatch-i5-{}"}


def shown_setting(client, run_id: str, sample_id: str, field: str) -> str:
    """What one row box shows: the value the settings route compares with
    (the box's defaultValue on a freshly drawn page)."""
    return _box(_page(client, run_id), _BOXES[field].format(sample_id))


def shown_tests(client, run_id: str, sample_ids) -> str:
    text = _page(client, run_id)
    return json.dumps([[_attr(_row_attrs(text, sid), "data-test-id"),
                        _attr(_row_attrs(text, sid), "data-test-version")]
                       for sid in sample_ids])
