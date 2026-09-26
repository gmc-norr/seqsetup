"""The index-kit dropdown keeps the kit the user picked across a
sample-section re-render.

Almost every edit on the run-edit page re-renders the whole
#sample-section server-side, and that render used to draw the kit
dropdown with index_kits[0] selected — so the chosen kit silently jumped
back to the first kit. app.js now sends the kit the dropdown shows as
the X-Selected-Kit header on every HTMX request, and the render selects
that kit when it matches an existing kit id. Anything else (absent,
deleted, bogus) falls back to the first kit, as before.
"""

import json
import re
from urllib.parse import quote

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun

ORIGIN = {"Origin": "http://testserver"}

# The template renders `value="..." selected` only on the chosen option.
_SELECTED_OPTION_RE = re.compile(r'<option value="([^"]*)" selected>')


def _kit(ctx, name, pair_name, i7, i5):
    """Save and return a one-pair unique-dual kit."""
    kit = IndexKit(
        name=name, version="1.0", index_mode=IndexMode.UNIQUE_DUAL,
        index_pairs=[IndexPair(
            id=f"{pair_name}-p1", name=pair_name,
            index1=Index(name=f"{pair_name}-i7", sequence=i7, index_type=IndexType.I7),
            index2=Index(name=f"{pair_name}-i5", sequence=i5, index_type=IndexType.I5),
        )],
    )
    ctx.index_kit_repo.save(kit)
    return kit


def _draft_run(ctx, run_id="kit-choice-run"):
    """Save a draft with two un-indexed samples; return (run_id, sample ids)."""
    run = SequencingRun(
        id=run_id, run_name="Kit choice run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=RunStatus.DRAFT,
    )
    for n in (1, 2):
        run.add_sample(Sample(id=f"{run_id}-s{n}", sample_id=f"KC-0{n}", lanes=[1]))
    ctx.run_repo.save(run)
    return run_id, [s.id for s in run.samples]


def _set_lanes(client, run_id, sample_ids, chosen_kit_header=None):
    headers = dict(ORIGIN)
    if chosen_kit_header is not None:
        headers["X-Selected-Kit"] = chosen_kit_header
    return client.post(
        f"/runs/{run_id}/samples/set-lanes",
        data={"sample_ids": json.dumps(sample_ids), "lanes": json.dumps([1])},
        headers=headers,
    )


def _selected_kit_option(html):
    """The value of the kit dropdown's selected <option>, or None.

    Only looks inside <select id="index-kit-dropdown">: other selects on the
    page (e.g. the paste form's test picker) render the same option shape.
    """
    start = html.find('id="index-kit-dropdown"')
    if start < 0:
        return None
    dropdown = html[start:html.find("</select>", start)]
    match = _SELECTED_OPTION_RE.search(dropdown)
    return match.group(1) if match else None


class TestSampleSectionKeepsTheChosenKit:
    """A re-rendered #sample-section shows the kit the header names."""

    def test_header_kit_is_selected_and_its_indexes_are_listed(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        kit_a = _kit(ctx, "Kit-A", "APAIR001", "AAAAAAAA", "AGAGAGAG")
        kit_b = _kit(ctx, "Kit-B", "BPAIR001", "CCCCCCCC", "CTCTCTCT")
        run_id, sample_ids = _draft_run(ctx)

        resp = _set_lanes(logged_in_client, run_id, sample_ids, quote(kit_b.kit_id))

        assert resp.status_code == 200, resp.text[:500]
        assert _selected_kit_option(resp.text) == kit_b.kit_id
        assert 'data-index-name="BPAIR001"' in resp.text
        assert 'data-index-name="APAIR001"' not in resp.text
        assert kit_a.kit_id in resp.text  # still an option, just not selected

    def test_without_the_header_the_first_kit_is_selected(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        kit_a = _kit(ctx, "Kit-A", "APAIR001", "AAAAAAAA", "AGAGAGAG")
        _kit(ctx, "Kit-B", "BPAIR001", "CCCCCCCC", "CTCTCTCT")
        run_id, sample_ids = _draft_run(ctx)

        resp = _set_lanes(logged_in_client, run_id, sample_ids)

        assert resp.status_code == 200, resp.text[:500]
        assert _selected_kit_option(resp.text) == kit_a.kit_id
        assert 'data-index-name="APAIR001"' in resp.text
        assert 'data-index-name="BPAIR001"' not in resp.text

    def test_an_unknown_kit_id_falls_back_to_the_first_kit(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        kit_a = _kit(ctx, "Kit-A", "APAIR001", "AAAAAAAA", "AGAGAGAG")
        _kit(ctx, "Kit-B", "BPAIR001", "CCCCCCCC", "CTCTCTCT")
        run_id, sample_ids = _draft_run(ctx)

        resp = _set_lanes(logged_in_client, run_id, sample_ids, quote("no-such-kit:1"))

        assert resp.status_code == 200, resp.text[:500]
        assert _selected_kit_option(resp.text) == kit_a.kit_id
        assert 'data-index-name="APAIR001"' in resp.text

    def test_a_non_ascii_kit_id_is_selected_when_sent_encoded(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _kit(ctx, "Kit-A", "APAIR001", "AAAAAAAA", "AGAGAGAG")
        kit_u = _kit(ctx, "Kit-Ümlaut", "UPAIR001", "GGGGGGGG", "GAGAGAGA")
        run_id, sample_ids = _draft_run(ctx)

        resp = _set_lanes(logged_in_client, run_id, sample_ids, quote(kit_u.kit_id))

        assert resp.status_code == 200, resp.text[:500]
        assert _selected_kit_option(resp.text) == kit_u.kit_id
        assert 'data-index-name="UPAIR001"' in resp.text
        assert 'data-index-name="APAIR001"' not in resp.text
