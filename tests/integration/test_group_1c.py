"""Group 1c through the real routes (spec 2026-09-28): the mismatch limit
(F6), disabled instruments (F27), the index-kit page (F31/F32) and the
Sample ID cell (F5)."""

import json
import re

import pytest

from seqsetup.data import instruments as instruments_module
from seqsetup.models.index import Index, IndexKit, IndexPair, IndexType
from seqsetup.models.instrument_definition import InstrumentDefinition
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.services.validation import ValidationService, clear_validation_cache

from .conftest import disable_repos


ORIGIN = {"Origin": "http://testserver"}
NOVASEQ_X = "NovaSeq X Series"
MISEQ_I100 = "MiSeq i100 Series"
REFUSAL = "Barcode mismatches must be 0, 1 or 2"


def _pair(i7: str, i5, name: str) -> IndexPair:
    return IndexPair(
        id=name, name=name,
        index1=Index(name=f"{name}-i7", sequence=i7, index_type=IndexType.I7),
        index2=Index(name=f"{name}-i5", sequence=i5, index_type=IndexType.I5) if i5 else None,
    )


def _mismatch_run(ctx, run_id: str) -> SequencingRun:
    """A draft with two samples, each with mismatch overrides 2 / 2."""
    run = SequencingRun(id=run_id, run_name="Group 1c", run_cycles=RunCycles(151, 151, 10, 10))
    for n in (1, 2):
        run.add_sample(Sample(sample_id=f"S{n}", lanes=[1],
                              barcode_mismatches_index1=2, barcode_mismatches_index2=2))
    ctx.run_repo.save(run)
    return ctx.run_repo.get_by_id(run_id)


def _mismatches(ctx, run_id: str):
    run = ctx.run_repo.get_by_id(run_id)
    return [(s.barcode_mismatches_index1, s.barcode_mismatches_index2) for s in run.samples], run.updated_at


class TestMismatchLimit:
    """Barcode mismatches are blank, 0, 1 or 2 (BCL Convert's range); any
    other text is refused and nothing is saved (F6)."""

    @pytest.mark.parametrize("value", ["3", "-1", "1.5", "1e", "x"])
    def test_row_refuses_value_outside_range(self, logged_in_client, fresh_app, value):
        _app, ctx, _db = fresh_app
        run = _mismatch_run(ctx, "f6-row-bad")
        before = _mismatches(ctx, run.id)

        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/{run.samples[0].id}/settings",
            data={"barcode_mismatches_index1": value}, headers=ORIGIN,
        )

        assert resp.status_code == 400
        assert REFUSAL in resp.text
        assert _mismatches(ctx, run.id) == before

    @pytest.mark.parametrize("value, stored", [("", None), ("0", 0), ("2", 2), (" 1 ", 1)])
    def test_row_saves_allowed_value(self, logged_in_client, fresh_app, value, stored):
        _app, ctx, _db = fresh_app
        run = _mismatch_run(ctx, "f6-row-ok")

        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/{run.samples[0].id}/settings",
            data={"barcode_mismatches_index1": value}, headers=ORIGIN,
        )

        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run.id).samples[0].barcode_mismatches_index1 == stored

    def test_bulk_one_bad_value_changes_no_sample(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _mismatch_run(ctx, "f6-bulk-bad")
        before = _mismatches(ctx, run.id)

        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/set-mismatches",
            data={"sample_ids": json.dumps([s.id for s in run.samples]),
                  "mismatch_index1": "1", "mismatch_index2": "3"},
            headers=ORIGIN,
        )

        assert resp.status_code == 400
        assert REFUSAL in resp.text
        assert _mismatches(ctx, run.id) == before

    def test_row_refuses_bad_value_in_the_index2_box(self, logged_in_client, fresh_app):
        """The i5 box on a row is a second call site of the parser; without
        its own test a revert there would go unnoticed."""
        _app, ctx, _db = fresh_app
        run = _mismatch_run(ctx, "f6-row-bad-i5")
        before = _mismatches(ctx, run.id)

        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/{run.samples[0].id}/settings",
            data={"barcode_mismatches_index2": "1e"}, headers=ORIGIN,
        )

        assert resp.status_code == 400
        assert REFUSAL in resp.text
        assert _mismatches(ctx, run.id) == before

    def test_bulk_refuses_bad_value_in_the_index1_box(self, logged_in_client, fresh_app):
        """The bulk i7 box is a third call site; same reason."""
        _app, ctx, _db = fresh_app
        run = _mismatch_run(ctx, "f6-bulk-bad-i7")
        before = _mismatches(ctx, run.id)

        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/set-mismatches",
            data={"sample_ids": json.dumps([s.id for s in run.samples]),
                  "mismatch_index1": "1e", "mismatch_index2": "1"},
            headers=ORIGIN,
        )

        assert resp.status_code == 400
        assert REFUSAL in resp.text
        assert _mismatches(ctx, run.id) == before

    def test_bulk_apply_writes_only_the_typed_i7_column(self, logged_in_client, fresh_app):
        """Apply with the i5 box blank leaves every ticked sample's i5 value
        alone (the user's decision after the build review, 2026-09-28)."""
        _app, ctx, _db = fresh_app
        run = _mismatch_run(ctx, "f6-bulk-ok")

        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/set-mismatches",
            data={"sample_ids": json.dumps([s.id for s in run.samples]),
                  "mismatch_index1": "0", "mismatch_index2": "", "mode": "apply"},
            headers=ORIGIN,
        )

        assert resp.status_code == 200
        assert _mismatches(ctx, run.id)[0] == [(0, 2), (0, 2)]

    def test_bulk_apply_writes_only_the_typed_i5_column(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _mismatch_run(ctx, "f6-bulk-i5-only")

        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/set-mismatches",
            data={"sample_ids": json.dumps([s.id for s in run.samples]),
                  "mismatch_index1": "", "mismatch_index2": "0", "mode": "apply"},
            headers=ORIGIN,
        )

        assert resp.status_code == 200
        assert _mismatches(ctx, run.id)[0] == [(2, 0), (2, 0)]

    def test_bulk_apply_with_both_boxes_blank_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = _mismatch_run(ctx, "f6-bulk-blank")
        before = _mismatches(ctx, run.id)

        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/set-mismatches",
            data={"sample_ids": json.dumps([s.id for s in run.samples]),
                  "mismatch_index1": "", "mismatch_index2": "", "mode": "apply"},
            headers=ORIGIN,
        )

        assert resp.status_code == 400
        assert "use Clear to reset both" in resp.text
        assert _mismatches(ctx, run.id) == before

    def test_bulk_clear_resets_both_columns(self, logged_in_client, fresh_app):
        """Control: Clear sends mode=clear and puts both back to the run default."""
        _app, ctx, _db = fresh_app
        run = _mismatch_run(ctx, "f6-bulk-clear")

        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/set-mismatches",
            data={"sample_ids": json.dumps([s.id for s in run.samples]),
                  "mismatch_index1": "", "mismatch_index2": "", "mode": "clear"},
            headers=ORIGIN,
        )

        assert resp.status_code == 200
        assert _mismatches(ctx, run.id)[0] == [(None, None), (None, None)]


def _sync(ctx, names=(NOVASEQ_X, MISEQ_I100), disabled=()) -> None:
    """Store synced definitions made from the shipped instruments.yaml, as a
    sync would, with the `disabled` ones switched off."""
    for name in names:
        definition = InstrumentDefinition.from_yaml(
            dict(instruments_module._instruments[name], name=name), "instruments.yaml"
        )
        definition.enabled = name not in disabled
        ctx.instrument_definition_repo.save(definition)
    instruments_module.clear_synced_instruments_cache()
    clear_validation_cache()


def _clean_run(ctx, run_id: str, platform=InstrumentPlatform.NOVASEQ_X, flowcell: str = "10B",
               status: RunStatus = RunStatus.DRAFT) -> SequencingRun:
    """One indexed sample in lane 1 with no blocking error and, on NovaSeq X,
    no color-balance error: i7 CCCCCCCC lights both channels, and the
    instrument reads i5 GGGGGGGG reverse-complemented, as CCCCCCCC."""
    run = SequencingRun(
        id=run_id, run_name="Group 1c", instrument_platform=platform,
        flowcell_type=flowcell, run_cycles=RunCycles(151, 151, 10, 10), status=status,
    )
    run.add_sample(Sample(sample_id="S1", index_pair=_pair("CCCCCCCC", "GGGGGGGG", "p1"), lanes=[1]))
    ctx.run_repo.save(run)
    return run


def _platform_options(page: str) -> list[tuple[str, bool, str]]:
    """(value, selected, label) of each option in the New Run Platform select."""
    select = re.search(r'<select name="instrument_platform".*?</select>', page, re.S).group(0)
    return [
        (value, bool(selected), label.strip())
        for value, selected, label in re.findall(
            r'<option value="([^"]*)"\s*(selected)?\s*>([^<]*)</option>', select)
    ]


class TestDisabledInstrument:
    """A synced instrument switched off is not offered, is refused when
    chosen, and a run already on one still shows it, marked (F27)."""

    def test_toggle_hides_instrument_from_new_run_at_once(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _sync(ctx)
        run = _clean_run(ctx, "f27-toggle", platform=InstrumentPlatform.MISEQ_I100, flowcell="5M")
        url = f"/runs/new/step/1?run_id={run.id}"
        # This first page load fills the synced-instrument cache.
        assert NOVASEQ_X in [v for v, _s, _l in _platform_options(logged_in_client.get(url).text)]
        novaseq = ctx.instrument_definition_repo.get_by_name(NOVASEQ_X)

        resp = logged_in_client.post(
            "/admin/instruments/synced/toggle",
            data={"instrument_id": novaseq.id, "enabled": "false"}, headers=ORIGIN,
        )

        assert resp.status_code == 200
        assert NOVASEQ_X not in [v for v, _s, _l in _platform_options(logged_in_client.get(url).text)]

    def test_run_on_disabled_instrument_shows_it_marked(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _sync(ctx, disabled=(NOVASEQ_X,))
        run = _clean_run(ctx, "f27-marked")

        options = _platform_options(logged_in_client.get(f"/runs/new/step/1?run_id={run.id}").text)

        assert options == [(MISEQ_I100, False, MISEQ_I100), (NOVASEQ_X, True, f"{NOVASEQ_X} (disabled)")]

    def test_run_on_instrument_left_out_of_sync_shows_not_available(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _sync(ctx, names=(MISEQ_I100,))
        run = _clean_run(ctx, "f27-not-synced")

        options = _platform_options(logged_in_client.get(f"/runs/new/step/1?run_id={run.id}").text)

        assert options == [(MISEQ_I100, False, MISEQ_I100), (NOVASEQ_X, True, f"{NOVASEQ_X} (not available)")]

    def test_choosing_disabled_instrument_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _sync(ctx, disabled=(NOVASEQ_X,))
        run = _clean_run(ctx, "f27-choose", platform=InstrumentPlatform.MISEQ_I100, flowcell="5M")
        before = ctx.run_repo.get_by_id(run.id).updated_at

        resp = logged_in_client.post(
            f"/runs/{run.id}/instrument", data={"instrument_platform": NOVASEQ_X}, headers=ORIGIN,
        )

        assert resp.status_code == 400
        assert f"{NOVASEQ_X} is disabled by an administrator. The run still uses {MISEQ_I100}." in resp.text
        after = ctx.run_repo.get_by_id(run.id)
        assert (after.instrument_platform, after.updated_at) == (InstrumentPlatform.MISEQ_I100, before)

    def test_choosing_enabled_instrument_still_works(self, logged_in_client, fresh_app):
        """Control: moving a run off a disabled instrument works."""
        _app, ctx, _db = fresh_app
        _sync(ctx, disabled=(NOVASEQ_X,))
        run = _clean_run(ctx, "f27-choose-ok")

        resp = logged_in_client.post(
            f"/runs/{run.id}/instrument", data={"instrument_platform": MISEQ_I100}, headers=ORIGIN,
        )

        assert resp.status_code == 200
        assert ctx.run_repo.get_by_id(run.id).instrument_platform == InstrumentPlatform.MISEQ_I100


class TestDisabledInstrumentBlocksMarkReady:
    """A Draft on a disabled instrument shows an Error and cannot be marked
    Ready, even when the switch goes off while the exports are being
    generated; Ready runs are left alone (F27, review P2)."""

    def _setup(self, fresh_app, run_id, disabled=(NOVASEQ_X,)):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")
        _sync(ctx, disabled=disabled)
        return ctx, _clean_run(ctx, run_id).id

    def test_check_panel_shows_the_error(self, logged_in_client, fresh_app):
        ctx, run_id = self._setup(fresh_app, "f27-panel")

        panel = logged_in_client.get(f"/runs/{run_id}/validate-panel").text

        assert f"{NOVASEQ_X} is disabled by an administrator" in panel

    def test_mark_ready_is_refused(self, logged_in_client, fresh_app):
        ctx, run_id = self._setup(fresh_app, "f27-ready")

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.headers.get("HX-Retarget") == "#ready-message"
        assert (f"{NOVASEQ_X} is disabled by an administrator. Pick another instrument "
                f"in Run Setup before marking the run ready.") in resp.text
        run = ctx.run_repo.get_by_id(run_id)
        assert run.status == RunStatus.DRAFT and run.generated_samplesheet_v2 is None

    def test_enabling_again_allows_mark_ready(self, logged_in_client, fresh_app):
        ctx, run_id = self._setup(fresh_app, "f27-again")
        refused = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)
        assert refused.headers.get("HX-Retarget") == "#ready-message"
        novaseq = ctx.instrument_definition_repo.get_by_name(NOVASEQ_X)
        logged_in_client.post(
            "/admin/instruments/synced/toggle",
            data={"instrument_id": novaseq.id, "enabled": "true"}, headers=ORIGIN,
        )

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert ctx.run_repo.get_by_id(run_id).status == RunStatus.READY, resp.text[:400]

    def test_only_drafts_get_the_error(self, fresh_app):
        _app, ctx, _db = fresh_app
        _sync(ctx, disabled=(NOVASEQ_X,))
        draft = _clean_run(ctx, "f27-draft-run")
        ready = _clean_run(ctx, "f27-ready-run", status=RunStatus.READY)

        assert "instrument_disabled" in [e.category for e in ValidationService.validate_configuration(draft)]
        assert "instrument_disabled" not in [e.category for e in ValidationService.validate_configuration(ready)]

    def test_draft_without_samples_gets_the_error_too(self, fresh_app):
        """The instrument is a run setting, so the error shows before any
        sample is added (spec § F27). Proven by moving the check below the
        no-samples early return: this test then fails."""
        _app, ctx, _db = fresh_app
        _sync(ctx, disabled=(NOVASEQ_X,))
        empty = SequencingRun(id="f27-empty", run_name="Empty", flowcell_type="10B",
                              run_cycles=RunCycles(151, 151, 10, 10))

        assert "instrument_disabled" in [e.category for e in ValidationService.validate_configuration(empty)]

    def test_disabled_while_exports_are_generated_is_refused(self, logged_in_client, fresh_app, monkeypatch):
        ctx, run_id = self._setup(fresh_app, "f27-race", disabled=())
        from seqsetup.routes import runs as runs_module
        generate = runs_module._pregenerate_exports

        def disable_during_generation(run, ctx_):
            novaseq = ctx.instrument_definition_repo.get_by_name(NOVASEQ_X)
            # The database only: the in-process cache still says enabled.
            ctx.instrument_definition_repo.set_enabled(novaseq.id, False)
            return generate(run, ctx_)

        monkeypatch.setattr(runs_module, "_pregenerate_exports", disable_during_generation)

        resp = logged_in_client.post(f"/runs/{run_id}/status/ready", headers=ORIGIN)

        assert resp.status_code == 409
        assert "was disabled by an administrator while the exports were being generated" in resp.text
        run = ctx.run_repo.get_by_id(run_id)
        assert run.status == RunStatus.DRAFT and run.generated_samplesheet_v2 is None
        (event,) = ctx.audit_event_repo.search(limit=50, event_prefix="run.status.denied")
        assert event.details["reason"] == "instrument_disabled_during_export"


class TestKitPage:
    """The unique-dual pair table shows each pair's sequences, and an empty
    field shows a dash, not the text "&mdash;" (F31, F32)."""

    def _kit_page(self, client, ctx) -> str:
        ctx.index_kit_repo.save(IndexKit(name="Kit1c", index_pairs=[
            _pair("ATTACTCG", "TATAGCCT", "A01"),
            _pair("TCCGGAGA", None, "A02"),
        ]))
        return client.get("/indexes/detail/Kit1c/1.0").text

    def test_unique_dual_pairs_show_their_sequences(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        page = self._kit_page(logged_in_client, ctx)

        rows = {name: (i7, i5) for name, i7, i5 in re.findall(
            r'<tr><td[^>]*>(A0\d)</td><td[^>]*>([^<]*)</td><td[^>]*>([^<]*)</td></tr>', page)}
        assert rows == {"A01": ("ATTACTCG", "TATAGCCT"), "A02": ("TCCGGAGA", "—")}

    def test_empty_fields_show_a_dash_not_the_entity(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app

        page = self._kit_page(logged_in_client, ctx)

        assert "&amp;mdash;" not in page


class TestSampleIdCell:
    """Both sample-row layouts mark the Sample ID cell, which the CSS shows
    whole (F5)."""

    LONG_ID = "LONG-SAMPLE-ID-0000000001-A"

    def test_run_page_marks_the_sample_id_cell(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run = SequencingRun(id="f5-page", run_name="R", flowcell_type="10B",
                            run_cycles=RunCycles(151, 151, 10, 10))
        run.add_sample(Sample(sample_id=self.LONG_ID, lanes=[1]))
        ctx.run_repo.save(run)

        page = logged_in_client.get("/runs/f5-page").text

        assert f'<td class="sample-id-cell" title="{self.LONG_ID}">' in page

    def test_added_row_marks_the_sample_id_cell(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        ctx.run_repo.save(SequencingRun(id="f5-add", run_name="R", flowcell_type="10B",
                                        run_cycles=RunCycles(151, 151, 10, 10)))

        resp = logged_in_client.post("/runs/f5-add/samples", data={"sample_id": self.LONG_ID}, headers=ORIGIN)

        assert resp.status_code == 200
        assert f'<td class="sample-id-cell" title="{self.LONG_ID}">' in resp.text
