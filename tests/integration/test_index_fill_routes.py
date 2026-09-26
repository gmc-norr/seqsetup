"""Integration tests: preview and apply routes for "Fill empty samples in
order" (Part B of the index-fill design, docs/superpowers/specs/
2026-09-25-index-fill-design.md).

The preview route (POST /runs/{id}/index-fill/preview) builds a plan and
saves nothing. The apply route (POST /runs/{id}/index-fill) rebuilds the
plan from the current run and kit and only assigns indexes if the rebuilt
plan's signature still matches the one the preview showed — otherwise it
refuses with 409 and saves nothing. Both routes are DRAFT-only
(Depends(get_editable_run)).
"""

from urllib.parse import quote

import markupsafe

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.services.index_fill import build_fill_plan

ORIGIN = {"Origin": "http://testserver"}

# Same sequences as Task 5's unit tests (tests/unit/test_index_fill.py) so
# both layers agree on what "unique" and "shared" indexes look like.
I7 = ["AAAAAAAA", "CCCCCCCC", "GGGGGGGG", "TTTTTTTT", "ACACACAC"]
I5 = ["AGAGAGAG", "CTCTCTCT", "GAGAGAGA", "TCTCTCTC", "CACACACA"]


def _pair(k, i7=None, i5=None):
    return IndexPair(
        id=f"p{k}", name=f"UDP{k:04d}",
        index1=Index(name=f"i7-{k}", sequence=i7 or I7[k], index_type=IndexType.I7),
        index2=Index(name=f"i5-{k}", sequence=i5 or I5[k], index_type=IndexType.I5),
    )


def _dual_kit(ctx, n=5, name="Kit", version="1", **kit_defaults):
    """Save and return a unique-dual kit with n pairs, indexes 0..n-1.

    ``kit_defaults`` forwards to IndexKit (e.g. default_index1_cycles=,
    default_read1_override=...) for tests that need to pin the kit-default
    fields _apply_kit_defaults copies onto a filled sample.
    """
    kit = IndexKit(
        name=name, version=version, index_mode=IndexMode.UNIQUE_DUAL,
        index_pairs=[_pair(k) for k in range(n)],
        **kit_defaults,
    )
    ctx.index_kit_repo.save(kit)
    return kit


def _single_kit(ctx, n=5, name="Single", version="1"):
    """Save and return a single-index (i7-only) kit with n indexes, 0..n-1."""
    kit = IndexKit(
        name=name, version=version, index_mode=IndexMode.SINGLE,
        i7_indexes=[Index(name=f"i7-{k}", sequence=I7[k], index_type=IndexType.I7) for k in range(n)],
    )
    ctx.index_kit_repo.save(kit)
    return kit


def _combinatorial_kit(ctx):
    kit = IndexKit(
        name="Combo", version="1", index_mode=IndexMode.COMBINATORIAL,
        i7_indexes=[Index(name="a", sequence=I7[0], index_type=IndexType.I7)],
        i5_indexes=[Index(name="b", sequence=I5[0], index_type=IndexType.I5)],
    )
    ctx.index_kit_repo.save(kit)
    return kit


def _run(ctx, run_id="fill-run", n_samples=3, status=RunStatus.DRAFT):
    """Save and return the id of a run holding S1..Sn with no index."""
    run = SequencingRun(
        id=run_id, run_name="Fill run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=status,
    )
    for k in range(1, n_samples + 1):
        run.add_sample(Sample(id=f"s{k}", sample_id=f"S{k}", lanes=[1]))
    ctx.run_repo.save(run)
    return run_id


def _plan_value(run, kit, start_id="") -> str:
    """What the preview's hidden ``plan`` input's value attribute renders as:
    the signature, HTML-attribute-escaped (Jinja2 autoescape == MarkupSafe)."""
    return str(markupsafe.escape(build_fill_plan(run, kit, start_id).signature()))


class TestPreviewHappyPath:
    """Preview shows exactly what Assign would do, and saves nothing."""

    def test_preview_shows_targets_in_kit_order_and_saves_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        kit = _dual_kit(ctx)
        before = ctx.run_repo.get_by_id(run_id).to_dict()

        resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill/preview",
            data={"selected_kit": kit.kit_id},
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:500]
        for sample_label, pair_name, i7, i5 in [
            ("S1", "UDP0000", I7[0], I5[0]),
            ("S2", "UDP0001", I7[1], I5[1]),
            ("S3", "UDP0002", I7[2], I5[2]),
        ]:
            assert sample_label in resp.text
            assert pair_name in resp.text
            assert i7 in resp.text
            assert i5 in resp.text
        assert "Assign 3 indexes" in resp.text

        run = ctx.run_repo.get_by_id(run_id)
        expected_plan_value = _plan_value(run, kit)
        assert f'name="plan" value="{expected_plan_value}"' in resp.text

        after = ctx.run_repo.get_by_id(run_id).to_dict()
        assert after == before


class TestPreviewStart:
    """The Start-at picker changes where the fill begins."""

    def test_start_id_moves_the_starting_point(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        kit = _dual_kit(ctx)

        resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill/preview",
            data={"selected_kit": kit.kit_id, "start_id": "p2"},
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:500]
        for sample_label, pair_name in [("S1", "UDP0002"), ("S2", "UDP0003"), ("S3", "UDP0004")]:
            assert sample_label in resp.text
            assert pair_name in resp.text
        assert "Assign 3 indexes" in resp.text

        # The above alone is vacuous: all five pair names (UDP0000..UDP0004)
        # always render in the Start-at <select>
        # (templates/runs/_index_fill_preview.html:22-25) regardless of where
        # the fill actually starts, so those substrings would still be
        # present even if start_id were ignored entirely. Pin the full
        # sample->index mapping via the hidden "plan" input's value, which
        # only equals the start_id="p2" signature when the fill truly begins
        # at the 3rd pair.
        run = ctx.run_repo.get_by_id(run_id)
        expected_plan_value = _plan_value(run, kit, "p2")
        assert f'name="plan" value="{expected_plan_value}"' in resp.text


class TestPreviewSkipsUsed:
    """An index already used elsewhere in the run is skipped and named."""

    def test_skipped_index_is_named_in_the_preview(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        kit = _dual_kit(ctx)
        run = ctx.run_repo.get_by_id(run_id)
        run.assign_index_pair_to_sample("s1", kit.index_pairs[0])
        ctx.run_repo.save(run)

        resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill/preview",
            data={"selected_kit": kit.kit_id, "start_id": "p0"},
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:500]
        assert "Skipped, already used in this run: UDP0000" in resp.text


class TestPreviewPartialI5OnlySamples:
    """A sample with only an i5 index is explained, not silently folded
    into "already has an index"; Assign still fills the true targets and
    leaves the i5-only sample exactly as it was."""

    def test_preview_explains_i5_only_sample_and_apply_leaves_it_unchanged(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, n_samples=3)
        kit = _dual_kit(ctx)
        run = ctx.run_repo.get_by_id(run_id)
        run.get_sample("s2").assign_index2(
            Index(name="x", sequence="GTGTGTGT", index_type=IndexType.I5)
        )
        ctx.run_repo.save(run)

        resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill/preview",
            data={"selected_kit": kit.kit_id},
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:500]
        assert "Left alone, they have only an i5 index: S2." in resp.text
        assert "Assign 2 indexes" in resp.text

        run = ctx.run_repo.get_by_id(run_id)
        plan = build_fill_plan(run, kit)

        apply_resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill",
            data={
                "selected_kit": kit.kit_id,
                "start_id": plan.start.id,
                "plan": plan.signature(),
            },
            headers=ORIGIN,
        )

        assert apply_resp.status_code == 200, apply_resp.text[:500]
        saved = ctx.run_repo.get_by_id(run_id)
        s2 = saved.get_sample("s2")
        assert s2.index_pair is None
        assert s2.index1 is None
        assert s2.index2_sequence == "GTGTGTGT"


class TestPreviewCombinatorialRefused:
    """A combinatorial kit is refused outright; no Assign is offered."""

    def test_combinatorial_kit_shows_refusal_and_no_assign(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        kit = _combinatorial_kit(ctx)

        resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill/preview",
            data={"selected_kit": kit.kit_id},
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:500]
        assert (
            "Fill in order works with unique dual and single-index kits. "
            "Assign combinatorial indexes by hand." in resp.text
        )
        # No Assign button: the refusal text itself contains the word
        # "Assign", so check for the button/plan-input specifically.
        assert 'name="plan"' not in resp.text
        assert "btn-primary btn-small\">Assign" not in resp.text


class TestPreviewNotEnough:
    """Too few unused indexes for the samples needing one: no partial fill."""

    def test_not_enough_indexes_shows_problem_and_no_plan_input(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, n_samples=3)
        kit = _dual_kit(ctx, n=2)

        resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill/preview",
            data={"selected_kit": kit.kit_id},
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:500]
        assert "Not enough unused indexes" in resp.text
        assert 'name="plan"' not in resp.text


class TestPreviewBadInput:
    """An unknown kit or start index is a 400, not a 500 or a silent no-op."""

    def test_unknown_kit_and_unknown_start_id_are_400(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        kit = _dual_kit(ctx)

        unknown_kit_resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill/preview",
            data={"selected_kit": "NoSuchKit:1"},
            headers=ORIGIN,
        )
        assert unknown_kit_resp.status_code == 400
        assert "Pick an index kit first." in unknown_kit_resp.text

        unknown_start_resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill/preview",
            data={"selected_kit": kit.kit_id, "start_id": "not-a-real-id"},
            headers=ORIGIN,
        )
        assert unknown_start_resp.status_code == 400
        assert "That start index is not in this kit." in unknown_start_resp.text

    def test_selected_kit_as_file_part_is_400_not_500(self, logged_in_client, fresh_app):
        """``await request.form()`` yields an ``UploadFile`` (not a ``str``)
        for a multipart part named ``selected_kit``, and
        ``sanitize_string(UploadFile, 512)`` calls ``.strip()`` on it,
        raising ``AttributeError`` — producing a 500 instead of a 400."""
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        before = ctx.run_repo.get_by_id(run_id).to_dict()

        resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill/preview",
            files={"selected_kit": ("kit.txt", b"SomeKit:1", "text/plain")},
            headers=ORIGIN,
        )

        assert resp.status_code == 400, resp.text[:300]
        after = ctx.run_repo.get_by_id(run_id).to_dict()
        assert after == before


class TestApplyHappyPath:
    """Assign gives each targeted sample the previewed index and reports it."""

    def test_apply_assigns_indexes_and_reports_success(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        kit = _dual_kit(ctx)
        run = ctx.run_repo.get_by_id(run_id)
        plan = build_fill_plan(run, kit)

        resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill",
            data={
                "selected_kit": kit.kit_id,
                "start_id": plan.start.id,
                "plan": plan.signature(),
            },
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:500]
        assert "Gave indexes to 3 samples from Kit, starting at UDP0000." in resp.text

        saved = ctx.run_repo.get_by_id(run_id)
        for sample_id, k in [("s1", 0), ("s2", 1), ("s3", 2)]:
            sample = saved.get_sample(sample_id)
            assert sample.index1_sequence == I7[k]
            assert sample.index2_sequence == I5[k]
            assert sample.index_kit_name == kit.name

    def test_apply_sets_kit_defaults_and_recomputes_override_cycles(self, logged_in_client, fresh_app):
        """Every filled row also gets the kit's override defaults and a
        recomputed override_cycles (routes/samples.py:826-827:
        _apply_kit_defaults + _update_override_cycles). The test kits used
        above set no kit defaults, so those two calls are no-ops there and
        this gap would pass unnoticed; here the kit sets 4bp effective index
        lengths and non-default read patterns, so the result is only
        correct if both calls ran."""
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, n_samples=1)
        kit = _dual_kit(
            ctx, n=1,
            default_index1_cycles=4, default_index2_cycles=4,
            default_read1_override="N2Y*", default_read2_override="N3Y*",
        )
        run = ctx.run_repo.get_by_id(run_id)
        plan = build_fill_plan(run, kit)

        resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill",
            data={
                "selected_kit": kit.kit_id,
                "start_id": plan.start.id,
                "plan": plan.signature(),
            },
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:500]
        saved = ctx.run_repo.get_by_id(run_id)
        sample = saved.get_sample("s1")
        # _apply_kit_defaults copied the kit's override defaults onto the sample:
        assert sample.index1_cycles == 4
        assert sample.index2_cycles == 4
        assert sample.read1_override_pattern == "N2Y*"
        assert sample.read2_override_pattern == "N3Y*"
        # _update_override_cycles recomputed override_cycles from those
        # defaults and the run's 151/151/8/8 cycles — not the raw 8bp
        # sequence length, and not left at None:
        assert sample.override_cycles == "N2Y149;I4N4;I4N4;N3Y148"


class TestApplySingleIndexKit:
    """The i7-only write path (routes/samples.py:822-823,
    run.assign_index1_to_sample, the plan.mode != "pair" branch) — every
    other apply test here uses a unique-dual kit and never reaches it."""

    def test_apply_single_index_kit_assigns_i7_only(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, n_samples=3)
        kit = _single_kit(ctx)
        run = ctx.run_repo.get_by_id(run_id)
        plan = build_fill_plan(run, kit)
        assert plan.mode == "i7"

        resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill",
            data={
                "selected_kit": kit.kit_id,
                "start_id": plan.start.id,
                "plan": plan.signature(),
            },
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:500]
        saved = ctx.run_repo.get_by_id(run_id)
        for sample_id, k in [("s1", 0), ("s2", 1), ("s3", 2)]:
            sample = saved.get_sample(sample_id)
            assert sample.index1_sequence == I7[k]
            assert not sample.index2_sequence
            assert sample.index_kit_name == kit.name


class TestApplyStaleSignatureRefused:
    """A changed run since the preview must not be silently adopted."""

    def test_stale_signature_is_409_and_nothing_saved(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        kit = _dual_kit(ctx)
        run = ctx.run_repo.get_by_id(run_id)
        stale_plan = build_fill_plan(run, kit)
        stale_signature = stale_plan.signature()

        # The run changes after the preview was taken: S1 gets an index by hand.
        run.assign_index_pair_to_sample("s1", kit.index_pairs[4])
        ctx.run_repo.save(run)
        before = ctx.run_repo.get_by_id(run_id).to_dict()

        resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill",
            data={
                "selected_kit": kit.kit_id,
                "start_id": stale_plan.start.id,
                "plan": stale_signature,
            },
            headers=ORIGIN,
        )

        assert resp.status_code == 409
        assert "The run or kit changed since the preview. Preview again." in resp.text

        after = ctx.run_repo.get_by_id(run_id).to_dict()
        assert after == before

    def test_kit_sequence_changed_since_preview_is_409(self, logged_in_client, fresh_app):
        """A kit sync can replace a pair's sequence without changing the kit's
        name, version or pair ids; Assign must not write a sequence the
        preview never showed."""
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        kit = _dual_kit(ctx)
        run = ctx.run_repo.get_by_id(run_id)
        stale_plan = build_fill_plan(run, kit)

        kit.index_pairs[0] = _pair(0, i7="GTGTGTGT")
        ctx.index_kit_repo.save(kit)
        before = ctx.run_repo.get_by_id(run_id).to_dict()

        resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill",
            data={
                "selected_kit": kit.kit_id,
                "start_id": stale_plan.start.id,
                "plan": stale_plan.signature(),
            },
            headers=ORIGIN,
        )

        assert resp.status_code == 409
        assert ctx.run_repo.get_by_id(run_id).to_dict() == before


class TestApplyLeavesIndexedSamplesAlone:
    """A sample that already had an index keeps exactly that index."""

    def test_already_indexed_sample_is_unchanged_after_apply(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, n_samples=3)
        kit = _dual_kit(ctx)
        other_kit = _dual_kit(ctx, n=1, name="Other", version="1")
        run = ctx.run_repo.get_by_id(run_id)
        run.assign_index_pair_to_sample("s1", other_kit.index_pairs[0])
        run.get_sample("s1").index_kit_name = other_kit.name
        ctx.run_repo.save(run)

        run = ctx.run_repo.get_by_id(run_id)
        plan = build_fill_plan(run, kit)
        assert [r.sample_label for r in plan.rows] == ["S2", "S3"]

        resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill",
            data={
                "selected_kit": kit.kit_id,
                "start_id": plan.start.id,
                "plan": plan.signature(),
            },
            headers=ORIGIN,
        )

        assert resp.status_code == 200, resp.text[:500]
        saved = ctx.run_repo.get_by_id(run_id)
        s1 = saved.get_sample("s1")
        assert s1.index1_sequence == other_kit.index_pairs[0].index1_sequence
        assert s1.index2_sequence == other_kit.index_pairs[0].index2_sequence
        assert s1.index_kit_name == other_kit.name


class TestReadyRunRefused:
    """Neither route may act on a run that isn't DRAFT."""

    def test_ready_run_preview_and_apply_are_403(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, status=RunStatus.READY)
        kit = _dual_kit(ctx)

        preview_resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill/preview",
            data={"selected_kit": kit.kit_id},
            headers=ORIGIN,
        )
        assert preview_resp.status_code == 403

        apply_resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill",
            data={"selected_kit": kit.kit_id, "start_id": "p0", "plan": "[]"},
            headers=ORIGIN,
        )
        assert apply_resp.status_code == 403


class TestApplyIgnoresSelectedKitHeader:
    """Assign takes its kit only from the previewed form's hidden
    ``selected_kit`` field, never from the X-Selected-Kit header app.js sends
    on every HTMX request so a re-rendered sample section keeps the
    dropdown's kit. If Assign ever fell back to that header, a fill could be
    built from a different kit (or kit version) than the one the preview
    showed, exporting samples under the wrong index sequences."""

    def test_assign_uses_previewed_kit_not_header_kit(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx)
        kit_a = _dual_kit(ctx, name="KitA", version="1")
        b_i7 = ["TTTTAAAA", "GGGGCCCC", "CCCCGGGG"]
        b_i5 = ["ACACGTGT", "GTGTACAC", "TGCATGCA"]
        kit_b = IndexKit(
            name="KitB", version="1", index_mode=IndexMode.UNIQUE_DUAL,
            index_pairs=[_pair(k, i7=b_i7[k], i5=b_i5[k]) for k in range(3)],
        )
        ctx.index_kit_repo.save(kit_b)

        preview_resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill/preview",
            data={"selected_kit": kit_a.kit_id},
            headers=ORIGIN,
        )
        assert preview_resp.status_code == 200, preview_resp.text[:500]

        run = ctx.run_repo.get_by_id(run_id)
        plan = build_fill_plan(run, kit_a)

        resp = logged_in_client.post(
            f"/runs/{run_id}/index-fill",
            data={
                "selected_kit": kit_a.kit_id,
                "start_id": plan.start.id,
                "plan": plan.signature(),
            },
            headers={**ORIGIN, "X-Selected-Kit": quote(kit_b.kit_id)},
        )

        assert resp.status_code == 200, resp.text[:500]
        saved = ctx.run_repo.get_by_id(run_id)
        for sample_id, k in [("s1", 0), ("s2", 1), ("s3", 2)]:
            sample = saved.get_sample(sample_id)
            assert sample.index1_sequence == I7[k]
            assert sample.index2_sequence == I5[k]
            assert sample.index1_sequence != b_i7[k]
            assert sample.index2_sequence != b_i5[k]
            assert sample.index_kit_name == kit_a.name
