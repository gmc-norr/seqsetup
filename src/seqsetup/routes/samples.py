"""Sample management routes.

Migrated from legacy register(app, ctx) closure pattern to APIRouter +
Depends(get_editable_run) + with saving_run(...).
"""

import json
import logging

from fastapi import APIRouter, Depends, Request
from starlette.responses import HTMLResponse, Response

from ..context import AppContext
from ..data.instruments import get_lanes_for_flowcell
from ..models.index import Index, IndexKit, IndexType
from ..models.sample import Sample
from ..models.sequencing_run import SequencingRun
from ..services.audit_log import audit
from ..services.cycle_calculator import CycleCalculator
from ..services.sample_parser import parse_pasted_samples
from ..templating import render, templates
from .dependencies import get_ctx, get_editable_run, saving_run
from .utils import get_username, sanitize_string

logger = logging.getLogger(__name__)


router = APIRouter(tags=["samples"])


# ---------------------------------------------------------------------------
# Module-level helpers (previously closures inside register())
# ---------------------------------------------------------------------------


def _render_sample_section(run, request: Request, ctx: AppContext) -> HTMLResponse:
    """Render the run-edit page's sample section (paste box + index panel + table).

    Used by mutation handlers that need to refresh the inline UI after
    a sample is added/removed/edited. The new section HTML re-targets
    #sample-section outerHTML.
    """
    num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
    is_editable = run.status.value == "draft"
    sample_api_cfg = ctx.sample_api_config
    sample_api_enabled = bool(sample_api_cfg and sample_api_cfg.enabled and sample_api_cfg.base_url)
    index_kits = ctx.index_kit_repo.list_all() if ctx.index_kit_repo else []
    test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []

    html = templates.env.get_template("runs/_sample_section.html").render(
        run=run, index_kits=index_kits, test_profiles=test_profiles,
        num_lanes=num_lanes, is_editable=is_editable,
        sample_api_enabled=sample_api_enabled, oob=False,
    )
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


def _messages_only(request, messages) -> HTMLResponse:
    """Render the _messages.html partial as the entire response."""
    html = templates.env.get_template("_messages.html").render(messages=messages)
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})



def _update_override_cycles(sample, run) -> None:
    """Recalculate override cycles for a sample from run configuration."""
    if run.run_cycles and sample.has_index:
        CycleCalculator.populate_index_override_patterns(sample, run.run_cycles)
        sample.override_cycles = CycleCalculator.calculate_override_cycles(
            sample, run.run_cycles
        )


def _apply_kit_defaults(sample: Sample, kit: IndexKit) -> None:
    """Copy kit-level override defaults to a sample."""
    if kit.default_index1_cycles is not None:
        sample.index1_cycles = kit.default_index1_cycles
    if kit.default_index2_cycles is not None:
        sample.index2_cycles = kit.default_index2_cycles
    if kit.default_read1_override:
        sample.read1_override_pattern = kit.default_read1_override
    if kit.default_read2_override:
        sample.read2_override_pattern = kit.default_read2_override


def _normalize_lane_selection(raw_lanes, max_lanes: int) -> list[int] | None:
    """Validate and normalize lane selection payload.

    Returns sorted unique lanes, or None if the payload is invalid.
    Empty list means "all lanes".
    """
    if not isinstance(raw_lanes, list):
        return None

    lanes: list[int] = []
    seen: set[int] = set()

    for lane in raw_lanes:
        if isinstance(lane, bool):
            return None

        if isinstance(lane, str):
            lane = lane.strip()
            if not lane:
                continue
            if not lane.isdigit():
                return None
            lane = int(lane)
        elif not isinstance(lane, int):
            return None

        if lane < 1 or lane > max_lanes:
            return None

        if lane not in seen:
            seen.add(lane)
            lanes.append(lane)

    return sorted(lanes)


# ---------------------------------------------------------------------------
# Mutation handlers — all require DRAFT run via Depends(get_editable_run)
# ---------------------------------------------------------------------------


@router.post("/runs/{run_id}/samples", response_class=HTMLResponse)
async def add_sample(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/samples — add a single sample (legacy non-wizard form)."""
    run_id = run.id
    form = await request.form()
    sample_id = form.get("sample_id", "")
    sample_name = form.get("sample_name", "")
    project = form.get("project", "")
    test_id = form.get("test_id", "")

    if not sample_id or not sample_id.strip():
        return Response("sample_id is required", status_code=400)
    sample_id = sanitize_string(sample_id, 256)
    sample_name = sanitize_string(sample_name, 256)
    project = sanitize_string(project, 256)
    test_id = sanitize_string(test_id, 256)

    sample = Sample(
        sample_id=sample_id,
        sample_name=sample_name,
        project=project,
        test_id=test_id,
        lanes=[1],
    )
    with saving_run(run, ctx, request):
        run.add_sample(sample)
    audit(
        "sample.added",
        actor=get_username(request),
        target=run_id,
        sample_id=sample.id,
        test_id=sample.test_id,
    )

    num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
    return render(request, "wizard/_sample_row.html", {
        "sample": sample,
        "run_id": run_id,
        "run_cycles": run.run_cycles,
        "show_drop_zones": False,
        "show_i5_column": True,
        "num_lanes": num_lanes,
        "show_bulk_actions": True,
        "context": "",
        "editable": True,
        "show_checkboxes": None,
    })


@router.post("/runs/{run_id}/samples/bulk", response_class=HTMLResponse)
async def add_bulk_samples(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
    context: str = "",
) -> Response:
    """POST /runs/{run_id}/samples/bulk — add multiple samples from paste/file."""
    run_id = run.id

    form = await request.form()

    sample_file = form.get("sample_file")
    if sample_file and hasattr(sample_file, "read") and sample_file.filename:
        raw_bytes = await sample_file.read()
        if len(raw_bytes) > 10 * 1024 * 1024:  # 10 MB limit
            return Response("File too large (max 10 MB)", status_code=400)
        try:
            content = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return Response("File must be UTF-8 encoded", status_code=400)
    else:
        content = form.get("paste_data", "")

    try:
        parsed = parse_pasted_samples(content)
    except ValueError as e:
        return Response(f"Validation error: {str(e)}", status_code=400)

    existing_sample_ids = {s.sample_id for s in run.samples}

    added_count = 0
    skipped_duplicates: list[str] = []
    skipped_within_paste: list[str] = []

    new_samples = []
    seen_in_paste: set[str] = set()
    for ps in parsed:
        if ps.sample_id in existing_sample_ids:
            skipped_duplicates.append(ps.sample_id)
        elif ps.sample_id in seen_in_paste:
            skipped_within_paste.append(ps.sample_id)
        else:
            seen_in_paste.add(ps.sample_id)
            sample = Sample(
                sample_id=ps.sample_id,
                test_id=ps.test_id,
                lanes=[1],
            )

            if ps.index1_sequence:
                index1 = Index(
                    name=ps.index1_name or "",
                    sequence=ps.index1_sequence,
                    index_type=IndexType.I7,
                )
                sample.assign_index1(index1)
                sample.index_kit_name = ps.index_pair_name or "Pasted"

            if ps.index2_sequence:
                index2 = Index(
                    name=ps.index2_name or "",
                    sequence=ps.index2_sequence,
                    index_type=IndexType.I5,
                )
                sample.assign_index2(index2)
                if not sample.index_kit_name:
                    sample.index_kit_name = ps.index_pair_name or "Pasted"

            _update_override_cycles(sample, run)

            new_samples.append(sample)
            added_count += 1

    if added_count > 0:
        with saving_run(run, ctx, request):
            for sample in new_samples:
                run.add_sample(sample)
        audit(
            "sample.bulk_added",
            actor=get_username(request),
            target=run_id,
            added_count=added_count,
            skipped_duplicates_count=len(skipped_duplicates),
            skipped_within_paste_count=len(skipped_within_paste),
        )

    return _render_sample_section(run, request, ctx)


# ---------------------------------------------------------------------------
# Read handlers — GET endpoints, no mutation, no get_editable_run needed
# ---------------------------------------------------------------------------


@router.get("/runs/{run_id}/samples/worklists", response_class=HTMLResponse)
def list_worklists(
    request: Request,
    run_id: str,
    context: str = "",
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /runs/{run_id}/samples/worklists — list available worklists."""
    if ctx.sample_api_config_repo is None:
        return _messages_only(request, [{"text": "Sample API is not configured.", "kind": "error"}])

    from ..services.sample_api import fetch_worklists

    api_config = ctx.sample_api_config
    if not api_config.enabled or not api_config.base_url:
        return _messages_only(request, [{"text": "Sample API is not enabled or base URL is not configured.", "kind": "error"}])

    success, message, worklists = fetch_worklists(api_config)
    if not success:
        return _messages_only(request, [{"text": f"Failed to load worklists: {message}", "kind": "error"}])

    return render(request, "wizard/_worklist_selector.html", {
        "run_id": run_id,
        "worklists": worklists,
        "context": context,
        "existing_ids": "",
    })


@router.get("/runs/{run_id}/samples/preview-worklist", response_class=HTMLResponse)
def preview_worklist(
    request: Request,
    run_id: str,
    worklist_id: str = "",
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /runs/{run_id}/samples/preview-worklist — preview samples in a worklist."""
    if ctx.sample_api_config_repo is None:
        return _messages_only(request, [{"text": "Sample API is not configured.", "kind": "error"}])

    if not worklist_id:
        return _messages_only(request, [{"text": "No worksheet selected.", "kind": "error"}])

    from ..services.sample_api import fetch_worklist_samples

    api_config = ctx.sample_api_config
    if not api_config.enabled or not api_config.base_url:
        return _messages_only(request, [{"text": "Sample API is not enabled or base URL is not configured.", "kind": "error"}])

    success, message, raw_data = fetch_worklist_samples(api_config, worklist_id)
    if not success:
        return _messages_only(request, [{"text": f"Failed to fetch worksheet samples: {message}", "kind": "error"}])

    return render(request, "wizard/_worklist_preview.html", {
        "samples": raw_data,
        "worklist_id": worklist_id,
    })


# ---------------------------------------------------------------------------
# More mutation handlers
# ---------------------------------------------------------------------------


@router.post("/runs/{run_id}/samples/fetch-worklist", response_class=HTMLResponse)
async def import_worklist_samples(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
    worklist_id: str = "",
    context: str = "",
) -> Response:
    """POST /runs/{run_id}/samples/fetch-worklist — import samples from a worklist."""
    run_id = run.id

    if ctx.sample_api_config_repo is None:
        return _messages_only(request, [{"text": "Sample API is not configured.", "kind": "error"}])

    if not worklist_id:
        return _messages_only(request, [{"text": "No worklist selected.", "kind": "error"}])

    from ..services.sample_api import fetch_worklist_samples, parse_api_samples

    api_config = ctx.sample_api_config
    if not api_config.enabled or not api_config.base_url:
        return _messages_only(request, [{"text": "Sample API is not enabled or base URL is not configured.", "kind": "error"}])

    success, message, raw_data = fetch_worklist_samples(api_config, worklist_id)
    if not success:
        return _messages_only(request, [{"text": f"Failed to fetch worklist samples: {message}", "kind": "error"}])

    api_samples = parse_api_samples(raw_data, api_config)
    if not api_samples:
        return _messages_only(request, [{"text": "No valid samples found in worklist.", "kind": "warning"}])

    existing_sample_ids = {s.sample_id for s in run.samples}
    added_count = 0
    skipped_duplicates: list[str] = []
    new_samples = []

    for api_sample in api_samples:
        sample_id = api_sample.get("sample_id", "")
        if not sample_id:
            continue
        if sample_id in existing_sample_ids:
            skipped_duplicates.append(sample_id)
            continue

        existing_sample_ids.add(sample_id)
        sample = Sample(
            sample_id=sample_id,
            test_id=api_sample.get("test_id", ""),
            worksheet_id=api_sample.get("worksheet_id", worklist_id),
            lanes=[1],
        )

        idx1_seq = api_sample.get("index1_sequence", "")
        if idx1_seq:
            index1 = Index(
                name=api_sample.get("index1_name", ""),
                sequence=idx1_seq,
                index_type=IndexType.I7,
            )
            sample.assign_index1(index1)
            sample.index_kit_name = api_sample.get("index_pair_name", "API")

        idx2_seq = api_sample.get("index2_sequence", "")
        if idx2_seq:
            index2 = Index(
                name=api_sample.get("index2_name", ""),
                sequence=idx2_seq,
                index_type=IndexType.I5,
            )
            sample.assign_index2(index2)
            if not sample.index_kit_name:
                sample.index_kit_name = api_sample.get("index_pair_name", "API")

        _update_override_cycles(sample, run)

        new_samples.append(sample)
        added_count += 1

    if added_count > 0:
        with saving_run(run, ctx, request):
            for sample in new_samples:
                run.add_sample(sample)
        audit(
            "sample.worklist_imported",
            actor=get_username(request),
            target=run_id,
            worklist_id=worklist_id,
            added_count=added_count,
            skipped_duplicates_count=len(skipped_duplicates),
        )

    messages = []
    if added_count == 0:
        messages.append({"text": "No new samples added from worklist.", "kind": "warning"})
    elif added_count == 1:
        messages.append({"text": "Added 1 sample from worklist.", "kind": "success"})
    else:
        messages.append({"text": f"Added {added_count} samples from worklist.", "kind": "success"})

    if skipped_duplicates:
        messages.append({"text": f"Skipped {len(skipped_duplicates)} duplicate(s) already in run.", "kind": "warning"})

    return _render_sample_section(run, request, ctx)


@router.post("/runs/{run_id}/samples/assign-indexes-bulk", response_class=HTMLResponse)
async def assign_indexes_bulk(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/samples/assign-indexes-bulk — assign indexes to consecutive samples."""
    run_id = run.id

    form = await request.form()
    start_sample_id = form.get("start_sample_id", "")
    indexes_json = form.get("indexes_json", "")
    context = form.get("context", "")

    if not start_sample_id:
        return Response("Missing start_sample_id", status_code=400)
    if not indexes_json:
        return Response("Missing indexes_json", status_code=400)

    try:
        indexes_data = json.loads(indexes_json)
    except json.JSONDecodeError:
        return Response("Invalid request data", status_code=400)
    if not isinstance(indexes_data, list):
        return Response("Invalid request data", status_code=400)

    start_idx = None
    for i, sample in enumerate(run.samples):
        if sample.id == start_sample_id:
            start_idx = i
            break

    if start_idx is None:
        return Response("Start sample not found", status_code=404)

    # Validate and resolve all index assignments before applying changes —
    # an invalid pair downstream must not leave the run half-updated.
    resolved_assignments = []
    for idx_data in indexes_data:
        if not isinstance(idx_data, dict):
            return Response("Invalid request data", status_code=400)

        idx_id = idx_data.get("id")
        idx_type = idx_data.get("type", "pair")

        if not isinstance(idx_id, str) or not idx_id:
            return Response("Invalid request data", status_code=400)

        if idx_type == "pair":
            index_pair, kit = ctx.index_kit_repo.find_index_pair_with_kit(idx_id)
            if not index_pair or not kit:
                return Response("Index pair not found", status_code=404)
            resolved_assignments.append((idx_type, index_pair, kit))
        elif idx_type in ("i7", "i5"):
            index, kit = ctx.index_kit_repo.find_index_with_kit(idx_id)
            if not index or not kit:
                return Response("Index not found", status_code=404)
            resolved_assignments.append((idx_type, index, kit))
        else:
            return Response(f"Invalid index type: {idx_type}", status_code=400)

    with saving_run(run, ctx, request):
        for offset, (idx_type, resolved_index, kit) in enumerate(resolved_assignments):
            sample_idx = start_idx + offset
            if sample_idx >= len(run.samples):
                break

            sample = run.samples[sample_idx]

            if idx_type == "pair":
                run.assign_index_pair_to_sample(sample.id, resolved_index)
            elif idx_type == "i7":
                run.assign_index1_to_sample(sample.id, resolved_index)
            elif idx_type == "i5":
                run.assign_index2_to_sample(sample.id, resolved_index)
            sample.index_kit_name = kit.name
            _apply_kit_defaults(sample, kit)
            _update_override_cycles(sample, run)

    audit(
        "sample.bulk_index_assigned",
        actor=get_username(request),
        target=run_id,
        sample_count=min(len(resolved_assignments), len(run.samples) - start_idx),
        kit_name=kit.name if resolved_assignments else "",
    )

    return _render_sample_section(run, request, ctx)


@router.post("/runs/{run_id}/samples/assign-index-to-selected", response_class=HTMLResponse)
async def assign_index_to_selected(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/samples/assign-index-to-selected — assign one index to selected samples."""
    run_id = run.id
    form = await request.form()
    sample_ids_json = form.get("sample_ids", "")
    index_pair_id = form.get("index_pair_id", "")
    index_id = form.get("index_id", "")
    index_type = form.get("index_type", "")
    context = form.get("context", "")

    if not sample_ids_json:
        return Response("Missing sample_ids", status_code=400)

    try:
        sample_ids = json.loads(sample_ids_json)
    except json.JSONDecodeError:
        return Response("Invalid sample_ids format", status_code=400)

    kit = None
    index_pair = None
    index = None

    if index_pair_id:
        index_pair, kit = ctx.index_kit_repo.find_index_pair_with_kit(index_pair_id)
        if not index_pair:
            return Response("Index pair not found", status_code=404)
    elif index_id and index_type:
        index, kit = ctx.index_kit_repo.find_index_with_kit(index_id)
        if not index:
            return Response("Index not found", status_code=404)
    else:
        return Response("Missing index_pair_id or index_id/index_type", status_code=400)

    with saving_run(run, ctx, request):
        for sid in sample_ids:
            sample = run.get_sample(sid)
            if not sample:
                continue

            if index_pair:
                run.assign_index_pair_to_sample(sample.id, index_pair)
            elif index_type == "i7":
                run.assign_index1_to_sample(sample.id, index)
            elif index_type == "i5":
                run.assign_index2_to_sample(sample.id, index)

            sample.index_kit_name = kit.name
            _apply_kit_defaults(sample, kit)
            _update_override_cycles(sample, run)

    audit(
        "sample.bulk_index_assigned_selected",
        actor=get_username(request),
        target=run_id,
        sample_count=len(sample_ids),
    )

    return _render_sample_section(run, request, ctx)


@router.post("/runs/{run_id}/samples/set-lanes", response_class=HTMLResponse)
async def set_lanes_bulk(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/samples/set-lanes — set lanes for selected samples."""
    run_id = run.id

    form = await request.form()
    sample_ids_json = form.get("sample_ids", "[]")
    lanes_json = form.get("lanes", "[]")

    try:
        sample_ids = json.loads(sample_ids_json)
        lanes = json.loads(lanes_json)
    except json.JSONDecodeError:
        return Response("Invalid request data", status_code=400)
    if not isinstance(sample_ids, list):
        return Response("Invalid request data", status_code=400)

    max_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
    normalized_lanes = _normalize_lane_selection(lanes, max_lanes)
    if normalized_lanes is None:
        return Response(
            f"Invalid lane selection. Use lane numbers between 1 and {max_lanes}.",
            status_code=400,
        )

    selected_ids = {str(sample_id) for sample_id in sample_ids}

    with saving_run(run, ctx, request):
        for sample in run.samples:
            if sample.id in selected_ids:
                sample.lanes = normalized_lanes

    audit(
        "sample.bulk_lanes_set",
        actor=get_username(request),
        target=run_id,
        sample_count=len(selected_ids),
        lanes=",".join(str(l) for l in normalized_lanes),
    )

    return _render_sample_section(run, request, ctx)


@router.post("/runs/{run_id}/samples/set-mismatches", response_class=HTMLResponse)
async def set_mismatches_bulk(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/samples/set-mismatches — set barcode mismatches for selected samples."""
    run_id = run.id

    form = await request.form()
    sample_ids_json = form.get("sample_ids", "[]")
    mismatch_index1_str = form.get("mismatch_index1", "")
    mismatch_index2_str = form.get("mismatch_index2", "")

    try:
        sample_ids = json.loads(sample_ids_json)
    except json.JSONDecodeError:
        return Response("Invalid request data", status_code=400)

    mismatch_index1 = None
    if mismatch_index1_str.strip():
        try:
            mismatch_index1 = max(0, min(3, int(mismatch_index1_str)))
        except ValueError:
            pass

    mismatch_index2 = None
    if mismatch_index2_str.strip():
        try:
            mismatch_index2 = max(0, min(3, int(mismatch_index2_str)))
        except ValueError:
            pass

    with saving_run(run, ctx, request):
        for sample in run.samples:
            if sample.id in sample_ids:
                sample.barcode_mismatches_index1 = mismatch_index1
                sample.barcode_mismatches_index2 = mismatch_index2

    audit(
        "sample.bulk_mismatches_set",
        actor=get_username(request),
        target=run_id,
        sample_count=len(sample_ids),
        mismatch_index1=mismatch_index1,
        mismatch_index2=mismatch_index2,
    )

    return _render_sample_section(run, request, ctx)


@router.post("/runs/{run_id}/samples/set-override-cycles", response_class=HTMLResponse)
async def set_override_cycles_bulk(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/samples/set-override-cycles — set override cycles for selected samples."""
    run_id = run.id

    form = await request.form()
    sample_ids_json = form.get("sample_ids", "[]")
    override_cycles_str = form.get("override_cycles", "")

    try:
        sample_ids = json.loads(sample_ids_json)
    except json.JSONDecodeError:
        return Response("Invalid request data", status_code=400)

    # Length-limit defensively — the model regex restricts characters but
    # a multi-megabyte all-`Y` string would still match and balloon the doc.
    override_cycles = sanitize_string(override_cycles_str, 256) if override_cycles_str else None
    override_cycles = override_cycles or None  # empty string -> None for the recalculate path

    with saving_run(run, ctx, request):
        for sample in run.samples:
            if sample.id in sample_ids:
                if override_cycles:
                    sample.override_cycles = override_cycles
                else:
                    if run.run_cycles and sample.has_index:
                        sample.override_cycles = CycleCalculator.calculate_override_cycles(
                            sample, run.run_cycles
                        )
                    else:
                        sample.override_cycles = None

    audit(
        "sample.bulk_override_cycles_set",
        actor=get_username(request),
        target=run_id,
        sample_count=len(sample_ids),
        override_cycles=override_cycles or "auto",
    )

    return _render_sample_section(run, request, ctx)


@router.post("/runs/{run_id}/samples/set-test-id", response_class=HTMLResponse)
async def set_test_id_bulk(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/samples/set-test-id — set test ID for selected samples."""
    run_id = run.id

    form = await request.form()
    sample_ids_json = form.get("sample_ids", "[]")
    test_id_str = form.get("test_id", "")

    try:
        sample_ids = json.loads(sample_ids_json)
    except json.JSONDecodeError:
        return Response("Invalid request data", status_code=400)

    test_id = sanitize_string(test_id_str, 256)

    with saving_run(run, ctx, request):
        for sample in run.samples:
            if sample.id in sample_ids:
                sample.test_id = test_id

    audit(
        "sample.bulk_test_id_set",
        actor=get_username(request),
        target=run_id,
        sample_count=len(sample_ids),
        test_id=test_id,
    )

    return _render_sample_section(run, request, ctx)


@router.post("/runs/{run_id}/samples/bulk-delete", response_class=HTMLResponse)
async def delete_samples_bulk(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/samples/bulk-delete — delete multiple selected samples."""
    run_id = run.id

    form = await request.form()
    sample_ids_json = form.get("sample_ids", "[]")

    try:
        sample_ids = json.loads(sample_ids_json)
    except json.JSONDecodeError:
        return Response("Invalid request data", status_code=400)

    deleted_ids = [sid for sid in sample_ids if run.get_sample(str(sid))]
    with saving_run(run, ctx, request):
        for sample_id in sample_ids:
            run.remove_sample(sample_id)

    audit(
        "sample.bulk_deleted",
        actor=get_username(request),
        target=run_id,
        sample_count=len(deleted_ids),
    )

    num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
    return render(request, "wizard/_sample_table.html", {
        "run": run,
        "show_drop_zones": True,
        "index_kits": None,
        "num_lanes": num_lanes,
        "show_bulk_actions": True,
        "context": "",
        "test_profiles": None,
        "editable": True,
    })


# ---------------------------------------------------------------------------
# Per-sample handlers — use {sample_id} path param (was {id})
# ---------------------------------------------------------------------------


@router.delete("/runs/{run_id}/samples/{sample_id}", response_class=HTMLResponse)
def delete_sample(
    request: Request,
    sample_id: str,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
    context: str = "",
) -> Response:
    """DELETE /runs/{run_id}/samples/{sample_id} — delete a single sample."""
    run_id = run.id

    with saving_run(run, ctx, request):
        run.remove_sample(sample_id)
    audit(
        "sample.deleted",
        actor=get_username(request),
        target=run_id,
        sample_id=sample_id,
    )

    return _render_sample_section(run, request, ctx)


@router.post("/runs/{run_id}/samples/{sample_id}", response_class=HTMLResponse)
async def update_sample(
    request: Request,
    sample_id: str,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/samples/{sample_id} — update an existing sample."""
    run_id = run.id
    sample_id_path = sample_id
    form = await request.form()
    sample_id_field = form.get("sample_id", "")
    sample_name = form.get("sample_name", "")
    project = form.get("project", "")

    # Reject blank sample_id before any mutation — mirrors add_sample.
    # Blanking sample_id would silently break demultiplexing for that sample.
    if not sample_id_field or not sample_id_field.strip():
        return Response("sample_id is required", status_code=400)
    sample_id_field = sanitize_string(sample_id_field, 256)
    sample_name = sanitize_string(sample_name, 256)
    project = sanitize_string(project, 256)

    sample = run.get_sample(sample_id_path)

    if sample:
        with saving_run(run, ctx, request):
            sample.sample_id = sample_id_field
            sample.sample_name = sample_name
            sample.project = project
        audit(
            "sample.updated",
            actor=get_username(request),
            target=run_id,
            sample_id=sample.id,
        )
        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        return render(request, "wizard/_sample_row.html", {
            "sample": sample,
            "run_id": run_id,
            "run_cycles": run.run_cycles,
            "show_drop_zones": False,
            "show_i5_column": True,
            "num_lanes": num_lanes,
            "show_bulk_actions": True,
            "context": "",
            "editable": True,
            "show_checkboxes": None,
        })

    return Response("")


@router.post("/runs/{run_id}/samples/{sample_id}/assign-index", response_class=HTMLResponse)
async def assign_index(
    request: Request,
    sample_id: str,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/samples/{sample_id}/assign-index — assign an index via drag-drop."""
    run_id = run.id
    sample_id_path = sample_id
    form = await request.form()
    index_pair_id = form.get("index_pair_id", "")
    index_id = form.get("index_id", "")
    index_type = form.get("index_type", "")
    context = form.get("context", "") or request.query_params.get("context", "")

    sample = run.get_sample(sample_id_path)
    if not sample:
        return Response("Sample not found", status_code=404)

    kit = None
    if index_pair_id:
        index_pair, kit = ctx.index_kit_repo.find_index_pair_with_kit(index_pair_id)
        if not index_pair:
            return Response("Index pair not found", status_code=404)

        with saving_run(run, ctx, request):
            run.assign_index_pair_to_sample(sample.id, index_pair)
            sample.index_kit_name = kit.name
            _apply_kit_defaults(sample, kit)
            _update_override_cycles(sample, run)
    elif index_id and index_type:
        index, kit = ctx.index_kit_repo.find_index_with_kit(index_id)
        if not index:
            return Response("Index not found", status_code=404)

        # Validate index_type before entering saving_run — a return inside
        # the with block would trigger the else clause and save a touched run.
        if index_type not in ("i7", "i5"):
            return Response(f"Invalid index type: {index_type}", status_code=400)

        with saving_run(run, ctx, request):
            if index_type == "i7":
                run.assign_index1_to_sample(sample.id, index)
            else:
                run.assign_index2_to_sample(sample.id, index)
            sample.index_kit_name = kit.name
            _apply_kit_defaults(sample, kit)
            _update_override_cycles(sample, run)
    else:
        return Response("Missing index_pair_id or index_id/index_type", status_code=400)

    audit(
        "sample.index.assigned",
        actor=get_username(request),
        target=run_id,
        sample_id=sample_id_path,
        index_type="pair" if index_pair_id else index_type,
        kit_name=kit.name if kit else "",
    )

    num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
    return render(request, "wizard/_sample_row.html", {
        "sample": sample,
        "run_id": run_id,
        "run_cycles": run.run_cycles,
        "show_drop_zones": True,
        "show_i5_column": True,
        "num_lanes": num_lanes,
        "show_bulk_actions": True,
        "context": "",
        "editable": True,
        "show_checkboxes": None,
    })


@router.post("/runs/{run_id}/samples/{sample_id}/clear-index", response_class=HTMLResponse)
async def clear_index(
    request: Request,
    sample_id: str,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
    index_type: str = "",
    context: str = "",
) -> Response:
    """POST /runs/{run_id}/samples/{sample_id}/clear-index — clear assigned index(es)."""
    run_id = run.id
    sample_id_path = sample_id
    # The clear button uses GET-style query params even on POST (htmx default).

    sample = run.get_sample(sample_id_path)
    if sample:
        with saving_run(run, ctx, request):
            if index_type == "i7":
                run.clear_sample_index1(sample.id)
            elif index_type == "i5":
                run.clear_sample_index2(sample.id)
            else:
                run.clear_sample_index(sample.id)

        audit(
            "sample.index.cleared",
            actor=get_username(request),
            target=run_id,
            sample_id=sample.id,
            index_type=index_type,
        )
        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        return render(request, "wizard/_sample_row.html", {
            "sample": sample,
            "run_id": run_id,
            "run_cycles": run.run_cycles,
            "show_drop_zones": True,
            "show_i5_column": True,
            "num_lanes": num_lanes,
            "show_bulk_actions": True,
            "context": "",
            "editable": True,
            "show_checkboxes": None,
        })

    return Response("")


@router.post("/runs/{run_id}/samples/{sample_id}/settings", response_class=HTMLResponse)
async def update_sample_settings(
    request: Request,
    sample_id: str,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/samples/{sample_id}/settings — update override cycles + mismatches."""
    run_id = run.id
    sample_id_path = sample_id
    form = await request.form()
    override_cycles = form.get("override_cycles", "")
    barcode_mismatches_index1 = form.get("barcode_mismatches_index1", "")
    barcode_mismatches_index2 = form.get("barcode_mismatches_index2", "")

    sample = run.get_sample(sample_id_path)
    if not sample:
        return Response("Sample not found", status_code=404)

    override_cycles = sanitize_string(override_cycles, 256)

    bmi1 = None
    bmi1_str = barcode_mismatches_index1.strip()
    if bmi1_str:
        try:
            bmi1 = max(0, min(3, int(bmi1_str)))
        except ValueError:
            bmi1 = None

    bmi2 = None
    bmi2_str = barcode_mismatches_index2.strip()
    if bmi2_str:
        try:
            bmi2 = max(0, min(3, int(bmi2_str)))
        except ValueError:
            bmi2 = None

    with saving_run(run, ctx, request):
        if override_cycles:
            sample.override_cycles = override_cycles
        else:
            if run.run_cycles and sample.has_index:
                sample.override_cycles = CycleCalculator.calculate_override_cycles(
                    sample, run.run_cycles
                )
            else:
                sample.override_cycles = None

        sample.barcode_mismatches_index1 = bmi1
        sample.barcode_mismatches_index2 = bmi2

    audit(
        "sample.settings.updated",
        actor=get_username(request),
        target=run_id,
        sample_id=sample.id,
    )

    num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
    return render(request, "wizard/_sample_row.html", {
        "sample": sample,
        "run_id": run_id,
        "run_cycles": run.run_cycles,
        "show_drop_zones": True,
        "show_i5_column": True,
        "num_lanes": num_lanes,
        "show_bulk_actions": True,
        "context": "",
        "editable": True,
        "show_checkboxes": None,
    })
