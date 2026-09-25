"""Sample management routes.

Migrated from legacy register(app, ctx) closure pattern to APIRouter +
Depends(get_editable_run) + with saving_run(...).
"""

import json
import logging
from dataclasses import dataclass
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.responses import HTMLResponse, Response

from ..context import AppContext
from ..data.instruments import get_lanes_for_flowcell
from ..models.index import Index, IndexKit, IndexType
from ..models.sample import Sample
from ..models import sequencing_run as sequencing_run_module
from ..models.sequencing_run import SequencingRun
from ..services.audit_log import audit
from ..services.cycle_calculator import CycleCalculator
from ..services.index_fill import build_fill_plan
from ..services.paste_preview import build_paste_preview, repeated_sample_ids
from ..services.sample_parser import parse_pasted_samples, read_pasted_samples
from ..templating import render, templates
from .dependencies import get_ctx, get_editable_run, saving_run
from .utils import UploadTooLargeError, get_username, read_upload_capped, sanitize_string

logger = logging.getLogger(__name__)


router = APIRouter(tags=["samples"])


# ---------------------------------------------------------------------------
# Module-level helpers (previously closures inside register())
# ---------------------------------------------------------------------------


def _render_sample_section(
    run,
    request: Request,
    ctx: AppContext,
    *,
    messages: Optional[list[dict]] = None,
) -> HTMLResponse:
    """Render the run-edit page's sample section (paste box + index panel + table).

    Used by mutation handlers that need to refresh the inline UI after
    a sample is added/removed/edited. The new section HTML re-targets
    #sample-section outerHTML.

    If ``messages`` is provided, an out-of-band fragment targeting
    ``#error-banner`` is prepended so the user sees toast-style feedback
    (e.g. duplicate-skip counts during a worklist import) alongside the
    refreshed section. The handler is responsible for choosing kinds —
    "success" / "warning" / "error".
    """
    num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
    is_editable = run.status.value == "draft"
    sample_api_cfg = ctx.sample_api_config
    sample_api_enabled = bool(sample_api_cfg and sample_api_cfg.enabled and sample_api_cfg.base_url)
    index_kits = ctx.index_kit_repo.list_all() if ctx.index_kit_repo else []
    test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []

    section_html = templates.env.get_template("runs/_sample_section.html").render(
        run=run, index_kits=index_kits, test_profiles=test_profiles,
        num_lanes=num_lanes, is_editable=is_editable,
        sample_api_enabled=sample_api_enabled, oob=False,
    )
    body = section_html
    if messages:
        msg_html = templates.env.get_template("_messages.html").render(messages=messages)
        # Wrap the messages fragment with the OOB target so HTMX swaps it
        # into the persistent #error-banner slot in _app_shell.html.
        oob_html = (
            f'<div id="error-banner" hx-swap-oob="innerHTML">{msg_html}</div>'
        )
        body = oob_html + section_html
    return HTMLResponse(body, headers={"Cache-Control": "no-store"})


def _messages_only(request, messages) -> HTMLResponse:
    """Render the _messages.html partial as the entire response."""
    html = templates.env.get_template("_messages.html").render(messages=messages)
    return HTMLResponse(html, headers={"Cache-Control": "no-store"})


def _render_sample_row(
    request: Request,
    sample: Sample,
    run: SequencingRun,
    *,
    show_drop_zones: bool,
) -> HTMLResponse:
    """Render one ``wizard/_sample_row.html`` fragment with the canonical
    kwarg shape used after a per-sample mutation.

    Previously this dict appeared verbatim in five handlers; a new template
    parameter (e.g. when a new column ships) had to be added in each. The
    only per-callsite axis was ``show_drop_zones`` (false on the initial
    add/update, true after an index assign/clear).
    """
    num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
    return render(request, "wizard/_sample_row.html", {
        "sample": sample,
        "run_id": run.id,
        "run_cycles": run.run_cycles,
        "show_drop_zones": show_drop_zones,
        "show_i5_column": True,
        "num_lanes": num_lanes,
        "show_bulk_actions": True,
        "context": "",
        "editable": True,
        "show_checkboxes": None,
    })



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


_MAX_PASTE_CHARS = 10 * 1024 * 1024


@dataclass
class _PasteInput:
    """What an Add-samples form sent: the text, and the picked lanes and test."""
    text: str
    lanes: list[int]
    default_test: str
    file_name: str = ""


def _test_types(ctx: AppContext) -> set[str]:
    repo = ctx.test_profile_repo
    return {tp.test_type for tp in repo.list_all()} if repo else set()


async def _read_paste_input(
    request: Request, run: SequencingRun, ctx: AppContext,
) -> tuple[Optional[_PasteInput], str]:
    """Read an Add-samples form (preview or add). Returns (input, "") or
    (None, message) for a 400. Saves nothing.

    Lanes: at least one, each within the flowcell — an empty choice is an
    error, never "all lanes". The default test must be empty or a known
    test profile.
    """
    form = await request.form()

    file_name = ""
    sample_file = form.get("sample_file")
    if sample_file and hasattr(sample_file, "read") and sample_file.filename:
        # Stream-read in bounded chunks so a multi-GB POST can't exhaust
        # memory before the size check fires (the index-kit upload path uses
        # the same shared helper).
        try:
            raw_bytes = await read_upload_capped(sample_file, _MAX_PASTE_CHARS)
        except UploadTooLargeError:
            return None, "File too large (max 10 MB)"
        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return None, "File must be UTF-8 encoded"
        file_name = sanitize_string(sample_file.filename, 256)
    else:
        text = form.get("paste_data", "")
        # Mirror the 10 MB cap from the file-upload branch — without this an
        # authenticated user can post unbounded paste_data and balloon the
        # run document past MongoDB's 16 MB BSON limit on save.
        if len(text) > _MAX_PASTE_CHARS:
            return None, "Pasted data too large (max 10 MB)"

    max_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
    lanes = _normalize_lane_selection(form.getlist("lanes"), max_lanes)
    if lanes is None:
        return None, f"Invalid lane selection. Use lane numbers between 1 and {max_lanes}."
    if not lanes:
        return None, "Pick at least one lane for the new samples."

    default_test = sanitize_string(form.get("default_test_id", ""), 256)
    if default_test and default_test not in _test_types(ctx):
        return None, f'No test called "{default_test}".'

    return _PasteInput(text=text, lanes=lanes, default_test=default_test, file_name=file_name), ""


def _name_list(ids: list[str], limit: int = 10) -> str:
    """'A, B, C' — the first ``limit`` names, then 'and N more'."""
    shown = ", ".join(ids[:limit])
    return f"{shown} and {len(ids) - limit} more" if len(ids) > limit else shown


def _lane_words(lanes: list[int]) -> str:
    return f"lane {lanes[0]}" if len(lanes) == 1 else "lanes " + ", ".join(str(n) for n in lanes)


def _parse_sample_ids(raw: str) -> Optional[list[str]]:
    """Parse a ``sample_ids`` form field as JSON and validate its shape.

    Returns the list of sample ID strings, or ``None`` if ``raw`` is not
    valid JSON, or the parsed value is not a JSON array of strings (e.g.
    ``null``, an object, or an array containing a non-string element).
    """
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        return None
    return parsed


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

    return _render_sample_row(request, sample, run, show_drop_zones=False)


@router.post("/runs/{run_id}/samples/bulk", response_class=HTMLResponse)
async def add_bulk_samples(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
    context: str = "",
) -> Response:
    """POST /runs/{run_id}/samples/bulk — add multiple samples from paste/file."""
    run_id = run.id

    paste, error = await _read_paste_input(request, run, ctx)
    if paste is None:
        return Response(error, status_code=400)

    try:
        parsed = parse_pasted_samples(paste.text)
    except ValueError as e:
        # Reject the whole import — silent partial drops would land
        # patient samples in the Undetermined bucket. Surface the parse
        # error as a banner so the operator can fix the source and retry.
        return _render_sample_section(
            run, request, ctx,
            messages=[{"text": f"Bulk import rejected: {e}", "kind": "error"}],
        )

    # An ID twice in one paste: we can't tell which row is right, so the
    # whole paste is refused (the preview shows these rows in red).
    repeated = repeated_sample_ids(parsed)
    if repeated:
        return _render_sample_section(
            run, request, ctx,
            messages=[{
                "text": (
                    "Bulk import rejected: these sample IDs appear more than once "
                    f"in the paste: {_name_list(repeated)}. Nothing was added."
                ),
                "kind": "error",
            }],
        )

    existing_sample_ids = {s.sample_id for s in run.samples}
    skipped_duplicates: list[str] = []
    new_samples = []
    for ps in parsed:
        if ps.sample_id in existing_sample_ids:
            skipped_duplicates.append(ps.sample_id)
            continue
        sample = Sample(
            sample_id=ps.sample_id,
            test_id=ps.test_id or paste.default_test,
            lanes=list(paste.lanes),
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
    added_count = len(new_samples)

    # Refuse before mutating if the additions would push the run past the
    # per-run cap (the model's add_sample backstop would otherwise raise
    # mid-loop and surface as a 500). Surface a clean banner instead.
    cap = sequencing_run_module.MAX_SAMPLES_PER_RUN
    if len(run.samples) + len(new_samples) > cap:
        return _render_sample_section(
            run, request, ctx,
            messages=[{
                "text": (
                    f"Bulk import rejected: a run accepts a maximum of {cap} "
                    f"samples (run already has {len(run.samples)})."
                ),
                "kind": "error",
            }],
        )

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
            lanes=",".join(str(n) for n in paste.lanes),
            default_test_id=paste.default_test,
        )

    # Surface per-import feedback so skips are never silent.
    messages: list[dict] = []
    if added_count:
        noun = "sample" if added_count == 1 else "samples"
        messages.append({
            "text": f"Added {added_count} {noun} to {_lane_words(paste.lanes)}.",
            "kind": "success",
        })
    elif not parsed:
        messages.append({"text": "No samples found in input.", "kind": "warning"})
    if skipped_duplicates:
        messages.append({
            "text": (
                f"Skipped {len(skipped_duplicates)} already in the run: "
                f"{_name_list(skipped_duplicates)}."
            ),
            "kind": "warning",
        })

    return _render_sample_section(run, request, ctx, messages=messages or None)


# Registered before POST /runs/{run_id}/samples/{sample_id}, which would
# otherwise take "preview" as a sample id.
@router.post("/runs/{run_id}/samples/preview", response_class=HTMLResponse)
async def preview_paste(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/samples/preview — show what a paste would add.

    Saves nothing. Reads with the same parser as /samples/bulk; the preview's
    Add form sends the same text back there, which re-applies every rule.
    """
    paste, error = await _read_paste_input(request, run, ctx)
    if paste is None:
        return Response(error, status_code=400)

    test_profiles = ctx.test_profile_repo.list_all() if ctx.test_profile_repo else []
    cap = sequencing_run_module.MAX_SAMPLES_PER_RUN
    preview, read_error = None, ""
    try:
        read = read_pasted_samples(paste.text)
    except ValueError as e:
        read_error = str(e)
    else:
        preview = build_paste_preview(
            read,
            existing_ids={s.sample_id for s in run.samples},
            test_types={tp.test_type for tp in test_profiles},
            default_test=paste.default_test,
            room=cap - len(run.samples),
        )

    return render(request, "runs/_paste_preview.html", {
        "run": run,
        "paste": paste,
        "preview": preview,
        "read_error": read_error,
        "line_count": len(paste.text.splitlines()),
        "cap": cap,
        "test_profiles": test_profiles,
        "num_lanes": get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type),
    })


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

    try:
        api_samples = parse_api_samples(raw_data, api_config)
    except ValueError as e:
        # parse_api_samples raises if any LIMS row is missing sample_id —
        # reject the whole import rather than silently routing patient
        # reads to Undetermined.
        return _messages_only(request, [{"text": f"Worklist import rejected: {e}", "kind": "error"}])

    if not api_samples:
        return _messages_only(request, [{"text": "No valid samples found in worklist.", "kind": "warning"}])

    existing_sample_ids = {s.sample_id for s in run.samples}
    added_count = 0
    skipped_duplicates: list[str] = []
    new_samples = []

    for api_sample in api_samples:
        sample_id = api_sample.get("sample_id", "")
        # parse_api_samples guarantees a non-empty sample_id; this is
        # defensive against a future code path that bypasses the parser.
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

    cap = sequencing_run_module.MAX_SAMPLES_PER_RUN
    if len(run.samples) + len(new_samples) > cap:
        return _messages_only(request, [{
            "text": (
                f"Worklist import rejected: a run accepts a maximum of {cap} "
                f"samples (run already has {len(run.samples)})."
            ),
            "kind": "error",
        }])

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

    messages: list[dict] = []
    if added_count == 0:
        messages.append({"text": "No new samples added from worklist.", "kind": "warning"})
    elif added_count == 1:
        messages.append({"text": "Added 1 sample from worklist.", "kind": "success"})
    else:
        messages.append({"text": f"Added {added_count} samples from worklist.", "kind": "success"})

    if skipped_duplicates:
        messages.append({"text": f"Skipped {len(skipped_duplicates)} duplicate(s) already in run.", "kind": "warning"})

    return _render_sample_section(run, request, ctx, messages=messages)


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
        return Response("Invalid indexes_json: not valid JSON", status_code=400)
    if not isinstance(indexes_data, list):
        return Response("Invalid indexes_json: expected a JSON array", status_code=400)

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
            return Response("Invalid indexes_json entry: expected an object", status_code=400)

        idx_id = idx_data.get("id")
        idx_type = idx_data.get("type", "pair")

        if not isinstance(idx_id, str) or not idx_id:
            return Response("Invalid indexes_json entry: missing 'id'", status_code=400)

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


def _index_fill_plan(form, run: SequencingRun, ctx: AppContext):
    """(plan, "") or (None, message for a 400)."""
    kit_id = sanitize_string(form.get("selected_kit", ""), 512)
    start_id = sanitize_string(form.get("start_id", ""), 512)
    kit = ctx.index_kit_repo.get_by_kit_id(kit_id) if kit_id else None
    if kit is None:
        return None, "Pick an index kit first."
    try:
        return build_fill_plan(run, kit, start_id), ""
    except ValueError:
        return None, "That start index is not in this kit."


@router.post("/runs/{run_id}/index-fill/preview", response_class=HTMLResponse)
async def preview_index_fill(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/index-fill/preview — what "Fill in order" would
    assign. Nothing is saved."""
    plan, error = _index_fill_plan(await request.form(), run, ctx)
    if error:
        return Response(error, status_code=400)
    return render(request, "runs/_index_fill_preview.html", {"run": run, "plan": plan})


@router.post("/runs/{run_id}/index-fill", response_class=HTMLResponse)
async def apply_index_fill(
    request: Request,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/index-fill — assign the previewed plan. Refused
    (409) unless the plan rebuilt now is the one the preview showed."""
    form = await request.form()
    plan, error = _index_fill_plan(form, run, ctx)
    if error:
        return Response(error, status_code=400)
    if not plan.can_apply:
        return Response(plan.problem or "Nothing to fill.", status_code=400)
    if plan.signature() != form.get("plan", ""):
        return Response(
            "The run or kit changed since the preview. Preview again.", status_code=409
        )

    with saving_run(run, ctx, request):
        for row in plan.rows:
            if plan.mode == "pair":
                run.assign_index_pair_to_sample(row.sample_id, row.entry.index)
            else:
                run.assign_index1_to_sample(row.sample_id, row.entry.index)
            sample = run.get_sample(row.sample_id)
            sample.index_kit_name = plan.kit.name
            _apply_kit_defaults(sample, plan.kit)
            _update_override_cycles(sample, run)

    audit(
        "sample.index_filled_in_order",
        actor=get_username(request),
        target=run.id,
        kit_name=plan.kit.name,
        kit_version=plan.kit.version,
        start=plan.start.name,
        sample_count=len(plan.rows),
    )
    return _render_sample_section(run, request, ctx, messages=[{
        "text": (
            f"Gave indexes to {len(plan.rows)} samples from {plan.kit.name}, "
            f"starting at {plan.start.name}."
        ),
        "kind": "success",
    }])


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

    sample_ids = _parse_sample_ids(sample_ids_json)
    if sample_ids is None:
        return Response("sample_ids must be a list of sample IDs", status_code=400)

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
        lanes = json.loads(lanes_json)
    except json.JSONDecodeError:
        return Response("Invalid sample_ids or lanes JSON", status_code=400)
    sample_ids = _parse_sample_ids(sample_ids_json)
    if sample_ids is None:
        return Response("sample_ids must be a list of sample IDs", status_code=400)

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

    sample_ids = _parse_sample_ids(sample_ids_json)
    if sample_ids is None:
        return Response("sample_ids must be a list of sample IDs", status_code=400)

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

    sample_ids = _parse_sample_ids(sample_ids_json)
    if sample_ids is None:
        return Response("sample_ids must be a list of sample IDs", status_code=400)

    # Length-limit defensively — the model regex restricts characters but
    # a multi-megabyte all-`Y` string would still match and balloon the doc.
    override_cycles = sanitize_string(override_cycles_str, 256) if override_cycles_str else None
    override_cycles = override_cycles or None  # empty string -> None for the recalculate path

    try:
        if override_cycles:
            # '*' is internal pattern shorthand; expand it to concrete cycle
            # counts against the run's declared cycles before storing, so the
            # value that ships in the Sample Sheet is valid BCL Convert
            # OverrideCycles. Raises (-> 400) if it cannot be resolved.
            override_cycles = CycleCalculator.expand_override_cycles(
                override_cycles, run.run_cycles
            )
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
    except ValueError as exc:
        # Sample model rejected an invariant violation; refuse the bulk save
        # so a single bad value does not invalidate every selected row.
        raise HTTPException(status_code=400, detail=str(exc))

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

    sample_ids = _parse_sample_ids(sample_ids_json)
    if sample_ids is None:
        return Response("sample_ids must be a list of sample IDs", status_code=400)

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

    sample_ids = _parse_sample_ids(sample_ids_json)
    if sample_ids is None:
        return Response("sample_ids must be a list of sample IDs", status_code=400)

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
    """POST /runs/{run_id}/samples/{sample_id} — update an existing sample.

    Partial update: each row input posts only its own field (HTMX default
    include behaviour). The handler updates exactly what was submitted —
    a key NOT present in the form is left untouched. Without the
    ``in form`` guards below, a request that posts only ``sample_id``
    would silently wipe ``sample_name`` and ``project`` on that row.
    """
    run_id = run.id
    sample_id_path = sample_id
    form = await request.form()

    has_sample_id = "sample_id" in form
    has_sample_name = "sample_name" in form
    has_project = "project" in form

    # Reject blank sample_id when it IS being updated — blanking it would
    # silently break demultiplexing for that sample.
    sample_id_field: str | None = None
    if has_sample_id:
        raw = form.get("sample_id", "")
        if not raw or not raw.strip():
            return Response("sample_id is required", status_code=400)
        sample_id_field = sanitize_string(raw, 256)

    sample_name = sanitize_string(form.get("sample_name", ""), 256) if has_sample_name else None
    project = sanitize_string(form.get("project", ""), 256) if has_project else None

    sample = run.get_sample(sample_id_path)

    if sample:
        with saving_run(run, ctx, request):
            if has_sample_id and sample_id_field is not None:
                sample.sample_id = sample_id_field
            if has_sample_name:
                sample.sample_name = sample_name
            if has_project:
                sample.project = project
        audit(
            "sample.updated",
            actor=get_username(request),
            target=run_id,
            sample_id=sample.id,
        )
        return _render_sample_row(request, sample, run, show_drop_zones=False)

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

    return _render_sample_row(request, sample, run, show_drop_zones=True)


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
        return _render_sample_row(request, sample, run, show_drop_zones=True)

    return Response("")


@router.post("/runs/{run_id}/samples/{sample_id}/settings", response_class=HTMLResponse)
async def update_sample_settings(
    request: Request,
    sample_id: str,
    run: SequencingRun = Depends(get_editable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /runs/{run_id}/samples/{sample_id}/settings — update override cycles + mismatches.

    Per-field partial update: each settings input on the row carries its own
    ``hx-post`` and lives outside any ``<form>`` (see
    ``templates/wizard/_sample_row.html`` and ``templates/runs/_sample_section.html``),
    so HTMX's default include behavior posts only the triggering element. The
    handler updates exactly that field; any setting *not* present in the
    submission is left untouched. A field that IS present but empty is treated
    as "clear/reset" (auto-recompute for override_cycles, ``None`` for the
    mismatch overrides). This prevents silent data loss across siblings.
    """
    run_id = run.id
    sample_id_path = sample_id
    form = await request.form()

    sample = run.get_sample(sample_id_path)
    if not sample:
        return Response("Sample not found", status_code=404)

    has_override = "override_cycles" in form
    has_bmi1 = "barcode_mismatches_index1" in form
    has_bmi2 = "barcode_mismatches_index2" in form

    override_cycles = sanitize_string(form.get("override_cycles", ""), 256) if has_override else None

    bmi1: Optional[int] = None
    if has_bmi1:
        bmi1_str = form.get("barcode_mismatches_index1", "").strip()
        if bmi1_str:
            try:
                bmi1 = max(0, min(3, int(bmi1_str)))
            except ValueError:
                bmi1 = None

    bmi2: Optional[int] = None
    if has_bmi2:
        bmi2_str = form.get("barcode_mismatches_index2", "").strip()
        if bmi2_str:
            try:
                bmi2 = max(0, min(3, int(bmi2_str)))
            except ValueError:
                bmi2 = None

    try:
        if has_override and override_cycles:
            # Expand the internal '*' wildcard to concrete cycle counts before
            # storing (see set_override_cycles_bulk). Raises (-> 400) if unresolvable.
            override_cycles = CycleCalculator.expand_override_cycles(
                override_cycles, run.run_cycles
            )
        with saving_run(run, ctx, request):
            if has_override:
                if override_cycles:
                    sample.override_cycles = override_cycles
                elif run.run_cycles and sample.has_index:
                    sample.override_cycles = CycleCalculator.calculate_override_cycles(
                        sample, run.run_cycles
                    )
                else:
                    sample.override_cycles = None
            if has_bmi1:
                sample.barcode_mismatches_index1 = bmi1
            if has_bmi2:
                sample.barcode_mismatches_index2 = bmi2
    except ValueError as exc:
        # Sample model rejected an invariant violation (e.g. malformed
        # override_cycles characters). Surface as a 400 so the run is not
        # persisted into an invalid state.
        raise HTTPException(status_code=400, detail=str(exc))

    audit(
        "sample.settings.updated",
        actor=get_username(request),
        target=run_id,
        sample_id=sample.id,
    )

    return _render_sample_row(request, sample, run, show_drop_zones=True)
