"""Sample management routes.

Migrated to Starlette ``Route(...)`` registration. Wizard FT components
are returned via ``ft_response`` because they have not yet been ported
to Jinja2 templates.
"""

import json
import logging

from fasthtml.common import Div, P
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from ..components.wizard import (
    AddSamplesNavigation,
    NewSamplesTableWizard,
    SampleRowWizard,
    SampleTableWizard,
    WizardNavigation,
    WorklistPreview,
    WorklistSelector,
)
from ..context import AppContext
from ..data.instruments import get_lanes_for_flowcell
from ..models.index import Index, IndexKit, IndexType
from ..models.sample import Sample
from ..services.cycle_calculator import CycleCalculator
from ..services.sample_parser import parse_pasted_samples
from ..templating import ft_response
from .utils import check_run_editable, get_username, sanitize_string

logger = logging.getLogger(__name__)


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


def register(app, ctx: AppContext) -> None:
    """Register sample routes on the parent Starlette app."""
    if not hasattr(app, "routes") or not isinstance(app.routes, list):
        raise TypeError(
            f"samples.register requires a Starlette-style app with a mutable "
            f"routes list, got {type(app).__name__}"
        )

    def _sample_table_with_nav(run):
        """Return sample table + step-2 navigation as an FT response.

        SampleTableWizard returns the table, WizardNavigation the OOB nav.
        Wrapping both in a Div keeps HTMX able to swap them as one fragment.
        """
        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        can_proceed = run.has_samples and run.all_samples_have_indexes
        return ft_response(
            Div(
                SampleTableWizard(run, show_drop_zones=True, num_lanes=num_lanes),
                WizardNavigation(2, run.id, can_proceed=can_proceed, oob=True),
            )
        )

    def _update_override_cycles(sample, run):
        """Recalculate override cycles for a sample from run configuration."""
        if run.run_cycles and sample.has_index:
            CycleCalculator.populate_index_override_patterns(sample, run.run_cycles)
            sample.override_cycles = CycleCalculator.calculate_override_cycles(
                sample, run.run_cycles
            )

    async def add_sample(request: Request) -> Response:
        """POST /runs/{run_id}/samples — add a single sample (legacy non-wizard form)."""
        run_id = request.path_params["run_id"]
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

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        sample = Sample(
            sample_id=sample_id,
            sample_name=sample_name,
            project=project,
            test_id=test_id,
            lanes=[1],
        )
        run.add_sample(sample)
        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)

        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        return ft_response(
            SampleRowWizard(sample, run_id, run.run_cycles, show_drop_zones=False, num_lanes=num_lanes)
        )

    async def add_bulk_samples(request: Request) -> Response:
        """POST /runs/{run_id}/samples/bulk — add multiple samples from paste/file."""
        run_id = request.path_params["run_id"]
        context = request.query_params.get("context", "")
        existing_ids = request.query_params.get("existing_ids", "")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

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

                run.add_sample(sample)
                added_count += 1

        if added_count > 0:
            run.touch(updated_by=get_username(request))
            ctx.run_repo.save(run)

        if context == "add_step1":
            messages = []

            if added_count == 0:
                if not parsed:
                    messages.append(P("No samples found in pasted data.", cls="warning-message"))
                else:
                    messages.append(P("No new samples added.", cls="warning-message"))
            elif added_count == 1:
                messages.append(P("Added 1 sample.", cls="success-message"))
            else:
                messages.append(P(f"Added {added_count} samples.", cls="success-message"))

            if skipped_duplicates:
                if len(skipped_duplicates) <= 3:
                    dup_list = ", ".join(skipped_duplicates)
                else:
                    dup_list = ", ".join(skipped_duplicates[:3]) + f" and {len(skipped_duplicates) - 3} more"
                messages.append(P(f"Skipped {len(skipped_duplicates)} duplicate(s) already in run: {dup_list}", cls="warning-message"))

            if skipped_within_paste:
                if len(skipped_within_paste) <= 3:
                    dup_list = ", ".join(skipped_within_paste)
                else:
                    dup_list = ", ".join(skipped_within_paste[:3]) + f" and {len(skipped_within_paste) - 3} more"
                messages.append(P(f"Skipped {len(skipped_within_paste)} duplicate(s) in pasted data: {dup_list}", cls="warning-message"))

            return ft_response(
                Div(
                    Div(*messages),
                    AddSamplesNavigation(1, run.id, can_proceed=run.has_samples, oob=True, existing_ids=existing_ids),
                )
            )

        return _sample_table_with_nav(run)

    def list_worklists(request: Request) -> Response:
        """GET /runs/{run_id}/samples/worklists — list available worklists."""
        run_id = request.path_params["run_id"]
        context = request.query_params.get("context", "")
        existing_ids = request.query_params.get("existing_ids", "")

        if ctx.sample_api_config_repo is None:
            return ft_response(P("Sample API is not configured.", cls="error-message"))

        from ..services.sample_api import fetch_worklists

        api_config = ctx.sample_api_config
        if not api_config.enabled or not api_config.base_url:
            return ft_response(P("Sample API is not enabled or base URL is not configured.", cls="error-message"))

        success, message, worklists = fetch_worklists(api_config)
        if not success:
            return ft_response(P(f"Failed to load worklists: {message}", cls="error-message"))

        return ft_response(WorklistSelector(run_id, worklists, context=context, existing_ids=existing_ids))

    def preview_worklist(request: Request) -> Response:
        """GET /runs/{run_id}/samples/preview-worklist — preview samples in a worklist."""
        worklist_id = request.query_params.get("worklist_id", "")

        if ctx.sample_api_config_repo is None:
            return ft_response(P("Sample API is not configured.", cls="error-message"))

        if not worklist_id:
            return ft_response(P("No worksheet selected.", cls="error-message"))

        from ..services.sample_api import fetch_worklist_samples

        api_config = ctx.sample_api_config
        if not api_config.enabled or not api_config.base_url:
            return ft_response(P("Sample API is not enabled or base URL is not configured.", cls="error-message"))

        success, message, raw_data = fetch_worklist_samples(api_config, worklist_id)
        if not success:
            return ft_response(P(f"Failed to fetch worksheet samples: {message}", cls="error-message"))

        return ft_response(WorklistPreview(raw_data, worklist_id))

    async def import_worklist_samples(request: Request) -> Response:
        """POST /runs/{run_id}/samples/fetch-worklist — import samples from a worklist."""
        run_id = request.path_params["run_id"]
        worklist_id = request.query_params.get("worklist_id", "")
        context = request.query_params.get("context", "")
        existing_ids = request.query_params.get("existing_ids", "")

        if ctx.sample_api_config_repo is None:
            return ft_response(P("Sample API is not configured.", cls="error-message"))

        if not worklist_id:
            return ft_response(P("No worklist selected.", cls="error-message"))

        from ..services.sample_api import fetch_worklist_samples, parse_api_samples

        api_config = ctx.sample_api_config
        if not api_config.enabled or not api_config.base_url:
            return ft_response(P("Sample API is not enabled or base URL is not configured.", cls="error-message"))

        success, message, raw_data = fetch_worklist_samples(api_config, worklist_id)
        if not success:
            return ft_response(P(f"Failed to fetch worklist samples: {message}", cls="error-message"))

        api_samples = parse_api_samples(raw_data, api_config)
        if not api_samples:
            return ft_response(P("No valid samples found in worklist.", cls="warning-message"))

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        existing_sample_ids = {s.sample_id for s in run.samples}
        added_count = 0
        skipped_duplicates: list[str] = []

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

            run.add_sample(sample)
            added_count += 1

        if added_count > 0:
            run.touch(updated_by=get_username(request))
            ctx.run_repo.save(run)

        messages = []
        if added_count == 0:
            messages.append(P("No new samples added from worklist.", cls="warning-message"))
        elif added_count == 1:
            messages.append(P("Added 1 sample from worklist.", cls="success-message"))
        else:
            messages.append(P(f"Added {added_count} samples from worklist.", cls="success-message"))

        if skipped_duplicates:
            messages.append(P(f"Skipped {len(skipped_duplicates)} duplicate(s) already in run.", cls="warning-message"))

        if context == "add_step1":
            return ft_response(
                Div(
                    Div(*messages),
                    AddSamplesNavigation(1, run.id, can_proceed=run.has_samples, oob=True, existing_ids=existing_ids),
                )
            )

        return _sample_table_with_nav(run)

    async def assign_indexes_bulk(request: Request) -> Response:
        """POST /runs/{run_id}/samples/assign-indexes-bulk — assign indexes to consecutive samples."""
        run_id = request.path_params["run_id"]

        form = await request.form()
        start_sample_id = form.get("start_sample_id", "")
        indexes_json = form.get("indexes_json", "")
        context = form.get("context", "")
        existing_ids = form.get("existing_ids", "")

        if not start_sample_id:
            return Response("Missing start_sample_id", status_code=400)
        if not indexes_json:
            return Response("Missing indexes_json", status_code=400)

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

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

        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)

        if context == "add_step2":
            existing_ids_set = (
                {sid.strip() for sid in existing_ids.split(",") if sid.strip()}
                if existing_ids else set()
            )
            new_samples = [s for s in run.samples if s.id not in existing_ids_set]
            return ft_response(
                NewSamplesTableWizard(run, new_samples, context=context, existing_ids=existing_ids)
            )

        return _sample_table_with_nav(run)

    async def assign_index_to_selected(request: Request) -> Response:
        """POST /runs/{run_id}/samples/assign-index-to-selected — assign one index to selected samples."""
        run_id = request.path_params["run_id"]
        form = await request.form()
        sample_ids_json = form.get("sample_ids", "")
        index_pair_id = form.get("index_pair_id", "")
        index_id = form.get("index_id", "")
        index_type = form.get("index_type", "")
        context = form.get("context", "")
        existing_ids = form.get("existing_ids", "")

        if not sample_ids_json:
            return Response("Missing sample_ids", status_code=400)

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

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

        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)

        if context == "add_step2":
            existing_ids_set = (
                {sid.strip() for sid in existing_ids.split(",") if sid.strip()}
                if existing_ids else set()
            )
            new_samples = [s for s in run.samples if s.id not in existing_ids_set]
            return ft_response(
                NewSamplesTableWizard(run, new_samples, context=context, existing_ids=existing_ids)
            )

        return _sample_table_with_nav(run)

    async def set_lanes_bulk(request: Request) -> Response:
        """POST /runs/{run_id}/samples/set-lanes — set lanes for selected samples."""
        run_id = request.path_params["run_id"]

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

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

        for sample in run.samples:
            if sample.id in selected_ids:
                sample.lanes = normalized_lanes

        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)

        return _sample_table_with_nav(run)

    async def set_mismatches_bulk(request: Request) -> Response:
        """POST /runs/{run_id}/samples/set-mismatches — set barcode mismatches for selected samples."""
        run_id = request.path_params["run_id"]

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

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

        for sample in run.samples:
            if sample.id in sample_ids:
                sample.barcode_mismatches_index1 = mismatch_index1
                sample.barcode_mismatches_index2 = mismatch_index2

        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)

        return _sample_table_with_nav(run)

    async def set_override_cycles_bulk(request: Request) -> Response:
        """POST /runs/{run_id}/samples/set-override-cycles — set override cycles for selected samples."""
        run_id = request.path_params["run_id"]

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

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

        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)

        return _sample_table_with_nav(run)

    async def set_test_id_bulk(request: Request) -> Response:
        """POST /runs/{run_id}/samples/set-test-id — set test ID for selected samples."""
        run_id = request.path_params["run_id"]

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        form = await request.form()
        sample_ids_json = form.get("sample_ids", "[]")
        test_id_str = form.get("test_id", "")

        try:
            sample_ids = json.loads(sample_ids_json)
        except json.JSONDecodeError:
            return Response("Invalid request data", status_code=400)

        test_id = sanitize_string(test_id_str, 256)

        for sample in run.samples:
            if sample.id in sample_ids:
                sample.test_id = test_id

        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)

        return _sample_table_with_nav(run)

    async def delete_samples_bulk(request: Request) -> Response:
        """POST /runs/{run_id}/samples/bulk-delete — delete multiple selected samples."""
        run_id = request.path_params["run_id"]

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        form = await request.form()
        sample_ids_json = form.get("sample_ids", "[]")

        try:
            sample_ids = json.loads(sample_ids_json)
        except json.JSONDecodeError:
            return Response("Invalid request data", status_code=400)

        for sample_id in sample_ids:
            run.remove_sample(sample_id)

        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)

        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        return ft_response(SampleTableWizard(run, show_drop_zones=True, num_lanes=num_lanes))

    def delete_sample(request: Request) -> Response:
        """DELETE /runs/{run_id}/samples/{id} — delete a single sample."""
        run_id = request.path_params["run_id"]
        sample_id = request.path_params["id"]
        context = request.query_params.get("context", "")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        run.remove_sample(sample_id)
        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)

        if context == "add_step2":
            return Response("")

        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        return ft_response(SampleTableWizard(run, show_drop_zones=True, num_lanes=num_lanes))

    async def update_sample(request: Request) -> Response:
        """POST /runs/{run_id}/samples/{id} — update an existing sample."""
        run_id = request.path_params["run_id"]
        sample_id_path = request.path_params["id"]
        form = await request.form()
        sample_id = form.get("sample_id", "")
        sample_name = form.get("sample_name", "")
        project = form.get("project", "")

        # Reject blank sample_id before any mutation — mirrors add_sample.
        # Blanking sample_id would silently break demultiplexing for that sample.
        if not sample_id or not sample_id.strip():
            return Response("sample_id is required", status_code=400)
        sample_id = sanitize_string(sample_id, 256)
        sample_name = sanitize_string(sample_name, 256)
        project = sanitize_string(project, 256)

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        sample = run.get_sample(sample_id_path)

        if sample:
            sample.sample_id = sample_id
            sample.sample_name = sample_name
            sample.project = project
            run.touch(updated_by=get_username(request))
            ctx.run_repo.save(run)
            num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
            return ft_response(
                SampleRowWizard(sample, run_id, run.run_cycles, show_drop_zones=False, num_lanes=num_lanes)
            )

        return Response("")

    async def assign_index(request: Request) -> Response:
        """POST /runs/{run_id}/samples/{id}/assign-index — assign an index via drag-drop."""
        run_id = request.path_params["run_id"]
        sample_id_path = request.path_params["id"]
        form = await request.form()
        index_pair_id = form.get("index_pair_id", "")
        index_id = form.get("index_id", "")
        index_type = form.get("index_type", "")
        context = form.get("context", "") or request.query_params.get("context", "")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        sample = run.get_sample(sample_id_path)
        if not sample:
            return Response("Sample not found", status_code=404)

        if index_pair_id:
            index_pair, kit = ctx.index_kit_repo.find_index_pair_with_kit(index_pair_id)
            if not index_pair:
                return Response("Index pair not found", status_code=404)

            run.assign_index_pair_to_sample(sample.id, index_pair)
            sample.index_kit_name = kit.name
            _apply_kit_defaults(sample, kit)
        elif index_id and index_type:
            index, kit = ctx.index_kit_repo.find_index_with_kit(index_id)
            if not index:
                return Response("Index not found", status_code=404)

            if index_type == "i7":
                run.assign_index1_to_sample(sample.id, index)
            elif index_type == "i5":
                run.assign_index2_to_sample(sample.id, index)
            else:
                return Response(f"Invalid index type: {index_type}", status_code=400)
            sample.index_kit_name = kit.name
            _apply_kit_defaults(sample, kit)
        else:
            return Response("Missing index_pair_id or index_id/index_type", status_code=400)

        _update_override_cycles(sample, run)

        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)

        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        show_bulk = context != "add_step2"
        show_cb = True if context == "add_step2" else None
        return ft_response(
            SampleRowWizard(
                sample, run_id, run.run_cycles,
                show_drop_zones=True, num_lanes=num_lanes,
                show_bulk_actions=show_bulk, context=context, show_checkboxes=show_cb,
            )
        )

    async def clear_index(request: Request) -> Response:
        """POST /runs/{run_id}/samples/{id}/clear-index — clear assigned index(es)."""
        run_id = request.path_params["run_id"]
        sample_id_path = request.path_params["id"]
        # The clear button uses GET-style query params even on POST (htmx default).
        index_type = request.query_params.get("index_type", "")
        context = request.query_params.get("context", "")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        sample = run.get_sample(sample_id_path)
        if sample:
            if index_type == "i7":
                run.clear_sample_index1(sample.id)
            elif index_type == "i5":
                run.clear_sample_index2(sample.id)
            else:
                run.clear_sample_index(sample.id)

            run.touch(updated_by=get_username(request))
            ctx.run_repo.save(run)
            num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
            show_bulk = context != "add_step2"
            show_cb = True if context == "add_step2" else None
            return ft_response(
                SampleRowWizard(
                    sample, run_id, run.run_cycles,
                    show_drop_zones=True, num_lanes=num_lanes,
                    show_bulk_actions=show_bulk, context=context, show_checkboxes=show_cb,
                )
            )

        return Response("")

    async def update_sample_settings(request: Request) -> Response:
        """POST /runs/{run_id}/samples/{id}/settings — update override cycles + mismatches."""
        run_id = request.path_params["run_id"]
        sample_id_path = request.path_params["id"]
        form = await request.form()
        override_cycles = form.get("override_cycles", "")
        barcode_mismatches_index1 = form.get("barcode_mismatches_index1", "")
        barcode_mismatches_index2 = form.get("barcode_mismatches_index2", "")

        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        if err := check_run_editable(run):
            return err

        sample = run.get_sample(sample_id_path)
        if not sample:
            return Response("Sample not found", status_code=404)

        override_cycles = sanitize_string(override_cycles, 256)
        if override_cycles:
            sample.override_cycles = override_cycles
        else:
            if run.run_cycles and sample.has_index:
                sample.override_cycles = CycleCalculator.calculate_override_cycles(
                    sample, run.run_cycles
                )
            else:
                sample.override_cycles = None

        barcode_mismatches_index1 = barcode_mismatches_index1.strip()
        if barcode_mismatches_index1:
            try:
                sample.barcode_mismatches_index1 = max(0, min(3, int(barcode_mismatches_index1)))
            except ValueError:
                sample.barcode_mismatches_index1 = None
        else:
            sample.barcode_mismatches_index1 = None

        barcode_mismatches_index2 = barcode_mismatches_index2.strip()
        if barcode_mismatches_index2:
            try:
                sample.barcode_mismatches_index2 = max(0, min(3, int(barcode_mismatches_index2)))
            except ValueError:
                sample.barcode_mismatches_index2 = None
        else:
            sample.barcode_mismatches_index2 = None

        run.touch(updated_by=get_username(request))
        ctx.run_repo.save(run)

        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        return ft_response(
            SampleRowWizard(sample, run_id, run.run_cycles, show_drop_zones=True, num_lanes=num_lanes)
        )

    # Order matters: specific paths before {id} captures.
    app.routes.append(Route("/runs/{run_id}/samples", add_sample, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/samples/bulk", add_bulk_samples, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/samples/bulk-delete", delete_samples_bulk, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/samples/worklists", list_worklists, methods=["GET"]))
    app.routes.append(Route("/runs/{run_id}/samples/preview-worklist", preview_worklist, methods=["GET"]))
    app.routes.append(Route("/runs/{run_id}/samples/fetch-worklist", import_worklist_samples, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/samples/assign-indexes-bulk", assign_indexes_bulk, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/samples/assign-index-to-selected", assign_index_to_selected, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/samples/set-lanes", set_lanes_bulk, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/samples/set-mismatches", set_mismatches_bulk, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/samples/set-override-cycles", set_override_cycles_bulk, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/samples/set-test-id", set_test_id_bulk, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/samples/{id}/assign-index", assign_index, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/samples/{id}/clear-index", clear_index, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/samples/{id}/settings", update_sample_settings, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/samples/{id}", update_sample, methods=["POST"]))
    app.routes.append(Route("/runs/{run_id}/samples/{id}", delete_sample, methods=["DELETE"]))
