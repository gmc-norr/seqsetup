"""Sample management routes."""

from dataclasses import dataclass
from fasthtml.common import *
from starlette.responses import Response

from ..components.sample_table import EmptyTableMessage, SampleRow, SampleTable
from ..components.wizard import (
    AddSamplesNavigation,
    NewSamplesTableWizard,
    SampleRowWizard,
    SampleTableWizard,
    WizardNavigation,
    WorklistSelector,
)
from ..models.index import Index, IndexKit, IndexType
from ..models.sample import Sample
from ..data.instruments import get_lanes_for_flowcell
from ..services.cycle_calculator import CycleCalculator


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


@dataclass
class ParsedSample:
    """Parsed sample data from pasted input."""
    sample_id: str
    test_id: str = ""
    index1_sequence: str = ""  # i7 index sequence
    index2_sequence: str = ""  # i5 index sequence
    index_pair_name: str = ""  # Name for the index pair (used as index_kit_name)
    index1_name: str = ""  # i7 index name
    index2_name: str = ""  # i5 index name


# Common header names (case-insensitive)
SAMPLE_HEADERS = {
    "sample_id", "sampleid", "sample", "sample id",
    "sample-id", "id", "name", "sample_name", "samplename",
}
TEST_HEADERS = {
    "test_id", "testid", "test", "test id", "test-id",
    "test_type", "testtype", "test type", "assay", "application",
}
INDEX1_HEADERS = {
    "index", "index1", "i7", "index_i7", "i7_index", "index i7",
}
INDEX2_HEADERS = {
    "index2", "i5", "index_i5", "i5_index", "index i5",
}
INDEX_PAIR_NAME_HEADERS = {
    "index_pair_name", "pair_name", "index_pair", "index pair",
    "index_kit", "kit_name", "kit name", "index kit",
}
INDEX1_NAME_HEADERS = {
    "i7_name", "i7 name", "index_i7_name", "index1_name",
    "index_name", "index name",
}
INDEX2_NAME_HEADERS = {
    "i5_name", "i5 name", "index_i5_name", "index2_name",
}


def _detect_column_mapping(header_parts: list[str]) -> dict[str, int]:
    """
    Detect which columns contain which fields based on header row.

    Args:
        header_parts: List of header column values

    Returns:
        Dictionary mapping field names to column indices
    """
    mapping = {}
    for i, col in enumerate(header_parts):
        col_lower = col.lower().strip()
        if col_lower in SAMPLE_HEADERS and "sample_id" not in mapping:
            mapping["sample_id"] = i
        elif col_lower in TEST_HEADERS and "test_id" not in mapping:
            mapping["test_id"] = i
        elif col_lower in INDEX1_NAME_HEADERS and "index1_name" not in mapping:
            # Check name headers before sequence headers (index_name is more
            # specific than index which could match INDEX1_HEADERS)
            mapping["index1_name"] = i
        elif col_lower in INDEX2_NAME_HEADERS and "index2_name" not in mapping:
            mapping["index2_name"] = i
        elif col_lower in INDEX1_HEADERS and "index1" not in mapping:
            mapping["index1"] = i
        elif col_lower in INDEX2_HEADERS and "index2" not in mapping:
            mapping["index2"] = i
        elif col_lower in INDEX_PAIR_NAME_HEADERS and "index_pair_name" not in mapping:
            mapping["index_pair_name"] = i
    return mapping


def _is_header_row(parts: list[str]) -> bool:
    """
    Check if a row appears to be a header row.

    Args:
        parts: List of column values from the row

    Returns:
        True if the row looks like a header
    """
    if not parts:
        return False

    first_lower = parts[0].lower().strip()

    # Check if first column matches a sample header
    if first_lower in SAMPLE_HEADERS:
        return True

    # Check if any column matches known headers
    all_headers = (
        TEST_HEADERS | INDEX1_HEADERS | INDEX2_HEADERS
        | INDEX_PAIR_NAME_HEADERS | INDEX1_NAME_HEADERS | INDEX2_NAME_HEADERS
    )
    for col in parts[1:]:
        col_lower = col.lower().strip()
        if col_lower in all_headers:
            return True

    return False


def parse_pasted_samples(paste_data: str) -> list[ParsedSample]:
    """
    Parse pasted sample data.

    Supports:
    - Tab or comma-separated columns
    - Optional header row (auto-detected and used for column mapping)
    - Columns: sample_id, test_id, index_i7, index_i5, index_pair_name, i7_name, i5_name

    Args:
        paste_data: Raw pasted text

    Returns:
        List of ParsedSample objects
    """
    samples = []
    lines = paste_data.strip().split("\n")

    # Default column mapping (no header)
    column_mapping = {"sample_id": 0, "test_id": 1, "index1": 2, "index2": 3}
    header_detected = False

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        # Try tab separator first, then comma
        if "\t" in line:
            parts = [p.strip() for p in line.split("\t")]
        elif "," in line:
            parts = [p.strip() for p in line.split(",")]
        else:
            parts = [line.strip()]

        # Check first non-empty line for header
        if i == 0 and _is_header_row(parts):
            column_mapping = _detect_column_mapping(parts)
            # Ensure sample_id has a mapping (default to first column if not found)
            if "sample_id" not in column_mapping:
                column_mapping["sample_id"] = 0
            header_detected = True
            continue

        # Extract values using column mapping
        sample_id = parts[column_mapping.get("sample_id", 0)] if len(parts) > column_mapping.get("sample_id", 0) else ""
        test_id = ""
        index1 = ""
        index2 = ""

        if "test_id" in column_mapping and len(parts) > column_mapping["test_id"]:
            test_id = parts[column_mapping["test_id"]]
        elif not header_detected and len(parts) > 1:
            # Default: second column is test_id if no header
            test_id = parts[1]

        if "index1" in column_mapping and len(parts) > column_mapping["index1"]:
            index1 = parts[column_mapping["index1"]]
        elif not header_detected and len(parts) > 2:
            # Default: third column is index1 if no header
            index1 = parts[2]

        if "index2" in column_mapping and len(parts) > column_mapping["index2"]:
            index2 = parts[column_mapping["index2"]]
        elif not header_detected and len(parts) > 3:
            # Default: fourth column is index2 if no header
            index2 = parts[3]

        # Name columns (only when header is detected, no default positions)
        index_pair_name = ""
        index1_name = ""
        index2_name = ""

        if "index_pair_name" in column_mapping and len(parts) > column_mapping["index_pair_name"]:
            index_pair_name = parts[column_mapping["index_pair_name"]]
        if "index1_name" in column_mapping and len(parts) > column_mapping["index1_name"]:
            index1_name = parts[column_mapping["index1_name"]]
        if "index2_name" in column_mapping and len(parts) > column_mapping["index2_name"]:
            index2_name = parts[column_mapping["index2_name"]]

        if sample_id:
            samples.append(ParsedSample(
                sample_id=sample_id,
                test_id=test_id,
                index1_sequence=index1.upper() if index1 else "",
                index2_sequence=index2.upper() if index2 else "",
                index_pair_name=index_pair_name,
                index1_name=index1_name,
                index2_name=index2_name,
            ))

    return samples


def _get_username(req) -> str:
    """Extract username from request auth scope."""
    user = req.scope.get("auth")
    return user.username if user else ""


def register(app, rt, get_run_repo, get_index_kit_repo, get_sample_api_config_repo=None):
    """Register sample routes."""

    @rt("/runs/{run_id}/samples")
    def add_sample(req, run_id: str, sample_id: str, sample_name: str = "", project: str = "", test_id: str = ""):
        """Add a new sample to a run."""
        if not sample_id or not sample_id.strip():
            return Response("sample_id is required", status_code=400)
        sample_id = sample_id.strip()[:256]
        sample_name = sample_name.strip()[:256]
        project = project.strip()[:256]
        test_id = test_id.strip()[:256]

        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        sample = Sample(
            sample_id=sample_id,
            sample_name=sample_name,
            project=project,
            test_id=test_id,
            lanes=[1],
        )
        run.add_sample(sample)
        run.touch(updated_by=_get_username(req))
        run_repo.save(run)

        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        return SampleRowWizard(sample, run_id, run.run_cycles, show_drop_zones=False, num_lanes=num_lanes)

    @app.post("/runs/{run_id}/samples/bulk")
    async def add_bulk_samples(req, run_id: str, context: str = "", existing_ids: str = ""):
        """Add multiple samples from pasted data or uploaded file."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        # Get form data from request
        form = await req.form()

        # Check for uploaded file first, then fall back to paste data
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

        parsed = parse_pasted_samples(content)

        # Get existing sample IDs to check for duplicates
        existing_sample_ids = {s.sample_id for s in run.samples}

        # Track added and skipped samples
        added_count = 0
        skipped_duplicates = []
        skipped_within_paste = []  # Duplicates within the pasted data itself

        seen_in_paste = set()
        for ps in parsed:
            if ps.sample_id in existing_sample_ids:
                # Skip samples that already exist in the run
                skipped_duplicates.append(ps.sample_id)
            elif ps.sample_id in seen_in_paste:
                # Skip duplicates within the pasted data
                skipped_within_paste.append(ps.sample_id)
            else:
                seen_in_paste.add(ps.sample_id)
                sample = Sample(
                    sample_id=ps.sample_id,
                    test_id=ps.test_id,
                    lanes=[1],
                )

                # Create and assign indexes from pasted sequences
                if ps.index1_sequence:
                    index1 = Index(
                        name=ps.index1_name or ps.index1_sequence,
                        sequence=ps.index1_sequence,
                        index_type=IndexType.I7,
                    )
                    sample.assign_index1(index1)
                    sample.index_kit_name = ps.index_pair_name or "Pasted"

                if ps.index2_sequence:
                    index2 = Index(
                        name=ps.index2_name or ps.index2_sequence,
                        sequence=ps.index2_sequence,
                        index_type=IndexType.I5,
                    )
                    sample.assign_index2(index2)
                    if not sample.index_kit_name:
                        sample.index_kit_name = ps.index_pair_name or "Pasted"

                # Calculate override cycles and index override patterns if indexes were assigned
                if sample.has_index and run.run_cycles:
                    CycleCalculator.populate_index_override_patterns(sample, run.run_cycles)
                    sample.override_cycles = CycleCalculator.calculate_override_cycles(
                        sample, run.run_cycles
                    )

                run.add_sample(sample)
                added_count += 1

        if added_count > 0:
            run.touch(updated_by=_get_username(req))
            run_repo.save(run)

        # Return different views based on context
        if context == "add_step1":
            # Add Samples wizard step 1 - return success message and update navigation
            messages = []

            # Success message for added samples
            if added_count == 0:
                if not parsed:
                    messages.append(P("No samples found in pasted data.", cls="warning-message"))
                else:
                    messages.append(P("No new samples added.", cls="warning-message"))
            elif added_count == 1:
                messages.append(P("Added 1 sample.", cls="success-message"))
            else:
                messages.append(P(f"Added {added_count} samples.", cls="success-message"))

            # Warning for skipped duplicates (already in run)
            if skipped_duplicates:
                if len(skipped_duplicates) <= 3:
                    dup_list = ", ".join(skipped_duplicates)
                else:
                    dup_list = ", ".join(skipped_duplicates[:3]) + f" and {len(skipped_duplicates) - 3} more"
                messages.append(P(f"Skipped {len(skipped_duplicates)} duplicate(s) already in run: {dup_list}", cls="warning-message"))

            # Warning for duplicates within paste
            if skipped_within_paste:
                if len(skipped_within_paste) <= 3:
                    dup_list = ", ".join(skipped_within_paste)
                else:
                    dup_list = ", ".join(skipped_within_paste[:3]) + f" and {len(skipped_within_paste) - 3} more"
                messages.append(P(f"Skipped {len(skipped_within_paste)} duplicate(s) in pasted data: {dup_list}", cls="warning-message"))

            return (
                Div(*messages),
                AddSamplesNavigation(1, run.id, can_proceed=run.has_samples, oob=True, existing_ids=existing_ids),
            )

        # Default: Return the sample table and updated navigation (out-of-band swap)
        # In combined step 2, show drop zones and require indexes to proceed
        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        can_proceed = run.has_samples and run.all_samples_have_indexes
        return (
            SampleTableWizard(run, show_drop_zones=True, num_lanes=num_lanes),
            WizardNavigation(2, run.id, can_proceed=can_proceed, oob=True),
        )

    @app.get("/runs/{run_id}/samples/worklists")
    def list_worklists(run_id: str, context: str = "", existing_ids: str = ""):
        """Fetch available worklists from the API and return a selector."""
        if get_sample_api_config_repo is None:
            return P("Sample API is not configured.", cls="error-message")

        from ..services.sample_api import fetch_worklists

        api_config = get_sample_api_config_repo().get()
        if not api_config.enabled or not api_config.base_url:
            return P("Sample API is not enabled or base URL is not configured.", cls="error-message")

        success, message, worklists = fetch_worklists(api_config)
        if not success:
            return P(f"Failed to load worklists: {message}", cls="error-message")

        return WorklistSelector(run_id, worklists, context=context, existing_ids=existing_ids)

    @app.post("/runs/{run_id}/samples/fetch-worklist")
    def import_worklist_samples(req, run_id: str, worklist_id: str = "", context: str = "", existing_ids: str = ""):
        """Import samples from a selected worklist."""
        if get_sample_api_config_repo is None:
            return P("Sample API is not configured.", cls="error-message")

        if not worklist_id:
            return P("No worklist selected.", cls="error-message")

        from ..services.sample_api import fetch_worklist_samples, parse_api_samples

        api_config = get_sample_api_config_repo().get()
        if not api_config.enabled or not api_config.base_url:
            return P("Sample API is not enabled or base URL is not configured.", cls="error-message")

        success, message, raw_data = fetch_worklist_samples(api_config, worklist_id)
        if not success:
            return P(f"Failed to fetch worklist samples: {message}", cls="error-message")

        api_samples = parse_api_samples(raw_data)
        if not api_samples:
            return P("No valid samples found in worklist.", cls="warning-message")

        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        existing_sample_ids = {s.sample_id for s in run.samples}
        added_count = 0
        skipped_duplicates = []

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
                lanes=[1],
            )

            # Create and assign indexes from API data
            idx1_seq = api_sample.get("index1_sequence", "")
            if idx1_seq:
                index1 = Index(
                    name=api_sample.get("index1_name", idx1_seq),
                    sequence=idx1_seq,
                    index_type=IndexType.I7,
                )
                sample.assign_index1(index1)
                sample.index_kit_name = api_sample.get("index_pair_name", "API")

            idx2_seq = api_sample.get("index2_sequence", "")
            if idx2_seq:
                index2 = Index(
                    name=api_sample.get("index2_name", idx2_seq),
                    sequence=idx2_seq,
                    index_type=IndexType.I5,
                )
                sample.assign_index2(index2)
                if not sample.index_kit_name:
                    sample.index_kit_name = api_sample.get("index_pair_name", "API")

            # Calculate override cycles and index override patterns if indexes were assigned
            if sample.has_index and run.run_cycles:
                CycleCalculator.populate_index_override_patterns(sample, run.run_cycles)
                sample.override_cycles = CycleCalculator.calculate_override_cycles(
                    sample, run.run_cycles
                )

            run.add_sample(sample)
            added_count += 1

        if added_count > 0:
            run.touch(updated_by=_get_username(req))
            run_repo.save(run)

        # Build result messages
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
            return (
                Div(*messages),
                AddSamplesNavigation(1, run.id, can_proceed=run.has_samples, oob=True, existing_ids=existing_ids),
            )

        # Default: return updated sample table
        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        can_proceed = run.has_samples and run.all_samples_have_indexes
        return (
            SampleTableWizard(run, show_drop_zones=True, num_lanes=num_lanes),
            WizardNavigation(2, run.id, can_proceed=can_proceed, oob=True),
        )

    @app.post("/runs/{run_id}/samples/assign-indexes-bulk")
    async def assign_indexes_bulk(req, run_id: str):
        """
        Assign multiple indexes to consecutive samples starting from a given sample.

        Args:
            start_sample_id: The sample ID where the drop occurred (first sample to assign)
            indexes_json: JSON array of {id, type} objects for indexes to assign
            index_type: For combinatorial mode, the drop zone type ('i7' or 'i5')
            context: Context for determining response format ("add_step2" for simplified view)
        """
        import json

        # Get form data from request (needed for htmx.ajax with values)
        form = await req.form()
        start_sample_id = form.get("start_sample_id", "")
        indexes_json = form.get("indexes_json", "")
        index_type = form.get("index_type", "")
        context = form.get("context", "")
        existing_ids = form.get("existing_ids", "")

        if not start_sample_id:
            return Response("Missing start_sample_id", status_code=400)
        if not indexes_json:
            return Response("Missing indexes_json", status_code=400)

        run_repo = get_run_repo()
        index_kit_repo = get_index_kit_repo()

        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        try:
            indexes_data = json.loads(indexes_json)
        except json.JSONDecodeError as e:
            return Response(f"Invalid indexes_json: {e}", status_code=400)

        # Find the starting sample index
        start_idx = None
        for i, sample in enumerate(run.samples):
            if sample.id == start_sample_id:
                start_idx = i
                break

        if start_idx is None:
            return Response("Start sample not found", status_code=404)

        # Assign indexes to consecutive samples
        for offset, idx_data in enumerate(indexes_data):
            sample_idx = start_idx + offset
            if sample_idx >= len(run.samples):
                break  # No more samples to assign to

            sample = run.samples[sample_idx]
            idx_id = idx_data.get("id")
            idx_type = idx_data.get("type", "pair")

            if idx_type == "pair":
                # Unique dual mode - assign pre-paired index
                index_pair, kit = index_kit_repo.find_index_pair_with_kit(idx_id)
                if index_pair:
                    sample.assign_index(index_pair)
                    sample.index_kit_name = kit.name
                    _apply_kit_defaults(sample, kit)
            elif idx_type == "i7":
                index, kit = index_kit_repo.find_index_with_kit(idx_id)
                if index:
                    sample.assign_index1(index)
                    sample.index_kit_name = kit.name
                    _apply_kit_defaults(sample, kit)
            elif idx_type == "i5":
                index, kit = index_kit_repo.find_index_with_kit(idx_id)
                if index:
                    sample.assign_index2(index)
                    sample.index_kit_name = kit.name
                    _apply_kit_defaults(sample, kit)

            # Calculate override cycles and index override patterns
            if run.run_cycles:
                CycleCalculator.populate_index_override_patterns(sample, run.run_cycles)
                sample.override_cycles = CycleCalculator.calculate_override_cycles(
                    sample, run.run_cycles
                )

        run.touch(updated_by=_get_username(req))
        run_repo.save(run)

        # Return the sample table based on context
        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)

        if context == "add_step2":
            # Simplified table for Add Samples wizard step 2 - only show new samples
            existing_ids_set = set(id.strip() for id in existing_ids.split(",") if id.strip()) if existing_ids else set()
            new_samples = [s for s in run.samples if s.id not in existing_ids_set]
            return NewSamplesTableWizard(run, new_samples, context=context, existing_ids=existing_ids)

        # Default: Return full table with navigation OOB swap
        can_proceed = run.has_samples and run.all_samples_have_indexes
        return (
            SampleTableWizard(run, show_drop_zones=True, num_lanes=num_lanes),
            WizardNavigation(2, run.id, can_proceed=can_proceed, oob=True),
        )

    @app.post("/runs/{run_id}/samples/set-lanes")
    async def set_lanes_bulk(req, run_id: str):
        """
        Set lanes for multiple selected samples.

        Form data:
            sample_ids: JSON array of sample IDs to update
            lanes: JSON array of lane numbers (empty = all lanes)
        """
        import json

        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        form = await req.form()
        sample_ids_json = form.get("sample_ids", "[]")
        lanes_json = form.get("lanes", "[]")

        try:
            sample_ids = json.loads(sample_ids_json)
            lanes = json.loads(lanes_json)
        except json.JSONDecodeError as e:
            return Response(f"Invalid JSON: {e}", status_code=400)

        # Update lanes for each selected sample
        for sample in run.samples:
            if sample.id in sample_ids:
                sample.lanes = sorted(lanes)

        run.touch(updated_by=_get_username(req))
        run_repo.save(run)

        # Return updated sample table
        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        can_proceed = run.has_samples and run.all_samples_have_indexes
        return (
            SampleTableWizard(run, show_drop_zones=True, num_lanes=num_lanes),
            WizardNavigation(2, run.id, can_proceed=can_proceed, oob=True),
        )

    @app.post("/runs/{run_id}/samples/set-mismatches")
    async def set_mismatches_bulk(req, run_id: str):
        """
        Set barcode mismatches for multiple selected samples.

        Form data:
            sample_ids: JSON array of sample IDs to update
            mismatch_index1: Mismatch value for index 1 (empty string to clear)
            mismatch_index2: Mismatch value for index 2 (empty string to clear)
        """
        import json

        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        form = await req.form()
        sample_ids_json = form.get("sample_ids", "[]")
        mismatch_index1_str = form.get("mismatch_index1", "")
        mismatch_index2_str = form.get("mismatch_index2", "")

        try:
            sample_ids = json.loads(sample_ids_json)
        except json.JSONDecodeError as e:
            return Response(f"Invalid JSON: {e}", status_code=400)

        # Parse mismatch values (empty string means clear/None)
        mismatch_index1 = None
        if mismatch_index1_str.strip():
            try:
                mismatch_index1 = int(mismatch_index1_str)
            except ValueError:
                pass

        mismatch_index2 = None
        if mismatch_index2_str.strip():
            try:
                mismatch_index2 = int(mismatch_index2_str)
            except ValueError:
                pass

        # Update mismatches for each selected sample
        for sample in run.samples:
            if sample.id in sample_ids:
                sample.barcode_mismatches_index1 = mismatch_index1
                sample.barcode_mismatches_index2 = mismatch_index2

        run.touch(updated_by=_get_username(req))
        run_repo.save(run)

        # Return updated sample table
        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        can_proceed = run.has_samples and run.all_samples_have_indexes
        return (
            SampleTableWizard(run, show_drop_zones=True, num_lanes=num_lanes),
            WizardNavigation(2, run.id, can_proceed=can_proceed, oob=True),
        )

    @app.post("/runs/{run_id}/samples/set-override-cycles")
    async def set_override_cycles_bulk(req, run_id: str):
        """
        Set override cycles for multiple selected samples.

        Form data:
            sample_ids: JSON array of sample IDs to update
            override_cycles: Override cycles value (empty string to recalculate auto)
        """
        import json

        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        form = await req.form()
        sample_ids_json = form.get("sample_ids", "[]")
        override_cycles_str = form.get("override_cycles", "")

        try:
            sample_ids = json.loads(sample_ids_json)
        except json.JSONDecodeError as e:
            return Response(f"Invalid JSON: {e}", status_code=400)

        # Update override cycles for each selected sample
        override_cycles = override_cycles_str.strip() if override_cycles_str else None

        for sample in run.samples:
            if sample.id in sample_ids:
                if override_cycles:
                    # Set explicit override cycles
                    sample.override_cycles = override_cycles
                else:
                    # Recalculate default if cleared
                    if run.run_cycles and sample.has_index:
                        sample.override_cycles = CycleCalculator.calculate_override_cycles(
                            sample, run.run_cycles
                        )
                    else:
                        sample.override_cycles = None

        run.touch(updated_by=_get_username(req))
        run_repo.save(run)

        # Return updated sample table
        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        can_proceed = run.has_samples and run.all_samples_have_indexes
        return (
            SampleTableWizard(run, show_drop_zones=True, num_lanes=num_lanes),
            WizardNavigation(2, run.id, can_proceed=can_proceed, oob=True),
        )

    @app.delete("/runs/{run_id}/samples/{id}")
    def delete_sample(req, run_id: str, id: str, context: str = ""):
        """Delete a sample."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        run.remove_sample(id)
        run.touch(updated_by=_get_username(req))
        run_repo.save(run)

        # Return different views based on context
        if context == "add_step2":
            # Add Samples wizard step 2 - just remove the row (button targets row directly)
            return ""

        # Default: Run overview - return the full table (delete button targets #sample-table)
        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        return SampleTableWizard(run, show_drop_zones=True, num_lanes=num_lanes)

    @rt("/runs/{run_id}/samples/{id}")
    def update_sample(req, run_id: str, id: str, sample_id: str, sample_name: str = "", project: str = ""):
        """Update a sample."""
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        sample = run.get_sample(id)

        if sample:
            sample.sample_id = sample_id
            sample.sample_name = sample_name
            sample.project = project
            run.touch(updated_by=_get_username(req))
            run_repo.save(run)
            num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
            return SampleRowWizard(sample, run_id, run.run_cycles, show_drop_zones=False, num_lanes=num_lanes)

        return ""

    @app.post("/runs/{run_id}/samples/{id}/assign-index")
    def assign_index(
        req,
        run_id: str,
        id: str,
        index_pair_id: str = "",
        index_id: str = "",
        index_type: str = "",
        context: str = "",
    ):
        """
        Assign an index to a sample via drag-drop.

        Supports:
        - index_pair_id: For unique_dual mode (pre-paired indexes)
        - index_id + index_type: For combinatorial/single mode (individual indexes)
        - context: Context for determining response format ("add_step2" for simplified view)
        """
        run_repo = get_run_repo()
        index_kit_repo = get_index_kit_repo()

        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        sample = run.get_sample(id)
        if not sample:
            return Response("Sample not found", status_code=404)

        if index_pair_id:
            # Unique dual mode - assign a pre-paired index
            index_pair, kit = index_kit_repo.find_index_pair_with_kit(index_pair_id)
            if not index_pair:
                return Response("Index pair not found", status_code=404)

            sample.assign_index(index_pair)
            sample.index_kit_name = kit.name
            _apply_kit_defaults(sample, kit)
        elif index_id and index_type:
            # Combinatorial/single mode - assign individual index
            index, kit = index_kit_repo.find_index_with_kit(index_id)
            if not index:
                return Response("Index not found", status_code=404)

            if index_type == "i7":
                sample.assign_index1(index)
            elif index_type == "i5":
                sample.assign_index2(index)
            else:
                return Response(f"Invalid index type: {index_type}", status_code=400)
            sample.index_kit_name = kit.name
            _apply_kit_defaults(sample, kit)
        else:
            return Response("Missing index_pair_id or index_id/index_type", status_code=400)

        # Calculate override cycles and index override patterns
        if run.run_cycles:
            CycleCalculator.populate_index_override_patterns(sample, run.run_cycles)
            sample.override_cycles = CycleCalculator.calculate_override_cycles(
                sample, run.run_cycles
            )

        run.touch(updated_by=_get_username(req))
        run_repo.save(run)

        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        # Return simplified row for add_step2 context
        show_bulk = context != "add_step2"
        return SampleRowWizard(sample, run_id, run.run_cycles, show_drop_zones=True, num_lanes=num_lanes, show_bulk_actions=show_bulk, context=context)

    @app.post("/runs/{run_id}/samples/{id}/clear-index")
    def clear_index(req, run_id: str, id: str, index_type: str = "", context: str = ""):
        """
        Clear the assigned index from a sample.

        Args:
            index_type: Optional. "i7" to clear only i7, "i5" to clear only i5,
                        empty to clear all indexes.
            context: Context for determining response format ("add_step2" for simplified view)
        """
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        sample = run.get_sample(id)
        if sample:
            if index_type == "i7":
                sample.clear_index1()
            elif index_type == "i5":
                sample.clear_index2()
            else:
                sample.clear_index()

            run.touch(updated_by=_get_username(req))
            run_repo.save(run)
            num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
            # Return simplified row for add_step2 context
            show_bulk = context != "add_step2"
            return SampleRowWizard(sample, run_id, run.run_cycles, show_drop_zones=True, num_lanes=num_lanes, show_bulk_actions=show_bulk, context=context)

        return ""

    @app.post("/runs/{run_id}/samples/{id}/settings")
    def update_sample_settings(
        req,
        run_id: str,
        id: str,
        override_cycles: str = "",
        barcode_mismatches_index1: str = "",
        barcode_mismatches_index2: str = "",
    ):
        """
        Update sample settings (override cycles, barcode mismatches - lanes are set via bulk action).
        """
        run_repo = get_run_repo()
        run = run_repo.get_by_id(run_id)
        if not run:
            return Response("Run not found", status_code=404)

        sample = run.get_sample(id)
        if not sample:
            return Response("Sample not found", status_code=404)

        # Update override cycles
        override_cycles = override_cycles.strip()
        if override_cycles:
            sample.override_cycles = override_cycles
        else:
            # Recalculate default if cleared
            if run.run_cycles and sample.has_index:
                sample.override_cycles = CycleCalculator.calculate_override_cycles(
                    sample, run.run_cycles
                )
            else:
                sample.override_cycles = None

        # Update barcode mismatches index 1
        barcode_mismatches_index1 = barcode_mismatches_index1.strip()
        if barcode_mismatches_index1:
            try:
                sample.barcode_mismatches_index1 = int(barcode_mismatches_index1)
            except ValueError:
                sample.barcode_mismatches_index1 = None
        else:
            sample.barcode_mismatches_index1 = None

        # Update barcode mismatches index 2
        barcode_mismatches_index2 = barcode_mismatches_index2.strip()
        if barcode_mismatches_index2:
            try:
                sample.barcode_mismatches_index2 = int(barcode_mismatches_index2)
            except ValueError:
                sample.barcode_mismatches_index2 = None
        else:
            sample.barcode_mismatches_index2 = None

        run.touch(updated_by=_get_username(req))
        run_repo.save(run)

        num_lanes = get_lanes_for_flowcell(run.instrument_platform, run.flowcell_type)
        return SampleRowWizard(sample, run_id, run.run_cycles, show_drop_zones=True, num_lanes=num_lanes)

