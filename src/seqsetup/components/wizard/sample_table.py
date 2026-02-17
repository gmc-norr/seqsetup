"""Sample table, paste/import, and bulk action components for the wizard."""

from fasthtml.common import *

from ...models.index import IndexKit
from ...models.sequencing_run import SequencingRun


def SamplePasteFormatHelp():
    """Collapsible section showing paste format examples for sample data."""
    return Details(
        Summary("Paste Format Help", cls="format-help-summary"),
        Div(
            # Basic format
            Div(
                Strong("Basic", cls="format-type-header"),
                P("sample_id and test_id columns. Tab or comma-separated.", cls="format-desc"),
                Pre(
                    "sample_id\ttest_id\n"
                    "Sample001\tWGS\n"
                    "Sample002\tRNA\n"
                    "Sample003\tWGS",
                    cls="format-example",
                ),
                P("A header row is auto-detected and used for column mapping. Without a header, columns default to: sample_id, test_id, index_i7, index_i5. Name columns require a header row.", cls="format-note"),
                cls="format-block",
            ),
            # With indexes
            Div(
                Strong("With Indexes", cls="format-type-header"),
                P("Include index_i7 and/or index_i5 sequences to auto-assign indexes on paste.", cls="format-desc"),
                Pre(
                    "sample_id\ttest_id\tindex_i7\tindex_i5\n"
                    "Sample001\tWGS\tATTACTCG\tTATAGCCT\n"
                    "Sample002\tRNA\tTCCGGAGA\tATAGAGGC\n"
                    "Sample003\tWGS\tCGCTCATT\tCCTATCCT",
                    cls="format-example",
                ),
                cls="format-block",
            ),
            # With index names
            Div(
                Strong("With Index Names", cls="format-type-header"),
                P("Optionally include index_pair_name, i7_name, and i5_name columns.", cls="format-desc"),
                Pre(
                    "sample_id\ttest_id\tindex_i7\tindex_i5\tindex_pair_name\ti7_name\ti5_name\n"
                    "Sample001\tWGS\tATTACTCG\tTATAGCCT\tUDP0001\tD701\tD501\n"
                    "Sample002\tRNA\tTCCGGAGA\tATAGAGGC\tUDP0002\tD702\tD502",
                    cls="format-example",
                ),
                P("All name columns are optional. Without names, sequences are used as index names and 'Pasted' as the kit name.", cls="format-note"),
                cls="format-block",
            ),
            # Minimal format
            Div(
                Strong("Minimal", cls="format-type-header"),
                P("Single column with just sample_ids.", cls="format-desc"),
                Pre(
                    "Sample001\n"
                    "Sample002\n"
                    "Sample003",
                    cls="format-example",
                ),
                cls="format-block",
            ),
            cls="format-help-content",
        ),
        cls="format-help-section",
    )


def FetchFromApiSection(run_id: str, target: str = "#sample-table", context: str = "", existing_ids: str = ""):
    """Section with worklist fetch flow: load worklists, pick one, import samples."""
    params = []
    if context:
        params.append(f"context={context}")
    if existing_ids:
        params.append(f"existing_ids={existing_ids}")
    query_string = "?" + "&".join(params) if params else ""

    return Div(
        Hr(style="margin: 0.75rem 0; border-color: var(--border);"),
        Div(
            Button(
                "Load Worklists",
                type="button",
                cls="btn-primary",
                hx_get=f"/runs/{run_id}/samples/worklists{query_string}",
                hx_target="#worklist-select-area",
                hx_swap="innerHTML",
            ),
            style="display:flex; align-items:center; gap:0.5rem;",
        ),
        P("Fetch a worklist of samples from the configured external API.", cls="field-hint", style="margin-top:0.25rem;"),
        Div(id="worklist-select-area"),
    )


def _format_worklist_option(wl: dict) -> str:
    """Format a worklist dict for display in the dropdown."""
    # Start with the ID
    parts = [wl["id"]]

    # Add investigator if present
    investigator = wl.get("investigator", "")
    if investigator:
        parts.append(f"({investigator})")

    # Add updated timestamp if present (format: just date part)
    updated_at = wl.get("updated_at", "")
    if updated_at:
        # Extract just the date portion if it's an ISO timestamp
        date_part = updated_at.split("T")[0] if "T" in updated_at else updated_at
        parts.append(f"[{date_part}]")

    return " ".join(parts)


def WorklistSelector(run_id: str, worklists: list[dict], context: str = "", existing_ids: str = ""):
    """Dropdown to select a worklist and import its samples."""
    params = []
    if context:
        params.append(f"context={context}")
    if existing_ids:
        params.append(f"existing_ids={existing_ids}")
    query_string = "?" + "&".join(params) if params else ""

    return Div(
        Div(
            Select(
                *[
                    Option(
                        _format_worklist_option(wl),
                        value=wl["id"],
                    )
                    for wl in worklists
                ],
                name="worklist_id",
                id="worklist-select",
                cls="index-kit-dropdown",
                style="min-width:400px; display:inline-block;",
            ),
            Button(
                "Preview",
                type="button",
                cls="btn-secondary",
                hx_get=f"/runs/{run_id}/samples/preview-worklist",
                hx_include="#worklist-select",
                hx_target="#worklist-preview",
                hx_swap="innerHTML",
            ),
            Button(
                "Import Samples",
                type="button",
                cls="btn-primary",
                hx_post=f"/runs/{run_id}/samples/fetch-worklist{query_string}",
                hx_include="#worklist-select",
                hx_target="#worklist-import-result" if context == "add_step1" else "#sample-table",
                hx_swap="innerHTML" if context == "add_step1" else "outerHTML",
            ),
            style="display:flex; align-items:center; gap:0.5rem; margin-top:0.5rem;",
        ),
        Div(id="worklist-preview", cls="worklist-preview"),
        Div(id="worklist-import-result"),
    )


def WorklistPreview(samples: list[dict], worklist_id: str):
    """Preview of samples in a worklist before importing."""
    if not samples:
        return P("No samples found in this worksheet.", cls="warning-message")

    return Div(
        H4(f"Samples in worksheet {worklist_id} ({len(samples)} total)"),
        Div(
            Table(
                Thead(
                    Tr(
                        Th("Sample ID"),
                        Th("Test ID"),
                    )
                ),
                Tbody(
                    *[
                        Tr(
                            Td(s.get("sample_id", s.get("SampleID", "-"))),
                            Td(s.get("test_id", s.get("TestID", "-")) or "-"),
                        )
                        for s in samples[:20]  # Show max 20 samples in preview
                    ]
                ),
                cls="preview-table",
            ),
            P(f"... and {len(samples) - 20} more samples", cls="text-muted")
            if len(samples) > 20 else None,
            cls="preview-table-wrapper",
            style="max-height: 300px; overflow-y: auto; margin-top: 0.5rem;",
        ),
        cls="worklist-preview-content",
        style="margin-top: 1rem; padding: 1rem; background: var(--card-bg); border-radius: 8px;",
    )


def BulkPasteSectionWizard(run_id: str, sample_api_enabled: bool = False):
    """Bulk paste section for wizard with run_id in path."""
    return Div(
        Details(
            Summary("Import samples"),
            Div(
                SamplePasteFormatHelp(),
                Form(
                    Textarea(
                        "",  # Empty initial content
                        name="paste_data",
                        id="paste_data",
                        placeholder="sample_id\ttest_id\tindex_i7\tindex_i5\nSample001\tWGS\tATTACTCG\tTATAGCCT\nSample002\tRNA\tTCCGGAGA\tATAGAGGC",
                        cls="paste-textarea",
                        rows="6",
                    ),
                    Div(
                        Span("or import from file:", cls="file-upload-label"),
                        Input(
                            type="file",
                            name="sample_file",
                            id="sample_file",
                            accept=".csv,.tsv,.txt",
                            cls="sample-file-input",
                        ),
                        cls="file-upload-row",
                    ),
                    Div(
                        Button("Add Samples", type="submit", cls="btn-primary"),
                        Button(
                            "Clear",
                            type="button",
                            cls="btn-secondary",
                            onclick="document.getElementById('paste_data').value=''; document.getElementById('sample_file').value=''",
                        ),
                        cls="paste-buttons",
                    ),
                    hx_post=f"/runs/{run_id}/samples/bulk",
                    hx_target="#sample-table",
                    hx_swap="outerHTML",
                    hx_encoding="multipart/form-data",
                ),
                FetchFromApiSection(run_id, target="#sample-table") if sample_api_enabled else None,
                cls="paste-form-content",
            ),
            cls="paste-details",
        ),
        cls="bulk-paste-section",
    )


def SampleTableWizard(run: SequencingRun, show_drop_zones: bool = False, index_kits: list[IndexKit] = None, num_lanes: int = 1, show_bulk_actions: bool = True, context: str = "", test_profiles: list = None, editable: bool = True):
    """Sample table for wizard with run_id in paths.

    Args:
        run: The sequencing run
        show_drop_zones: Whether to show index drop zones
        index_kits: Available index kits
        num_lanes: Number of lanes for the flowcell
        show_bulk_actions: Whether to show bulk action panel and columns for lanes,
                          override cycles, and mismatches. Set to False for simplified
                          index assignment view.
        context: Context string for HTMX endpoints (e.g., "add_step2" for simplified view)
        test_profiles: List of TestProfile objects for the test ID dropdown
        editable: Whether the table allows editing (delete buttons, bulk actions, etc.)
    """
    if not run.samples:
        return Div(
            P("No samples added yet. Use the paste function above to add samples."),
            cls="empty-message",
            id="sample-table",
        )

    # Determine if we have single-only or combinatorial kits
    # For now, show both columns unless all kits are single mode
    show_i5_column = True
    if index_kits:
        show_i5_column = any(not kit.is_single() for kit in index_kits)

    # Disable bulk actions if not editable
    effective_bulk_actions = show_bulk_actions and editable

    header_cells = []
    # Only show checkbox column if bulk actions are enabled and editable
    if effective_bulk_actions:
        header_cells.append(
            Th(
                Input(type="checkbox", cls="select-all-checkbox", onclick="toggleSelectAllSamples(this)"),
                cls="checkbox-cell",
            )
        )
    header_cells.extend([
        Th("Sample ID"),
        Th("Test ID"),
        Th("Worksheet"),
    ])
    if show_drop_zones:
        header_cells.append(Th("Index Kit"))
        header_cells.append(Th("Index (i7)"))
        if show_i5_column:
            header_cells.append(Th("Index (i5)"))
        # Show lanes, override cycles, mismatches columns when bulk actions is enabled (read-only when not editable)
        if show_bulk_actions:
            header_cells.append(Th("Lanes"))
            header_cells.append(Th("Override Cycles"))
            header_cells.append(Th("MM i7", title="Barcode Mismatches Index 1"))
            header_cells.append(Th("MM i5", title="Barcode Mismatches Index 2"))
    # Only show actions column if editable
    if editable:
        header_cells.append(Th("", cls="actions-col"))  # Minimal width for delete button

    # Bulk action panel for lane assignment (only if enabled and editable)
    bulk_action_panel = BulkLaneAssignmentPanel(run.id, num_lanes, test_profiles) if effective_bulk_actions else None

    return Div(
        bulk_action_panel,
        Table(
            Thead(Tr(*header_cells)),
            Tbody(
                *[
                    SampleRowWizard(sample, run.id, run.run_cycles, show_drop_zones, show_i5_column, num_lanes, show_bulk_actions, context, editable)
                    for sample in run.samples
                ]
            ),
            cls="sample-table",
        ),
        id="sample-table",
    )


def NewSamplesTableWizard(run: SequencingRun, samples: list, index_kits: list[IndexKit] = None, context: str = "", existing_ids: str = ""):
    """
    Sample table for wizard showing only specific samples (newly added ones).

    This is similar to SampleTableWizard but displays only the provided samples list
    instead of all run samples. Used in Add Samples wizard Step 2.

    Args:
        run: The sequencing run (for run_id and run_cycles)
        samples: List of Sample objects to display
        index_kits: Available index kits
        context: Context string for HTMX endpoints
        existing_ids: Comma-separated list of sample IDs that existed before wizard started
    """
    if not samples:
        return Div(
            P("No new samples to display."),
            cls="empty-message",
            id="sample-table",
            data_existing_ids=existing_ids,
        )

    # Determine if we have single-only or combinatorial kits
    show_i5_column = True
    if index_kits:
        show_i5_column = any(not kit.is_single() for kit in index_kits)

    header_cells = [
        Th("Sample ID"),
        Th("Test ID"),
        Th("Worksheet"),
        Th("Index Kit"),
        Th("Index (i7)"),
    ]
    if show_i5_column:
        header_cells.append(Th("Index (i5)"))
    header_cells.append(Th("", cls="actions-col"))  # Minimal width for delete button

    return Div(
        Table(
            Thead(Tr(*header_cells)),
            Tbody(
                *[
                    SampleRowWizard(sample, run.id, run.run_cycles, show_drop_zones=True, show_i5_column=show_i5_column, num_lanes=1, show_bulk_actions=False, context=context)
                    for sample in samples
                ]
            ),
            cls="sample-table",
        ),
        id="sample-table",
        data_existing_ids=existing_ids,
    )


def BulkLaneAssignmentPanel(run_id: str, num_lanes: int, test_profiles: list = None):
    """Panel for bulk lane, mismatch, override cycles, and test ID assignment to selected samples.

    Args:
        run_id: The run ID for HTMX endpoints
        num_lanes: Number of lanes for the flowcell
        test_profiles: List of TestProfile objects for the dropdown (optional)
    """
    lane_checkboxes = [
        Label(
            Input(
                type="checkbox",
                name="bulk_lane",
                value=str(lane),
                cls="bulk-lane-checkbox",
            ),
            f" {lane}",
            cls="lane-checkbox-label",
        )
        for lane in range(1, num_lanes + 1)
    ]

    return Div(
        # Hidden forms for HTMX submission
        Form(
            Input(type="hidden", name="sample_ids", id="bulk-sample-ids"),
            Input(type="hidden", name="lanes", id="bulk-lanes"),
            hx_post=f"/runs/{run_id}/samples/set-lanes",
            hx_target="#sample-table",
            hx_swap="outerHTML",
            id="bulk-lanes-form",
            style="display: none;",
        ),
        Form(
            Input(type="hidden", name="sample_ids", id="bulk-mismatch-sample-ids"),
            Input(type="hidden", name="mismatch_index1", id="bulk-mismatch-index1"),
            Input(type="hidden", name="mismatch_index2", id="bulk-mismatch-index2"),
            hx_post=f"/runs/{run_id}/samples/set-mismatches",
            hx_target="#sample-table",
            hx_swap="outerHTML",
            id="bulk-mismatches-form",
            style="display: none;",
        ),
        Form(
            Input(type="hidden", name="sample_ids", id="bulk-override-sample-ids"),
            Input(type="hidden", name="override_cycles", id="bulk-override-cycles"),
            hx_post=f"/runs/{run_id}/samples/set-override-cycles",
            hx_target="#sample-table",
            hx_swap="outerHTML",
            id="bulk-override-form",
            style="display: none;",
        ),
        Form(
            Input(type="hidden", name="sample_ids", id="bulk-test-id-sample-ids"),
            Input(type="hidden", name="test_id", id="bulk-test-id"),
            hx_post=f"/runs/{run_id}/samples/set-test-id",
            hx_target="#sample-table",
            hx_swap="outerHTML",
            id="bulk-test-id-form",
            style="display: none;",
        ),
        Form(
            Input(type="hidden", name="sample_ids", id="bulk-delete-sample-ids"),
            hx_post=f"/runs/{run_id}/samples/bulk-delete",
            hx_target="#sample-table",
            hx_swap="outerHTML",
            hx_confirm="Delete selected samples?",
            id="bulk-delete-form",
            style="display: none;",
        ),
        # Header row with selection count and delete button
        Div(
            Span("0", id="selected-sample-count", cls="selected-count"),
            Span(" samples selected", cls="selected-label"),
            Button(
                "Delete Selected",
                type="button",
                onclick="applyBulkDeleteForm()",
                cls="btn btn-danger btn-small bulk-delete-btn",
                id="bulk-delete-btn",
            ),
            cls="selection-info",
        ),
        # Two-column grid layout
        Div(
            # Left column
            Div(
                # Lanes
                Div(
                    Span("Lanes:", cls="bulk-action-label"),
                    Div(*lane_checkboxes, cls="lane-checkboxes"),
                    Div(
                        Button("Apply", type="button", onclick="applyBulkLanesForm()", cls="btn btn-primary btn-small"),
                        Button("Clear", type="button", onclick="clearBulkLanesForm()", cls="btn btn-secondary btn-small"),
                        Button("Toggle", type="button", onclick="toggleBulkLanes()", cls="btn btn-secondary btn-small", title="Invert lane selections"),
                        cls="bulk-action-buttons",
                    ),
                    cls="bulk-action-row",
                ),
                # Mismatches
                Div(
                    Span("Mismatches:", cls="bulk-action-label"),
                    Div(
                        Label("i7:", cls="mismatch-label"),
                        Input(type="number", id="bulk-mismatch-i7-input", placeholder="-", min="0", max="2", cls="mismatch-input bulk-mismatch-input"),
                        Label("i5:", cls="mismatch-label"),
                        Input(type="number", id="bulk-mismatch-i5-input", placeholder="-", min="0", max="2", cls="mismatch-input bulk-mismatch-input"),
                        cls="bulk-action-inputs",
                    ),
                    Div(
                        Button("Apply", type="button", onclick="applyBulkMismatchesForm()", cls="btn btn-primary btn-small"),
                        Button("Clear", type="button", onclick="clearBulkMismatchesForm()", cls="btn btn-secondary btn-small"),
                        cls="bulk-action-buttons",
                    ),
                    cls="bulk-action-row",
                ),
                cls="bulk-action-column",
            ),
            # Right column
            Div(
                # Override cycles
                Div(
                    Span("Override Cycles:", cls="bulk-action-label"),
                    Input(type="text", id="bulk-override-cycles-input", placeholder="e.g., Y151;I8N2;I8N2;Y151", cls="override-cycles-input bulk-override-input"),
                    Div(
                        Button("Apply", type="button", onclick="applyBulkOverrideCyclesForm()", cls="btn btn-primary btn-small"),
                        Button("Auto", type="button", onclick="clearBulkOverrideCyclesForm()", cls="btn btn-secondary btn-small", title="Recalculate override cycles automatically"),
                        cls="bulk-action-buttons",
                    ),
                    cls="bulk-action-row",
                ),
                # Test ID
                Div(
                    Span("Test ID:", cls="bulk-action-label"),
                    _TestIdDropdown(test_profiles),
                    Div(
                        Button("Apply", type="button", onclick="applyBulkTestIdForm()", cls="btn btn-primary btn-small"),
                        Button("Clear", type="button", onclick="clearBulkTestIdForm()", cls="btn btn-secondary btn-small"),
                        cls="bulk-action-buttons",
                    ),
                    cls="bulk-action-row",
                ),
                cls="bulk-action-column",
            ),
            cls="bulk-action-grid",
        ),
        cls="bulk-action-panel",
        id="bulk-action-panel",
    )


def _TestIdDropdown(test_profiles: list = None):
    """Create a dropdown for selecting test profiles.

    Args:
        test_profiles: List of TestProfile objects. If None or empty, shows a message.
    """
    if not test_profiles:
        return Select(
            Option("No test profiles available", value="", disabled=True, selected=True),
            id="bulk-test-id-input",
            cls="test-id-input bulk-test-id-input",
            disabled=True,
        )

    options = [Option("Select a test...", value="", selected=True)]
    for tp in test_profiles:
        # Use test_type as the value (matches sample.test_id)
        label = tp.test_type
        if tp.test_name and tp.test_name != tp.test_type:
            label = f"{tp.test_type} ({tp.test_name})"
        options.append(Option(label, value=tp.test_type))

    return Select(
        *options,
        id="bulk-test-id-input",
        cls="test-id-input bulk-test-id-input",
    )


def SampleRowWizard(sample, run_id: str, run_cycles, show_drop_zones: bool = False, show_i5_column: bool = True, num_lanes: int = 1, show_bulk_actions: bool = True, context: str = "", editable: bool = True):
    """Sample row for wizard with run_id in paths.

    Args:
        sample: The sample to render
        run_id: Run ID for HTMX endpoints
        run_cycles: Run cycle configuration
        show_drop_zones: Whether to show index drop zones
        show_i5_column: Whether to show i5 index column
        num_lanes: Number of lanes
        show_bulk_actions: Whether to show checkbox and bulk action columns
        context: Context string for HTMX endpoints (e.g., "add_step2" for simplified view)
        editable: Whether the row allows editing (delete button, etc.)
    """
    # Build context query string for HTMX endpoints
    ctx_param = f"?context={context}" if context else ""
    has_index = sample.has_index
    has_i7 = sample.index1_sequence is not None
    has_i5 = sample.index2_sequence is not None

    row_class = "sample-row has-index" if has_index else "sample-row"

    # Checkbox for selection (only if bulk actions enabled AND editable)
    checkbox_cell = None
    if show_bulk_actions and editable:
        checkbox_cell = Td(
            Input(
                type="checkbox",
                cls="sample-checkbox",
                data_sample_id=sample.id,
                onclick="handleSampleCheckboxClick(event)",
            ),
            cls="checkbox-cell",
        )

    if show_drop_zones:
        # i7 column - show assigned name+sequence or drop zone
        if has_i7:
            i7_name = sample.index1_name or ""
            i7_well = sample.index1_well_position
            i7_seq = sample.index1_sequence[:8] + ("..." if len(sample.index1_sequence) > 8 else "")
            # Only show clear button in wizard views (not in run view where show_bulk_actions=True)
            clear_button = None
            if not show_bulk_actions:
                clear_i7_url = f"/runs/{run_id}/samples/{sample.id}/clear-index?index_type=i7" + (f"&context={context}" if context else "")
                clear_button = Button(
                    "x",
                    hx_post=clear_i7_url,
                    hx_target=f"#sample-row-{sample.id}",
                    hx_swap="outerHTML",
                    cls="btn-tiny btn-clear",
                    title="Clear i7 index",
                )
            index_i7 = Td(
                Div(
                    Span(i7_name, cls="index-name-display") if i7_name else None,
                    Span(i7_well, cls="index-well-display") if i7_well else None,
                    Span(i7_seq, cls="assigned-index i7"),
                    clear_button,
                    cls="index-assigned",
                ),
                cls="index-cell",
            )
        else:
            if editable:
                index_i7 = Td(
                    Div(
                        "Drop i7",
                        cls="drop-zone i7-drop",
                        data_context=context,
                        ondragover="event.preventDefault(); this.classList.add('drag-over')",
                        ondragleave="this.classList.remove('drag-over')",
                        ondrop=f"handleIndexDrop(event, '{sample.id}', '{run_id}', 'i7')",
                    ),
                )
            else:
                index_i7 = Td(Span("-", cls="no-index"), cls="index-cell")

        # i5 column - show assigned name+sequence or drop zone
        if show_i5_column:
            if has_i5:
                i5_name = sample.index2_name or ""
                i5_well = sample.index2_well_position
                i5_seq = sample.index2_sequence[:8] + ("..." if len(sample.index2_sequence) > 8 else "")
                # Only show clear button in wizard views (not in run view where show_bulk_actions=True)
                clear_button_i5 = None
                if not show_bulk_actions:
                    clear_i5_url = f"/runs/{run_id}/samples/{sample.id}/clear-index?index_type=i5" + (f"&context={context}" if context else "")
                    clear_button_i5 = Button(
                        "x",
                        hx_post=clear_i5_url,
                        hx_target=f"#sample-row-{sample.id}",
                        hx_swap="outerHTML",
                        cls="btn-tiny btn-clear",
                        title="Clear i5 index",
                    )
                index_i5 = Td(
                    Div(
                        Span(i5_name, cls="index-name-display") if i5_name else None,
                        Span(i5_well, cls="index-well-display") if i5_well else None,
                        Span(i5_seq, cls="assigned-index i5"),
                        clear_button_i5,
                        cls="index-assigned",
                    ),
                    cls="index-cell",
                )
            else:
                if editable:
                    index_i5 = Td(
                        Div(
                            "Drop i5",
                            cls="drop-zone i5-drop",
                            data_context=context,
                            ondragover="event.preventDefault(); this.classList.add('drag-over')",
                            ondragleave="this.classList.remove('drag-over')",
                            ondrop=f"handleIndexDrop(event, '{sample.id}', '{run_id}', 'i5')",
                        ),
                    )
                else:
                    index_i5 = Td(Span("-", cls="no-index"), cls="index-cell")
        else:
            index_i5 = None

        # Index kit name cell
        kit_name_cell = Td(
            Span(sample.index_kit_name, cls="kit-name-display") if sample.index_kit_name else Span("-", cls="kit-name-empty"),
            cls="kit-name-cell",
        )

        # Lanes display (read-only, set via bulk action)
        lane_cell = Td(
            Span(sample.lanes_display, cls="lanes-display"),
            cls="lane-cell",
        )

        # Override cycles input (or read-only display)
        if editable:
            override_cell = Td(
                Input(
                    type="text",
                    name="override_cycles",
                    value=sample.override_cycles or "",
                    placeholder="Auto",
                    hx_post=f"/runs/{run_id}/samples/{sample.id}/settings",
                    hx_target=f"#sample-row-{sample.id}",
                    hx_swap="outerHTML",
                    hx_trigger="change",
                    cls="override-cycles-input",
                ),
                cls="override-cell",
            )
        else:
            override_cell = Td(
                Span(sample.override_cycles or "Auto", cls="override-cycles-display"),
                cls="override-cell",
            )

        # Barcode mismatches inputs (or read-only display)
        if editable:
            mismatch_i7_cell = Td(
                Input(
                    type="number",
                    name="barcode_mismatches_index1",
                    value=str(sample.barcode_mismatches_index1) if sample.barcode_mismatches_index1 is not None else "",
                    placeholder="-",
                    min="0",
                    max="2",
                    hx_post=f"/runs/{run_id}/samples/{sample.id}/settings",
                    hx_target=f"#sample-row-{sample.id}",
                    hx_swap="outerHTML",
                    hx_trigger="change",
                    cls="mismatch-input",
                ),
                cls="mismatch-cell",
            )
            mismatch_i5_cell = Td(
                Input(
                    type="number",
                    name="barcode_mismatches_index2",
                    value=str(sample.barcode_mismatches_index2) if sample.barcode_mismatches_index2 is not None else "",
                    placeholder="-",
                    min="0",
                    max="2",
                    hx_post=f"/runs/{run_id}/samples/{sample.id}/settings",
                    hx_target=f"#sample-row-{sample.id}",
                    hx_swap="outerHTML",
                    hx_trigger="change",
                    cls="mismatch-input",
                ),
                cls="mismatch-cell",
            )
        else:
            mismatch_i7_cell = Td(
                Span(str(sample.barcode_mismatches_index1) if sample.barcode_mismatches_index1 is not None else "-", cls="mismatch-display"),
                cls="mismatch-cell",
            )
            mismatch_i5_cell = Td(
                Span(str(sample.barcode_mismatches_index2) if sample.barcode_mismatches_index2 is not None else "-", cls="mismatch-display"),
                cls="mismatch-cell",
            )

        cells = []
        if show_bulk_actions and editable:
            cells.append(checkbox_cell)
        cells.extend([
            Td(sample.sample_id),
            Td(sample.test_id),
            Td(sample.worksheet_id or "-", cls="worksheet-cell"),
            kit_name_cell,
            index_i7,
        ])
        if show_i5_column:
            cells.append(index_i5)
        # Only include lanes, override cycles, mismatches if bulk actions enabled
        if show_bulk_actions:
            cells.extend([lane_cell, override_cell, mismatch_i7_cell, mismatch_i5_cell])

        # Only show delete button if editable
        if editable:
            delete_url = f"/runs/{run_id}/samples/{sample.id}{ctx_param}"

            # For add_step2 context, delete should just remove the row (not refresh entire table)
            # because we don't have access to existing_sample_ids to filter properly
            if context == "add_step2":
                delete_target = f"#sample-row-{sample.id}"
                delete_swap = "outerHTML"
            else:
                delete_target = "#sample-table"
                delete_swap = "outerHTML"

            cells.append(
                Td(
                    Button(
                        "\u00d7",
                        hx_delete=delete_url,
                        hx_target=delete_target,
                        hx_swap=delete_swap,
                        hx_confirm="Delete this sample?",
                        cls="btn-tiny btn-danger",
                        title="Delete sample",
                    ),
                    cls="actions",
                )
            )

        return Tr(
            *cells,
            cls=row_class,
            id=f"sample-row-{sample.id}",
        )
    else:
        # Simple row without drop zones
        cells = []
        if show_bulk_actions and editable:
            cells.append(checkbox_cell)
        cells.extend([
            Td(sample.sample_id),
            Td(sample.test_id),
            Td(sample.worksheet_id or "-", cls="worksheet-cell"),
        ])
        # Only show delete button if editable
        if editable:
            cells.append(
                Td(
                    Button(
                        "\u00d7",
                        hx_delete=f"/runs/{run_id}/samples/{sample.id}",
                        hx_target=f"#sample-row-{sample.id}",
                        hx_swap="outerHTML",
                        hx_confirm="Delete this sample?",
                        cls="btn-tiny btn-danger",
                        title="Delete sample",
                    ),
                    cls="actions",
                )
            )
        return Tr(
            *cells,
            cls=row_class,
            id=f"sample-row-{sample.id}",
        )
