"""Wizard components for step-by-step samplesheet creation."""

from fasthtml.common import *

from ..models.index import Index, IndexKit, IndexMode, IndexType
from ..models.sequencing_run import SequencingRun
from .export_panel import ExportPanel, ValidationSummary
from .index_panel import (
    CombinatorialIndexContent,
    DraggableIndex,
    DraggableIndexPair,
    IndexKitSection,
    SingleIndexContent,
    _escape_js_string,
    _escape_html_attr,
)


def WizardProgress(current_step: int, run_id: str):
    """
    Progress indicator showing wizard steps for new run creation.

    Args:
        current_step: Current step number (1 for new run config)
        run_id: Run ID for navigation links
    """
    steps = [
        ("1", "Run Configuration", f"/runs/new/step/1?run_id={run_id}"),
    ]

    return Div(
        *[
            WizardStepIndicator(
                number=num,
                label=label,
                href=href,
                is_active=(int(num) == current_step),
                is_completed=(int(num) < current_step),
            )
            for num, label, href in steps
        ],
        cls="wizard-progress",
    )


def WizardStepIndicator(
    number: str, label: str, href: str, is_active: bool, is_completed: bool
):
    """Individual step indicator in the wizard progress bar."""
    classes = ["wizard-step"]
    if is_active:
        classes.append("active")
    if is_completed:
        classes.append("completed")

    return A(
        Span(number, cls="step-number"),
        Span(label, cls="step-label"),
        href=href,
        cls=" ".join(classes),
    )


def WizardNavigation(step: int, run_id: str, can_proceed: bool = True, oob: bool = False):
    """
    Navigation buttons for new run wizard (goes to run overview after config).

    Args:
        step: Current step number (1 for new run config)
        run_id: Run ID for navigation
        can_proceed: Whether the Next button should be enabled
        oob: If True, add hx-swap-oob for out-of-band HTMX swap
    """
    attrs = {
        "cls": "wizard-nav",
        "id": f"wizard-nav-step-{step}",
    }
    if oob:
        attrs["hx_swap_oob"] = "true"

    # Step 1 goes to run overview
    return Div(
        A("Cancel", href="/", cls="btn btn-secondary"),
        A(
            "Continue to Run",
            href=f"/runs/{run_id}",
            cls="btn btn-primary",
        ),
        **attrs,
    )


def WizardStep1(run: SequencingRun):
    """
    Wizard Step 1: Run Configuration.

    Configures instrument, flowcell, and cycle settings.
    """
    return Div(
        WizardProgress(1, run.id),
        Div(
            H2("Step 1: Run Configuration"),
            P("Configure the sequencing instrument and cycle settings for this run."),
            RunMetadataDisplayWizard(run),
            Div(
                RunNameFormWizard(run),
                InstrumentConfigFormWizard(run),
                CycleConfigFormWizard(run),
                cls="wizard-form",
            ),
            WizardNavigation(1, run.id),
            cls="wizard-content",
        ),
        cls="wizard-container",
    )


def RunMetadataDisplayWizard(run: SequencingRun):
    """Display read-only run metadata (UUID, user, dates) in wizard."""
    created_at_str = run.created_at.strftime("%Y-%m-%d %H:%M") if run.created_at else "—"
    updated_at_str = run.updated_at.strftime("%Y-%m-%d %H:%M") if run.updated_at else "—"
    created_by_str = run.created_by or "—"

    return Div(
        Div(
            Span("UUID: ", cls="metadata-label"),
            Span(run.id, cls="metadata-value uuid-value", title=run.id),
            cls="metadata-item",
        ),
        Div(
            Span("Created by: ", cls="metadata-label"),
            Span(created_by_str, cls="metadata-value"),
            Span(" | Created: ", cls="metadata-label"),
            Span(created_at_str, cls="metadata-value"),
            Span(" | Updated: ", cls="metadata-label"),
            Span(updated_at_str, cls="metadata-value"),
            cls="metadata-item",
        ),
        cls="run-metadata",
    )


def WizardStep2(run: SequencingRun, index_kits: list[IndexKit], sample_api_enabled: bool = False):
    """
    Wizard Step 2: Samples & Indexes.

    Combined view for adding samples and assigning indexes.
    Allows iteratively adding batches of samples and assigning indexes in one place.
    """
    can_proceed = run.has_samples and run.all_samples_have_indexes

    # Default to first kit if available
    default_kit = index_kits[0] if index_kits else None

    return Div(
        WizardProgress(2, run.id),
        Div(
            H2("Step 2: Samples & Indexes"),
            P("Add samples and assign indexes. You can add samples in batches and assign indexes as you go."),
            # Paste section for adding samples
            BulkPasteSectionWizard(run.id, sample_api_enabled=sample_api_enabled),
            # Tips for index selection
            P(
                "Drag indexes from the panel and drop them onto samples. ",
                Span(id="selection-count", cls="selection-count"),
                cls="selection-hint",
            ),
            P("Tip: Click to select, Ctrl+click to multi-select, Shift+click for range.", cls="selection-hint"),
            Div(
                # Index kits panel on the left
                Aside(
                    H3("Available Indexes"),
                    IndexKitDropdown(index_kits, default_kit.name if default_kit else None),
                    Div(
                        IndexListCompact(default_kit) if default_kit else P("No index kits available.", cls="no-kits-message"),
                        cls="index-kits-compact",
                        id="index-list-container",
                    ),
                    cls="wizard-index-panel",
                ),
                # Sample table on the right with drop zones
                Div(
                    SampleTableWizard(run, show_drop_zones=True),
                    cls="wizard-sample-panel",
                ),
                cls="wizard-step3-layout",
            ),
            WizardNavigation(2, run.id, can_proceed=can_proceed),
            cls="wizard-content",
        ),
        cls="wizard-container",
    )


def WizardStep3(run: SequencingRun):
    """
    Wizard Step 3: Review & Export.

    Shows summary and export options.
    """
    return Div(
        WizardProgress(3, run.id),
        Div(
            H2("Step 3: Review & Export"),
            P("Review your samplesheet configuration and export when ready."),
            Div(
                # Summary section
                Div(
                    H3("Run Summary"),
                    Dl(
                        Dt("Run Name"),
                        Dd(run.run_name or "Not set"),
                        Dt("Instrument"),
                        Dd(run.instrument_platform.value),
                        Dt("Flowcell"),
                        Dd(run.flowcell_type or "Not set"),
                        Dt("Total Samples"),
                        Dd(str(len(run.samples))),
                        Dt("Samples with Indexes"),
                        Dd(str(sum(1 for s in run.samples if s.has_index))),
                        cls="summary-list",
                    ),
                    cls="review-summary",
                ),
                # Validation
                ValidationSummary(run),
                # Export options
                Div(
                    H3("Export Options"),
                    Div(
                        A(
                            "Download Sample Sheet (v2)",
                            href=f"/runs/{run.id}/export/samplesheet",
                            cls="btn btn-primary export-btn",
                        ),
                        cls="export-option",
                    ),
                    Div(
                        A(
                            "Download JSON Metadata",
                            href=f"/runs/{run.id}/export/json",
                            cls="btn btn-secondary export-btn",
                        ),
                        cls="export-option",
                    ),
                    cls="export-section",
                ),
                cls="wizard-review-content",
            ),
            WizardNavigation(3, run.id),
            cls="wizard-content",
        ),
        cls="wizard-container",
    )


# Wizard-specific variants of existing components that use run_id in paths


def RunNameFormWizard(run: SequencingRun):
    """Run name form for wizard with run_id in path."""
    return Form(
        Div(
            Label("Run Name", fr="run_name"),
            Input(
                type="text",
                name="run_name",
                id="run_name",
                value=run.run_name,
                placeholder="e.g., Run_20240115",
            ),
            cls="form-group",
        ),
        Div(
            Label("Description", fr="run_description"),
            Textarea(
                run.run_description,
                name="run_description",
                id="run_description",
                placeholder="Optional run description",
                rows="2",
            ),
            cls="form-group",
        ),
        hx_post=f"/runs/{run.id}/name",
        hx_trigger="change",
        hx_swap="none",
        cls="run-name-form",
    )


def InstrumentConfigFormWizard(run: SequencingRun):
    """Instrument config form for wizard - delegates to original with run_id."""
    from ..data.instruments import (
        get_enabled_instruments,
        get_flowcells_for_instrument,
        get_reagent_kits_for_flowcell,
    )
    from ..app import get_instrument_config_repo

    instrument_config = get_instrument_config_repo().get()
    instruments = get_enabled_instruments(instrument_config)
    current_flowcells = get_flowcells_for_instrument(run.instrument_platform)
    current_reagent_kits = get_reagent_kits_for_flowcell(
        run.instrument_platform, run.flowcell_type
    )

    return Fieldset(
        Legend("Instrument"),
        Div(
            Label("Platform", fr="instrument_platform"),
            Select(
                *[
                    Option(
                        inst["name"],
                        value=inst["platform"].value,
                        selected=run.instrument_platform == inst["platform"],
                    )
                    for inst in instruments
                ],
                name="instrument_platform",
                id="instrument_platform",
                hx_post=f"/runs/{run.id}/instrument",
                hx_target="#flowcell-select",
                hx_swap="outerHTML",
            ),
            cls="form-group",
        ),
        Div(
            Label("Flowcell", fr="flowcell_type"),
            FlowcellSelectWizard(run.id, run.flowcell_type, current_flowcells),
            cls="form-group",
        ),
        Div(
            Label("Reagent Kit (cycles)", fr="reagent_cycles"),
            ReagentKitSelectWizard(run.id, run.reagent_cycles, current_reagent_kits),
            cls="form-group",
        ),
        cls="instrument-config",
    )


def FlowcellSelectWizard(run_id: str, current: str, flowcells: dict):
    """Flowcell dropdown for wizard."""
    return Select(
        *[
            Option(
                f"{fc} - {info['description']}",
                value=fc,
                selected=current == fc,
            )
            for fc, info in flowcells.items()
        ],
        name="flowcell_type",
        id="flowcell-select",
        hx_post=f"/runs/{run_id}/flowcell",
        hx_target="#reagent-kit-select",
        hx_swap="outerHTML",
    )


def ReagentKitSelectWizard(run_id: str, current: int, reagent_kits: list[int]):
    """Reagent kit dropdown for wizard."""
    return Select(
        *[
            Option(
                f"{kit} cycles",
                value=str(kit),
                selected=current == kit,
            )
            for kit in reagent_kits
        ],
        name="reagent_cycles",
        id="reagent-kit-select",
        hx_post=f"/runs/{run_id}/reagent-kit",
        hx_target="#cycle-config",
        hx_swap="outerHTML",
    )


def CycleConfigFormWizard(run: SequencingRun):
    """Cycle config form for wizard with run_id in path."""
    from ..data.instruments import get_default_cycles, get_index_cycle_options
    from ..models.sequencing_run import RunCycles

    cycles = run.run_cycles or RunCycles(150, 150, 10, 10)
    defaults = get_default_cycles(run.reagent_cycles)
    index_cycle_options = get_index_cycle_options()

    return Fieldset(
        Legend("Cycle Configuration"),
        Div(
            Div(
                Label("Read 1", fr="read1_cycles"),
                Input(
                    type="number",
                    name="read1_cycles",
                    id="read1_cycles",
                    value=str(cycles.read1_cycles),
                    min="1",
                    max=str(run.reagent_cycles),
                ),
                cls="form-group",
            ),
            Div(
                Label("Read 2", fr="read2_cycles"),
                Input(
                    type="number",
                    name="read2_cycles",
                    id="read2_cycles",
                    value=str(cycles.read2_cycles),
                    min="0",
                    max=str(run.reagent_cycles),
                ),
                cls="form-group",
            ),
            cls="cycle-row",
        ),
        Div(
            Div(
                Label("Index 1", fr="index1_cycles"),
                Select(
                    *[
                        Option(str(v), value=str(v), selected=cycles.index1_cycles == v)
                        for v in index_cycle_options
                    ],
                    name="index1_cycles",
                    id="index1_cycles",
                ),
                cls="form-group",
            ),
            Div(
                Label("Index 2", fr="index2_cycles"),
                Select(
                    *[
                        Option(str(v), value=str(v), selected=cycles.index2_cycles == v)
                        for v in index_cycle_options
                    ],
                    name="index2_cycles",
                    id="index2_cycles",
                ),
                cls="form-group",
            ),
            cls="cycle-row",
        ),
        Div(
            Span(f"Total: {cycles.total_cycles} / {run.reagent_cycles} cycles"),
            cls="cycle-total",
        ),
        Button("Apply Cycles", type="submit", cls="btn-primary btn-small"),
        hx_post=f"/runs/{run.id}/cycles",
        hx_target="#sample-table",
        hx_swap="outerHTML",
        cls="cycle-config",
        id="cycle-config",
    )


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
                        wl.get("name", wl["id"]),
                        value=wl["id"],
                    )
                    for wl in worklists
                ],
                name="worklist_id",
                id="worklist-select",
                cls="index-kit-dropdown",
                style="max-width:400px; display:inline-block;",
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
        Div(id="worklist-import-result"),
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


def SampleTableWizard(run: SequencingRun, show_drop_zones: bool = False, index_kits: list[IndexKit] = None, num_lanes: int = 1, show_bulk_actions: bool = True, context: str = ""):
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

    header_cells = []
    # Only show checkbox column if bulk actions are enabled
    if show_bulk_actions:
        header_cells.append(
            Th(
                Input(type="checkbox", cls="select-all-checkbox", onclick="toggleSelectAllSamples(this)"),
                cls="checkbox-cell",
            )
        )
    header_cells.extend([
        Th("Sample ID"),
        Th("Test ID"),
    ])
    if show_drop_zones:
        header_cells.append(Th("Index Kit"))
        header_cells.append(Th("Index (i7)"))
        if show_i5_column:
            header_cells.append(Th("Index (i5)"))
        # Only show lanes, override cycles, mismatches if bulk actions enabled
        if show_bulk_actions:
            header_cells.append(Th("Lanes"))
            header_cells.append(Th("Override Cycles"))
            header_cells.append(Th("MM i7", title="Barcode Mismatches Index 1"))
            header_cells.append(Th("MM i5", title="Barcode Mismatches Index 2"))
    header_cells.append(Th("Actions"))

    # Bulk action panel for lane assignment (only if enabled)
    bulk_action_panel = BulkLaneAssignmentPanel(run.id, num_lanes) if show_bulk_actions else None

    return Div(
        bulk_action_panel,
        Table(
            Thead(Tr(*header_cells)),
            Tbody(
                *[
                    SampleRowWizard(sample, run.id, run.run_cycles, show_drop_zones, show_i5_column, num_lanes, show_bulk_actions, context)
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
        Th("Index Kit"),
        Th("Index (i7)"),
    ]
    if show_i5_column:
        header_cells.append(Th("Index (i5)"))
    header_cells.append(Th("Actions"))

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


def BulkLaneAssignmentPanel(run_id: str, num_lanes: int):
    """Panel for bulk lane, mismatch, and override cycles assignment to selected samples."""
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
        # Header row with selection count
        Div(
            Span("0", id="selected-sample-count", cls="selected-count"),
            Span(" samples selected", cls="selected-label"),
            cls="selection-info",
        ),
        # Grid layout for action rows
        Div(
            # Row 1 - Lanes
            Span("Lanes:", cls="bulk-action-label"),
            Div(*lane_checkboxes, cls="lane-checkboxes"),
            Div(
                Button(
                    "Apply",
                    type="button",
                    onclick="applyBulkLanesForm()",
                    cls="btn btn-primary btn-small",
                ),
                Button(
                    "Clear",
                    type="button",
                    onclick="clearBulkLanesForm()",
                    cls="btn btn-secondary btn-small",
                ),
                Button(
                    "Toggle",
                    type="button",
                    onclick="toggleBulkLanes()",
                    cls="btn btn-secondary btn-small",
                    title="Invert lane selections",
                ),
                cls="bulk-action-buttons",
            ),
            # Row 2 - Override cycles
            Span("Override Cycles:", cls="bulk-action-label"),
            Input(
                type="text",
                id="bulk-override-cycles-input",
                placeholder="e.g., Y151;I8N2;I8N2;Y151",
                cls="override-cycles-input bulk-override-input",
            ),
            Div(
                Button(
                    "Apply",
                    type="button",
                    onclick="applyBulkOverrideCyclesForm()",
                    cls="btn btn-primary btn-small",
                ),
                Button(
                    "Auto",
                    type="button",
                    onclick="clearBulkOverrideCyclesForm()",
                    cls="btn btn-secondary btn-small",
                    title="Recalculate override cycles automatically",
                ),
                cls="bulk-action-buttons",
            ),
            # Row 3 - Mismatches
            Span("Mismatches:", cls="bulk-action-label"),
            Div(
                Label("i7:", cls="mismatch-label"),
                Input(
                    type="number",
                    id="bulk-mismatch-i7-input",
                    placeholder="-",
                    min="0",
                    max="2",
                    cls="mismatch-input bulk-mismatch-input",
                ),
                Label("i5:", cls="mismatch-label"),
                Input(
                    type="number",
                    id="bulk-mismatch-i5-input",
                    placeholder="-",
                    min="0",
                    max="2",
                    cls="mismatch-input bulk-mismatch-input",
                ),
                cls="bulk-action-inputs",
            ),
            Div(
                Button(
                    "Apply",
                    type="button",
                    onclick="applyBulkMismatchesForm()",
                    cls="btn btn-primary btn-small",
                ),
                Button(
                    "Clear",
                    type="button",
                    onclick="clearBulkMismatchesForm()",
                    cls="btn btn-secondary btn-small",
                ),
                cls="bulk-action-buttons",
            ),
            cls="bulk-action-grid",
        ),
        cls="bulk-action-panel",
        id="bulk-action-panel",
    )


def SampleRowWizard(sample, run_id: str, run_cycles, show_drop_zones: bool = False, show_i5_column: bool = True, num_lanes: int = 1, show_bulk_actions: bool = True, context: str = ""):
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
    """
    # Build context query string for HTMX endpoints
    ctx_param = f"?context={context}" if context else ""
    has_index = sample.has_index
    has_i7 = sample.index1_sequence is not None
    has_i5 = sample.index2_sequence is not None

    row_class = "sample-row has-index" if has_index else "sample-row"

    # Checkbox for selection (only if bulk actions enabled)
    checkbox_cell = None
    if show_bulk_actions:
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
            i7_seq = sample.index1_sequence[:8] + ("..." if len(sample.index1_sequence) > 8 else "")
            clear_i7_url = f"/runs/{run_id}/samples/{sample.id}/clear-index?index_type=i7" + (f"&context={context}" if context else "")
            index_i7 = Td(
                Div(
                    Span(i7_name, cls="index-name-display") if i7_name else None,
                    Span(i7_seq, cls="assigned-index i7"),
                    Button(
                        "x",
                        hx_post=clear_i7_url,
                        hx_target=f"#sample-row-{sample.id}",
                        hx_swap="outerHTML",
                        cls="btn-tiny btn-clear",
                        title="Clear i7 index",
                    ),
                    cls="index-assigned",
                ),
                cls="index-cell",
            )
        else:
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

        # i5 column - show assigned name+sequence or drop zone
        if show_i5_column:
            if has_i5:
                i5_name = sample.index2_name or ""
                i5_seq = sample.index2_sequence[:8] + ("..." if len(sample.index2_sequence) > 8 else "")
                clear_i5_url = f"/runs/{run_id}/samples/{sample.id}/clear-index?index_type=i5" + (f"&context={context}" if context else "")
                index_i5 = Td(
                    Div(
                        Span(i5_name, cls="index-name-display") if i5_name else None,
                        Span(i5_seq, cls="assigned-index i5"),
                        Button(
                            "x",
                            hx_post=clear_i5_url,
                            hx_target=f"#sample-row-{sample.id}",
                            hx_swap="outerHTML",
                            cls="btn-tiny btn-clear",
                            title="Clear i5 index",
                        ),
                        cls="index-assigned",
                    ),
                    cls="index-cell",
                )
            else:
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

        # Override cycles input
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

        # Barcode mismatches inputs
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

        cells = []
        if show_bulk_actions:
            cells.append(checkbox_cell)
        cells.extend([
            Td(sample.sample_id),
            Td(sample.test_id),
            kit_name_cell,
            index_i7,
        ])
        if show_i5_column:
            cells.append(index_i5)
        # Only include lanes, override cycles, mismatches if bulk actions enabled
        if show_bulk_actions:
            cells.extend([lane_cell, override_cell, mismatch_i7_cell, mismatch_i5_cell])
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
                    "Delete",
                    hx_delete=delete_url,
                    hx_target=delete_target,
                    hx_swap=delete_swap,
                    cls="btn-small btn-danger",
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
        if show_bulk_actions:
            cells.append(checkbox_cell)
        cells.extend([
            Td(sample.sample_id),
            Td(sample.test_id),
            Td(
                Button(
                    "Delete",
                    hx_delete=f"/runs/{run_id}/samples/{sample.id}",
                    hx_target=f"#sample-row-{sample.id}",
                    hx_swap="outerHTML",
                    cls="btn-small btn-danger",
                ),
                cls="actions",
            ),
        ])
        return Tr(
            *cells,
            cls=row_class,
            id=f"sample-row-{sample.id}",
        )


def IndexKitSectionCompact(kit: IndexKit):
    """Compact index kit section for wizard step 2 (Samples & Indexes)."""
    # Determine display info based on mode
    mode_label = {
        IndexMode.UNIQUE_DUAL: "Dual",
        IndexMode.COMBINATORIAL: "Comb",
        IndexMode.SINGLE: "Single",
    }.get(kit.index_mode, "Dual")

    if kit.is_combinatorial():
        index_count = len(kit.i7_indexes) + len(kit.i5_indexes)
        content = CombinatorialIndexContent(kit)
    elif kit.is_single():
        index_count = len(kit.i7_indexes)
        content = SingleIndexContent(kit)
    else:
        index_count = len(kit.index_pairs)
        content = Div(
            *[DraggableIndexPair(pair) for pair in kit.index_pairs],
            cls="index-grid",
        )

    return Details(
        Summary(
            Span(f"{kit.name}", cls="kit-name"),
            Span(f"[{mode_label}]", cls="kit-mode-badge"),
            Span(f"({index_count})", cls="kit-count"),
        ),
        content,
        open=True,
        cls="index-kit-section",
    )


def IndexKitDropdown(index_kits: list[IndexKit], selected_kit_name: str = None):
    """Dropdown to select which index kit to display."""
    if not index_kits:
        return None

    return Select(
        *[
            Option(
                f"{kit.name} v{kit.version} ({_get_kit_count(kit)} indexes)",
                value=kit.kit_id,
                selected=kit.kit_id == selected_kit_name,
            )
            for kit in index_kits
        ],
        name="selected_kit",
        id="index-kit-dropdown",
        hx_get="/indexes/kit-content",
        hx_target="#index-list-container",
        hx_swap="innerHTML",
        hx_trigger="change",
        cls="index-kit-dropdown",
    )


def _get_kit_count(kit: IndexKit) -> int:
    """Get the total index count for a kit."""
    if kit.is_combinatorial():
        return len(kit.i7_indexes) + len(kit.i5_indexes)
    elif kit.is_single():
        return len(kit.i7_indexes)
    else:
        return len(kit.index_pairs)


def IndexListCompact(kit: IndexKit):
    """
    Compact single-column index list with i7/i5 side by side.

    Args:
        kit: Index kit to display
    """
    if kit is None:
        return P("Select an index kit", cls="no-kits-message")

    if kit.is_combinatorial():
        # For combinatorial, show i7 and i5 in separate sections
        return Div(
            Div(
                Strong("i7 Indexes", cls="index-subsection-header"),
                Div(
                    *[DraggableIndexCompact(idx, kit.name, "i7") for idx in kit.i7_indexes],
                    cls="index-list",
                ),
                cls="index-subsection i7-section",
            ),
            Div(
                Strong("i5 Indexes", cls="index-subsection-header"),
                Div(
                    *[DraggableIndexCompact(idx, kit.name, "i5") for idx in kit.i5_indexes],
                    cls="index-list",
                ),
                cls="index-subsection i5-section",
            ),
            cls="combinatorial-content",
        )
    elif kit.is_single():
        # Single mode - only i7
        return Div(
            *[DraggableIndexCompact(idx, kit.name, "i7") for idx in kit.i7_indexes],
            cls="index-list",
        )
    else:
        # Unique dual - show pairs with i7/i5 side by side
        return Div(
            *[DraggableIndexPairCompact(pair) for pair in kit.index_pairs],
            cls="index-list",
        )


def DraggableIndexPairCompact(pair):
    """Compact draggable index pair with i7/i5 side by side."""
    from ..models.index import IndexPair

    i7_seq = pair.index1_sequence[:8] + ("..." if len(pair.index1_sequence) > 8 else "")
    i5_seq = ""
    if pair.index2_sequence:
        i5_seq = pair.index2_sequence[:8] + ("..." if len(pair.index2_sequence) > 8 else "")

    # Escape user data for safe use in JavaScript event handlers
    safe_id = _escape_js_string(pair.id)
    safe_name = _escape_html_attr(pair.name)

    return Div(
        Span(pair.name, cls="index-name-compact"),
        Div(
            Span(i7_seq, cls="index-seq-compact i7"),
            Span(i5_seq, cls="index-seq-compact i5") if i5_seq else None,
            cls="index-seqs-inline",
        ),
        cls="draggable-index-compact draggable-pair",
        draggable="true",
        data_index_pair_id=pair.id,
        data_index_name=pair.name,
        data_index_type="pair",
        onclick=f"handleIndexClick(event, '{safe_id}', 'pair')",
        ondragstart=f"handleDragStart(event, '{safe_id}', 'pair')",
        title=f"{safe_name}\ni7: {pair.index1_sequence}\ni5: {pair.index2_sequence or 'N/A'}",
    )


def DraggableIndexCompact(index, kit_name: str, index_type: str):
    """Compact draggable individual index (for combinatorial/single mode)."""
    from ..models.index import Index, IndexType

    seq_preview = index.sequence[:10] + ("..." if len(index.sequence) > 10 else "")
    index_id = f"{kit_name}_{index_type}_{index.name}"

    # Escape user data for safe use in JavaScript event handlers
    safe_index_id = _escape_js_string(index_id)
    safe_name = _escape_html_attr(index.name)

    return Div(
        Span(index.name, cls="index-name-compact"),
        Span(seq_preview, cls=f"index-seq-compact {index_type}"),
        cls=f"draggable-index-compact draggable-single {index_type}-index",
        draggable="true",
        data_index_id=index_id,
        data_index_name=index.name,
        data_index_type=index_type,
        data_kit_name=kit_name,
        onclick=f"handleIndexClick(event, '{safe_index_id}', '{index_type}')",
        ondragstart=f"handleDragStart(event, '{safe_index_id}', '{index_type}')",
        title=f"{safe_name}: {index.sequence}",
    )


# =============================================================================
# Add Samples Wizard Components
# =============================================================================
# A 2-step wizard for adding samples to an existing run:
# Step 1: Add samples (sample_id + test_id required)
# Step 2: Assign indexes to the newly added samples


def AddSamplesWizardProgress(current_step: int, run_id: str):
    """
    Progress indicator for Add Samples wizard.

    Args:
        current_step: Current step (1 or 2)
        run_id: Run ID for navigation
    """
    steps = [
        ("1", "Add Samples", f"/runs/{run_id}/samples/add/step/1"),
        ("2", "Assign Indexes", f"/runs/{run_id}/samples/add/step/2"),
    ]

    return Div(
        *[
            WizardStepIndicator(
                number=num,
                label=label,
                href=href,
                is_active=(int(num) == current_step),
                is_completed=(int(num) < current_step),
            )
            for num, label, href in steps
        ],
        cls="wizard-progress",
    )


def AddSamplesStep1(run: SequencingRun, existing_sample_ids: list[str] = None, sample_api_enabled: bool = False):
    """
    Add Samples Wizard Step 1: Enter samples.

    Allows entering sample_id and test_id for new samples.
    This step shows only newly added samples, not existing ones from the run.

    Args:
        run: The sequencing run
        existing_sample_ids: List of sample IDs that existed before the wizard started.
                            If None, captures current sample IDs as existing.
        sample_api_enabled: Whether the Sample API is configured and enabled.
    """
    # Capture existing sample IDs when entering the wizard
    if existing_sample_ids is None:
        existing_sample_ids = [s.id for s in run.samples]

    # Encode existing IDs for passing to Step 2
    existing_ids_param = ",".join(existing_sample_ids) if existing_sample_ids else ""

    return Div(
        AddSamplesWizardProgress(1, run.id),
        Div(
            H2("Step 1: Add Samples"),
            P("Paste or import samples from a spreadsheet. Optionally include index sequences.", cls="step-description"),
            # Paste / file import section
            Div(
                H3("Import Samples"),
                SamplePasteFormatHelp(),
                Form(
                    Textarea(
                        "",
                        name="paste_data",
                        id="paste_data",
                        placeholder="sample_id\ttest_id\tindex_i7\tindex_i5\nSample001\tWGS\tATTACTCG\tTATAGCCT\nSample002\tRNA\tTCCGGAGA\tATAGAGGC\nSample003\tWGS\tCGCTCATT\tCCTATCCT",
                        cls="paste-textarea",
                        rows="8",
                    ),
                    Div(
                        Span("or import from file:", cls="file-upload-label"),
                        Input(
                            type="file",
                            name="sample_file",
                            id="sample_file_step1",
                            accept=".csv,.tsv,.txt",
                            cls="sample-file-input",
                        ),
                        cls="file-upload-row",
                    ),
                    Div(
                        Button("Add Samples", type="submit", cls="btn btn-primary"),
                        Button(
                            "Clear",
                            type="button",
                            cls="btn btn-secondary",
                            onclick="document.getElementById('paste_data').value=''; document.getElementById('sample_file_step1').value=''",
                        ),
                        cls="paste-buttons",
                    ),
                    hx_post=f"/runs/{run.id}/samples/bulk?context=add_step1&existing_ids={existing_ids_param}",
                    hx_target="#add-samples-result",
                    hx_swap="innerHTML",
                    hx_encoding="multipart/form-data",
                ),
                FetchFromApiSection(run.id, target="#add-samples-result", context="add_step1", existing_ids=existing_ids_param) if sample_api_enabled else None,
                cls="paste-section",
            ),
            # Result message for newly added samples
            Div(
                P("Paste sample data above and click 'Add Samples'.", cls="hint-message"),
                id="add-samples-result",
            ),
            AddSamplesNavigation(1, run.id, can_proceed=True, existing_ids=existing_ids_param),
            cls="wizard-content",
        ),
        cls="wizard-container",
    )


def AddSamplesStep2(run: SequencingRun, index_kits: list[IndexKit], existing_sample_ids: list[str] = None):
    """
    Add Samples Wizard Step 2: Assign indexes to samples.

    Shows only newly added samples (those not in existing_sample_ids) and allows drag-drop assignment.

    Args:
        run: The sequencing run
        index_kits: Available index kits
        existing_sample_ids: List of sample IDs that existed before the wizard started.
                            Only samples NOT in this list will be shown.
    """
    # Filter to only newly added samples (not in existing_sample_ids)
    existing_ids_set = set(existing_sample_ids) if existing_sample_ids else set()
    new_samples = [s for s in run.samples if s.id not in existing_ids_set]

    # Check if all new samples have indexes
    samples_without_indexes = [s for s in new_samples if not s.has_index]
    all_have_indexes = len(samples_without_indexes) == 0

    default_kit = index_kits[0] if index_kits else None

    # Encode existing IDs for passing back to Step 1 (Back button)
    existing_ids_param = ",".join(existing_sample_ids) if existing_sample_ids else ""

    return Div(
        AddSamplesWizardProgress(2, run.id),
        Div(
            H2("Step 2: Assign Indexes"),
            P(f"Assign indexes to {len(new_samples)} new sample(s).") if new_samples and not all_have_indexes else None,
            P("No new samples to assign indexes to.") if not new_samples else None,
            Div(
                # Index kits panel on the left
                Aside(
                    H3("Available Indexes"),
                    IndexKitDropdown(index_kits, default_kit.name if default_kit else None),
                    Div(
                        IndexListCompact(default_kit) if default_kit else P("No index kits available.", cls="no-kits-message"),
                        cls="index-kits-compact",
                        id="index-list-container",
                    ),
                    cls="wizard-index-panel",
                ) if new_samples and not all_have_indexes else None,
                # Sample table on the right with drop zones (no bulk actions in this wizard)
                Div(
                    P("All samples have indexes assigned.", cls="all-indexed-message") if all_have_indexes and new_samples else None,
                    NewSamplesTableWizard(run, new_samples, index_kits, context="add_step2", existing_ids=existing_ids_param) if new_samples else None,
                    cls="wizard-sample-panel",
                ),
                cls="wizard-step3-layout" if new_samples and not all_have_indexes else "wizard-sample-only",
            ),
            AddSamplesNavigation(2, run.id, can_proceed=True, existing_ids=existing_ids_param),
            cls="wizard-content",
        ),
        cls="wizard-container",
    )


def AddSamplesNavigation(step: int, run_id: str, can_proceed: bool = True, oob: bool = False, existing_ids: str = ""):
    """
    Navigation buttons for Add Samples wizard.

    Args:
        step: Current step (1 or 2)
        run_id: Run ID for navigation
        can_proceed: Whether user can proceed to next step
        oob: If True, add hx-swap-oob for out-of-band HTMX swap
        existing_ids: Comma-separated list of sample IDs that existed before wizard started
    """
    attrs = {
        "cls": "wizard-nav",
        "id": "add-samples-nav",
    }
    if oob:
        attrs["hx_swap_oob"] = "true"

    # Build query string for passing existing IDs
    existing_param = f"?existing={existing_ids}" if existing_ids else ""

    if step == 1:
        return Div(
            A("Cancel", href=f"/runs/{run_id}", cls="btn btn-secondary"),
            A(
                "Next: Assign Indexes",
                href=f"/runs/{run_id}/samples/add/step/2{existing_param}",
                cls=f"btn btn-primary {'disabled' if not can_proceed else ''}",
            ),
            **attrs,
        )
    else:  # step == 2
        return Div(
            A("Back", href=f"/runs/{run_id}/samples/add/step/1{existing_param}", cls="btn btn-secondary"),
            A(
                "Finish",
                href=f"/runs/{run_id}",
                cls="btn btn-primary",
            ),
            **attrs,
        )


def NewSamplesPreviewTable(run: SequencingRun):
    """Preview table showing samples that will be added."""
    if not run.samples:
        return P("No samples added yet. Paste data above to add samples.", cls="empty-message")

    return Table(
        Thead(
            Tr(
                Th("Sample ID"),
                Th("Test ID"),
                Th("Actions"),
            )
        ),
        Tbody(
            *[
                Tr(
                    Td(sample.sample_id),
                    Td(sample.test_id),
                    Td(
                        Button(
                            "Remove",
                            hx_delete=f"/runs/{run.id}/samples/{sample.id}?context=add_step1",
                            hx_target="#new-samples-preview",
                            hx_swap="innerHTML",
                            cls="btn-small btn-danger",
                        ),
                    ),
                )
                for sample in run.samples
            ]
        ),
        cls="sample-preview-table",
    )
