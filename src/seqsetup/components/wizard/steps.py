"""Core wizard navigation and run configuration forms."""

from fasthtml.common import *

from ...models.index import IndexKit
from ...models.sequencing_run import SequencingRun
from ..export_panel import ValidationSummary
from .sample_table import BulkPasteSectionWizard, SampleTableWizard
from .index_panel import IndexKitDropdown, IndexKitPanel


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
    created_at_str = run.created_at.strftime("%Y-%m-%d %H:%M") if run.created_at else "\u2014"
    updated_at_str = run.updated_at.strftime("%Y-%m-%d %H:%M") if run.updated_at else "\u2014"
    created_by_str = run.created_by or "\u2014"

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
                        IndexKitPanel(default_kit) if default_kit else P("No index kits available.", cls="no-kits-message"),
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
    from ...data.instruments import (
        get_enabled_instruments,
        get_flowcells_for_instrument,
        get_reagent_kits_for_flowcell,
    )
    from ...startup import get_instrument_config_repo

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
    from ...data.instruments import get_default_cycles, get_index_cycle_options
    from ...models.sequencing_run import RunCycles

    cycles = run.run_cycles or RunCycles(150, 150, 10, 10)
    defaults = get_default_cycles(run.reagent_cycles)
    index_cycle_options = get_index_cycle_options()

    return Fieldset(
        Legend("Run Cycle Configuration"),
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
