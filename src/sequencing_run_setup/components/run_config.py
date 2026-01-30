"""Run configuration UI component (read-only display for overview)."""

from fasthtml.common import *

from ..data.instruments import get_flowcells_for_instrument
from ..models.sequencing_run import RunCycles, SequencingRun


def RunConfigPanel(run: SequencingRun):
    """
    Read-only panel displaying the sequencing run configuration.

    Args:
        run: Current sequencing run configuration
    """
    return Div(
        H3("Run Configuration"),
        RunMetadataDisplay(run),
        RunNameDisplay(run),
        InstrumentConfigDisplay(run),
        CycleConfigDisplay(run),
        cls="run-config-panel",
        id="run-config-panel",
    )


def RunMetadataDisplay(run: SequencingRun):
    """Display read-only run metadata (UUID, user, dates)."""
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
            cls="metadata-item",
        ),
        Div(
            Span("Created: ", cls="metadata-label"),
            Span(created_at_str, cls="metadata-value"),
            Span(" | Updated: ", cls="metadata-label"),
            Span(updated_at_str, cls="metadata-value"),
            cls="metadata-item",
        ),
        cls="run-metadata",
    )


def RunNameDisplay(run: SequencingRun):
    """Read-only display of run name and description."""
    return Div(
        Div(
            Span("Run Name: ", cls="config-label"),
            Span(run.run_name or "—", cls="config-value"),
            cls="config-item",
        ),
        Div(
            Span("Description: ", cls="config-label"),
            Span(run.run_description or "—", cls="config-value"),
            cls="config-item",
        ) if run.run_description else None,
        cls="run-name-display",
    )


def InstrumentConfigDisplay(run: SequencingRun):
    """Read-only display of instrument configuration."""
    # Get flowcell description
    flowcells = get_flowcells_for_instrument(run.instrument_platform)
    flowcell_info = flowcells.get(run.flowcell_type, {})
    flowcell_desc = flowcell_info.get("description", run.flowcell_type)

    return Fieldset(
        Legend("Instrument"),
        Div(
            Div(
                Span("Platform: ", cls="config-label"),
                Span(run.instrument_platform.value, cls="config-value"),
                cls="config-item",
            ),
            Div(
                Span("Flowcell: ", cls="config-label"),
                Span(f"{run.flowcell_type} - {flowcell_desc}", cls="config-value"),
                cls="config-item",
            ),
            Div(
                Span("Reagent Kit: ", cls="config-label"),
                Span(f"{run.reagent_cycles} cycles", cls="config-value"),
                cls="config-item",
            ),
            cls="instrument-display",
        ),
        cls="config-panel instrument-config-display",
    )


def CycleConfigDisplay(run: SequencingRun):
    """Read-only display of cycle configuration."""
    cycles = run.run_cycles or RunCycles(150, 150, 10, 10)

    return Fieldset(
        Legend("Cycle Configuration"),
        Div(
            Div(
                Span("Read 1: ", cls="cycle-label"),
                Span(str(cycles.read1_cycles), cls="cycle-value"),
                cls="cycle-item",
            ),
            Div(
                Span("Read 2: ", cls="cycle-label"),
                Span(str(cycles.read2_cycles), cls="cycle-value"),
                cls="cycle-item",
            ),
            Div(
                Span("Index 1: ", cls="cycle-label"),
                Span(str(cycles.index1_cycles), cls="cycle-value"),
                cls="cycle-item",
            ),
            Div(
                Span("Index 2: ", cls="cycle-label"),
                Span(str(cycles.index2_cycles), cls="cycle-value"),
                cls="cycle-item",
            ),
            cls="cycle-display",
        ),
        cls="config-panel cycle-config-display",
        id="cycle-config",
    )
