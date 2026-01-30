"""Export panel UI component."""

from fasthtml.common import *

from ..models.sequencing_run import SequencingRun
from ..services.validation import ValidationService


def ExportPanel(run: SequencingRun):
    """
    Panel with export options.

    Args:
        run: Current sequencing run
    """
    has_samples = run.has_samples
    all_indexed = run.all_samples_have_indexes if has_samples else False

    return Div(
        H3("Export"),
        Div(
            A(
                "Download SampleSheet v2",
                href="/export/samplesheet",
                cls="btn btn-primary" + ("" if all_indexed else " disabled"),
                download=f"{run.run_name or 'SampleSheet'}.csv",
            ),
            P(
                "All samples must have indexes assigned",
                cls="export-warning",
            ) if not all_indexed else None,
            cls="export-option",
        ),
        Div(
            A(
                "Download JSON Metadata",
                href="/export/json",
                cls="btn btn-secondary",
                download=f"{run.run_name or 'run_metadata'}.json",
            ),
            cls="export-option",
        ),
        ValidationSummary(run),
        cls="export-panel",
        id="export-panel",
    )


def ValidationSummary(run: SequencingRun):
    """Display validation status and warnings."""
    warnings = []
    errors = []

    if not run.has_samples:
        warnings.append("No samples added yet")
    elif not run.all_samples_have_indexes:
        samples_without = sum(1 for s in run.samples if not s.has_index)
        errors.append(f"{samples_without} sample(s) missing indexes")

    if not run.run_name:
        warnings.append("Run name not set")

    if not run.flowcell_type:
        warnings.append("Flowcell not selected")

    if not run.run_cycles:
        warnings.append("Cycles not configured")

    # Run index validation if we have samples with indexes
    validation_link = None
    if run.has_samples:
        validation_result = ValidationService.validate_run(run)

        # Add duplicate sample ID errors
        for dup_error in validation_result.duplicate_sample_ids:
            errors.append(dup_error)

        # Add index collision errors (summarized)
        if validation_result.index_collisions:
            collision_count = len(validation_result.index_collisions)
            errors.append(f"{collision_count} index collision(s) detected")

        # Add link to full validation page
        validation_link = A(
            "View validation details",
            href=f"/runs/{run.id}/validation",
            cls="validation-link",
        )

    if not errors and not warnings:
        return Div(
            P("Ready to export", cls="status-ok"),
            validation_link,
            cls="validation-summary ok",
        )

    return Div(
        *[P(f"Error: {e}", cls="status-error") for e in errors],
        *[P(f"Warning: {w}", cls="status-warning") for w in warnings],
        validation_link,
        cls="validation-summary" + (" has-errors" if errors else ""),
    )
