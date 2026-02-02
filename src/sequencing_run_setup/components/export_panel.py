"""Export panel UI component."""

from fasthtml.common import *

from ..models.sequencing_run import RunStatus, SequencingRun
from ..services.samplesheet_v1_exporter import SampleSheetV1Exporter
from ..services.validation import ValidationService


def ExportPanel(run: SequencingRun):
    """
    Panel with export options.

    Args:
        run: Current sequencing run
    """
    has_samples = run.has_samples
    all_indexed = run.all_samples_have_indexes if has_samples else False
    is_ready = run.status == RunStatus.READY

    # SampleSheet and JSON: enabled only when ready
    ss_enabled = is_ready and all_indexed
    json_enabled = is_ready
    has_v1 = SampleSheetV1Exporter.supports(run.instrument_platform)
    v1_enabled = is_ready and all_indexed

    # Validation reports: enabled only when pre-generated data exists
    val_json_enabled = run.generated_validation_json is not None
    val_pdf_enabled = run.generated_validation_pdf is not None

    v1_option = Div(
        A(
            "Download SampleSheet v1",
            href=f"/runs/{run.id}/export/samplesheet-v1" if v1_enabled else None,
            cls="btn btn-primary" + ("" if v1_enabled else " disabled"),
            download=f"{run.run_name or 'SampleSheet'}_v1.csv" if v1_enabled else None,
        ),
        P(
            "Run must be marked as ready" if not is_ready else "All samples must have indexes assigned",
            cls="export-warning",
        ) if not v1_enabled else None,
        cls="export-option",
    ) if has_v1 else None

    return Div(
        H3("Export"),
        Div(
            A(
                "Download SampleSheet v2",
                href=f"/runs/{run.id}/export/samplesheet" if ss_enabled else None,
                cls="btn btn-primary" + ("" if ss_enabled else " disabled"),
                download=f"{run.run_name or 'SampleSheet'}.csv" if ss_enabled else None,
            ),
            P(
                "Run must be marked as ready" if not is_ready else "All samples must have indexes assigned",
                cls="export-warning",
            ) if not ss_enabled else None,
            cls="export-option",
        ),
        v1_option,
        Div(
            A(
                "Download JSON Metadata",
                href=f"/runs/{run.id}/export/json" if json_enabled else None,
                cls="btn btn-secondary" + ("" if json_enabled else " disabled"),
                download=f"{run.run_name or 'run_metadata'}.json" if json_enabled else None,
            ),
            P(
                "Run must be marked as ready",
                cls="export-warning",
            ) if not json_enabled else None,
            cls="export-option",
        ),
        Div(
            A(
                "Download Validation Report (JSON)",
                href=f"/runs/{run.id}/export/validation-report" if val_json_enabled else None,
                cls="btn btn-secondary" + ("" if val_json_enabled else " disabled"),
                download=f"{run.run_name or 'validation_report'}_validation.json" if val_json_enabled else None,
            ),
            A(
                "Download Validation Report (PDF)",
                href=f"/runs/{run.id}/export/validation-pdf" if val_pdf_enabled else None,
                cls="btn btn-secondary" + ("" if val_pdf_enabled else " disabled"),
                download=f"{run.run_name or 'validation_report'}_validation.pdf" if val_pdf_enabled else None,
            ),
            P(
                "Run must be marked as ready to generate reports",
                cls="export-warning",
            ) if not (val_json_enabled and val_pdf_enabled) else None,
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
