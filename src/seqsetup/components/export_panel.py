"""Validation summary UI component."""

from typing import Optional

from fasthtml.common import *

from ..models.sequencing_run import SequencingRun
from ..models.validation import ValidationResult
from ..services.validation import ValidationService


def ValidationSummary(run: SequencingRun, validation_result: Optional[ValidationResult] = None):
    """
    Display validation status and warnings.

    Args:
        run: Sequencing run
        validation_result: Pre-computed validation result. If None, runs basic validation
                          as fallback (no profile checks).
    """
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
        # Use pre-computed result or fall back to basic validation
        if validation_result is None:
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
