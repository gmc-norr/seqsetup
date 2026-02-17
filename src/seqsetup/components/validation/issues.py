"""Validation issues tab: error/warning rendering and collision details."""

from fasthtml.common import *

from ...models.validation import (
    ApplicationValidationError,
    ConfigurationError,
    DarkCycleError,
    IndexCollision,
    ValidationResult,
    ValidationSeverity,
)


def IssuesTabContent(result: ValidationResult):
    """Content for the Issues tab."""
    errors = []

    # Duplicate sample IDs are errors
    for error in result.duplicate_sample_ids:
        errors.append(("duplicate", error))

    # Index collisions are errors
    for collision in result.index_collisions:
        errors.append(("collision", collision))

    # Dark cycle errors
    for dark_err in result.dark_cycle_errors:
        errors.append(("dark_cycle", dark_err))

    # Application profile errors
    for app_err in result.application_errors:
        errors.append(("application", app_err))

    # Configuration errors
    for cfg_err in result.configuration_errors:
        if cfg_err.severity == ValidationSeverity.ERROR:
            errors.append(("config", cfg_err))

    # Configuration warnings (separate list)
    warnings = []
    for cfg_err in result.configuration_errors:
        if cfg_err.severity == ValidationSeverity.WARNING:
            warnings.append(("config_warning", cfg_err))

    if not errors and not warnings:
        return Div(
            Div(
                Span("\u2713", cls="status-icon ok"),
                Span("No validation issues detected", cls="status-text"),
                cls="validation-ok",
            ),
            cls="issues-tab-content",
        )

    sections = []
    if errors:
        sections.append(H3(f"Errors ({len(errors)})"))
        sections.append(
            Div(
                *[_render_issue(err_type, err) for err_type, err in errors],
                cls="validation-error-list",
            )
        )

    if warnings:
        sections.append(H3(f"Warnings ({len(warnings)})", style="margin-top: 1rem;"))
        sections.append(
            Div(
                *[_render_issue(err_type, err) for err_type, err in warnings],
                cls="validation-warning-list",
            )
        )

    return Div(
        *sections,
        cls="issues-tab-content" + (" has-errors" if errors else ""),
    )


def _render_issue(err_type: str, err):
    """Render a single validation issue item."""
    if err_type == "duplicate":
        return Div(
            Span("Duplicate ID: ", cls="error-type"),
            Span(err),
            cls="validation-error-item",
        )
    elif err_type == "collision":
        return Div(
            IndexCollisionDetail(err),
            cls="validation-error-item",
        )
    elif err_type == "dark_cycle":
        return Div(
            DarkCycleErrorDetail(err),
            cls="validation-error-item",
        )
    elif err_type == "application":
        return Div(
            ApplicationErrorDetail(err),
            cls="validation-error-item",
        )
    elif err_type == "config":
        return Div(
            ConfigurationErrorDetail(err),
            cls="validation-error-item",
        )
    elif err_type == "config_warning":
        return Div(
            ConfigurationErrorDetail(err),
            cls="validation-warning-item",
        )
    return None


def DarkCycleErrorDetail(error: DarkCycleError):
    """Detailed view of a dark cycle error."""
    return Div(
        Span("Dark cycle: ", cls="error-type"),
        Span(f"{error.sample_name}", cls="collision-sample"),
        Span(f" \u2014 {error.index_type} index ", cls="collision-vs"),
        Code(error.sequence, cls="sequence"),
        Span(
            f" starts with two dark bases ({error.dark_base}{error.dark_base})",
            cls="collision-distance",
        ),
        cls="dark-cycle-detail",
    )


def ApplicationErrorDetail(error: ApplicationValidationError):
    """Detailed view of an application validation error."""
    type_labels = {
        "app_not_available": "Application not available",
        "version_not_available": "Version mismatch",
        "version_conflict": "Version conflict",
        "profile_not_found": "Profile not found",
        "test_profile_not_found": "Test profile not found",
    }
    label = type_labels.get(error.error_type, "Application error")
    # Run-level errors (no specific sample) don't show sample name
    show_sample = error.error_type not in ("test_profile_not_found", "version_conflict") and error.sample_name
    return Div(
        Span(f"{label}: ", cls="error-type"),
        Span(error.detail),
        Span(f" (sample: {error.sample_name})", cls="collision-distance") if show_sample else None,
        cls="application-error-detail",
    )


def ConfigurationErrorDetail(error: ConfigurationError):
    """Detailed view of a configuration error or warning."""
    category_labels = {
        "lane_out_of_range": "Lane out of range",
        "index_length_mismatch": "Index length mismatch",
        "mixed_indexing": "Mixed indexing mode",
        "invalid_sample_id": "Invalid sample ID",
        "index_exceeds_cycles": "Index exceeds cycles",
        "duplicate_index_pair": "Duplicate indexes",
        "no_lane_assignment": "No lane assignment",
        "mismatch_threshold_risk": "Mismatch threshold",
    }
    label = category_labels.get(error.category, error.category.replace("_", " ").title())
    return Div(
        Span(f"{label}: ", cls="error-type"),
        Span(error.message),
        cls="configuration-error-detail",
    )


def ValidationErrorList(result: ValidationResult):
    """Display validation errors and warnings (legacy, for export panel)."""
    errors = []

    # Duplicate sample IDs are errors
    for error in result.duplicate_sample_ids:
        errors.append(error)

    # Index collisions are errors
    for collision in result.index_collisions:
        errors.append(collision.collision_description)

    # Dark cycle errors
    for dark_err in result.dark_cycle_errors:
        errors.append(dark_err.description)

    # Application profile errors
    for app_err in result.application_errors:
        errors.append(app_err.detail)

    # Configuration errors
    for cfg_err in result.configuration_errors:
        if cfg_err.severity == ValidationSeverity.ERROR:
            errors.append(cfg_err.message)

    # Configuration warnings
    warnings = [
        cfg_err.message for cfg_err in result.configuration_errors
        if cfg_err.severity == ValidationSeverity.WARNING
    ]

    if not errors and not warnings:
        return Div(
            Span("OK", cls="status-icon ok"),
            Span("No validation issues detected", cls="status-text"),
            cls="validation-summary ok",
        )

    items = [Li(e, cls="validation-error") for e in errors]
    items.extend(Li(w, cls="validation-warning") for w in warnings)

    total = len(errors) + len(warnings)
    return Div(
        H4(f"Validation Issues ({total})"),
        Ul(
            *items,
            cls="validation-error-list",
        ),
        cls="validation-summary has-errors" if errors else "validation-summary has-warnings",
    )


def IndexCollisionDetail(collision: IndexCollision):
    """Detailed view of a single index collision."""
    return Div(
        Span(f"Lane {collision.lane}: ", cls="collision-lane"),
        Span(f"{collision.sample1_name}", cls="collision-sample"),
        Span(" vs ", cls="collision-vs"),
        Span(f"{collision.sample2_name}", cls="collision-sample"),
        Div(
            Span(f"{collision.index_type}: ", cls="collision-index-type"),
            Code(collision.sequence1, cls="sequence"),
            Span(" / ", cls="collision-sep"),
            Code(collision.sequence2, cls="sequence"),
            Span(f" (distance: {collision.hamming_distance})", cls="collision-distance"),
            cls="collision-sequences",
        ),
        cls="collision-detail",
    )
