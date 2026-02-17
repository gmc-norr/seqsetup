"""Add Samples wizard (2-step flow for existing runs)."""

from fasthtml.common import *

from ...models.index import IndexKit
from ...models.sequencing_run import SequencingRun
from .steps import WizardStepIndicator
from .sample_table import SamplePasteFormatHelp, FetchFromApiSection, NewSamplesTableWizard
from .index_panel import IndexKitDropdown, IndexKitPanel


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
                        IndexKitPanel(default_kit) if default_kit else P("No index kits available.", cls="no-kits-message"),
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
