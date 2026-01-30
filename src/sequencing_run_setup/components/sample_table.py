"""Sample table UI component."""

from fasthtml.common import *

from ..models.sample import Sample
from ..models.sequencing_run import RunCycles


def SampleTableSection(samples: list[Sample], run_cycles: RunCycles | None = None):
    """
    Complete sample section with paste form and table.

    Args:
        samples: List of samples to display
        run_cycles: Current run cycle configuration
    """
    return Div(
        BulkSamplePasteForm(),
        SampleTable(samples, run_cycles),
        id="sample-section",
    )


def SampleTable(samples: list[Sample], run_cycles: RunCycles | None = None):
    """
    Render the sample table with drag-drop targets for index assignment.

    Args:
        samples: List of samples to display
        run_cycles: Current run cycle configuration for override cycle calculation
    """
    return Table(
        Thead(
            Tr(
                Th("Sample ID"),
                Th("Test ID"),
                Th("Index 1 (i7)", cls="index-col"),
                Th("Index 2 (i5)", cls="index-col"),
                Th("Override Cycles"),
                Th("Actions"),
            )
        ),
        Tbody(
            *[SampleRow(s, run_cycles) for s in samples] if samples else [EmptyTableMessage()],
            id="sample-tbody",
        ),
        cls="sample-table",
        id="sample-table",
    )


def BulkSamplePasteForm():
    """
    Form for pasting multiple samples at once.

    Expected format: tab-separated Sample_ID and Test_ID, one per line.
    """
    return Div(
        Details(
            Summary("Paste Samples", cls="paste-toggle"),
            Div(
                P(
                    "Paste tab-separated data: Sample_ID and Test_ID (one sample per line)",
                    cls="paste-help",
                ),
                Form(
                    Textarea(
                        name="paste_data",
                        id="paste_data",
                        placeholder="Sample_001\tTest_001\nSample_002\tTest_002\nSample_003\tTest_003",
                        rows=6,
                        cls="paste-textarea",
                    ),
                    Div(
                        Button("Add Samples", type="submit", cls="btn-primary"),
                        Button(
                            "Clear",
                            type="button",
                            cls="btn-secondary",
                            onclick="document.getElementById('paste_data').value = ''",
                        ),
                        cls="paste-buttons",
                    ),
                    hx_post="/samples/bulk",
                    hx_target="#sample-tbody",
                    hx_swap="beforeend",
                ),
                cls="paste-form-content",
            ),
            cls="paste-details",
        ),
        cls="bulk-paste-section",
        id="bulk-paste-section",
    )


def SampleRow(sample: Sample, run_cycles: RunCycles | None = None):
    """
    Single sample row with drop zone for indexes.

    Args:
        sample: Sample to render
        run_cycles: Run cycle configuration
    """
    return Tr(
        Td(sample.sample_id or "-"),
        Td(sample.test_id or "-"),
        Td(
            IndexDropZone(sample, "index1"),
            cls="index-cell",
        ),
        Td(
            sample.index2_sequence or "-",
            cls="index-cell index2",
        ),
        Td(sample.override_cycles or "-", cls="override-cycles"),
        Td(
            Button(
                "Clear",
                hx_post=f"/samples/{sample.id}/clear-index",
                hx_target=f"#sample-row-{sample.id}",
                hx_swap="outerHTML",
                cls="btn-small btn-secondary",
                disabled=not sample.has_index,
            ),
            Button(
                "Delete",
                hx_delete=f"/samples/{sample.id}",
                hx_target=f"#sample-row-{sample.id}",
                hx_swap="outerHTML",
                hx_confirm="Delete this sample?",
                cls="btn-small btn-danger",
            ),
            cls="actions",
        ),
        id=f"sample-row-{sample.id}",
        cls="sample-row" + (" has-index" if sample.has_index else ""),
    )


def IndexDropZone(sample: Sample, index_type: str = "index1"):
    """
    Drop zone for index assignment via drag-and-drop.

    Args:
        sample: Sample that will receive the dropped index
        index_type: Which index column this is (index1 or index2)
    """
    if sample.has_index:
        # Show assigned index
        return Span(
            sample.index1_sequence,
            cls="assigned-index",
            title=f"{sample.index_pair.name}: {sample.index1_sequence}",
        )
    else:
        # Show drop target
        return Div(
            "Drop index here",
            cls="drop-zone",
            data_sample_id=sample.id,
            ondragover="event.preventDefault(); this.classList.add('drag-over')",
            ondragleave="this.classList.remove('drag-over')",
            ondrop=f"handleIndexDrop(event, '{sample.id}')",
        )


def SampleForm(sample: Sample | None = None):
    """
    Form for adding/editing a sample.

    Args:
        sample: Existing sample for editing, or None for new sample
    """
    is_edit = sample is not None
    action = f"/samples/{sample.id}" if is_edit else "/samples"
    method = "put" if is_edit else "post"

    return Form(
        Div(
            Label("Sample ID", fr="sample_id"),
            Input(
                type="text",
                name="sample_id",
                id="sample_id",
                value=sample.sample_id if sample else "",
                required=True,
                placeholder="e.g., Sample_001",
            ),
            cls="form-group",
        ),
        Div(
            Label("Sample Name", fr="sample_name"),
            Input(
                type="text",
                name="sample_name",
                id="sample_name",
                value=sample.sample_name if sample else "",
                placeholder="e.g., Patient Sample 1",
            ),
            cls="form-group",
        ),
        Div(
            Label("Project", fr="project"),
            Input(
                type="text",
                name="project",
                id="project",
                value=sample.project if sample else "",
                placeholder="e.g., ProjectA",
            ),
            cls="form-group",
        ),
        Button(
            "Update Sample" if is_edit else "Add Sample",
            type="submit",
            cls="btn-primary",
        ),
        hx_post=action if not is_edit else None,
        hx_put=action if is_edit else None,
        hx_target="#sample-tbody",
        hx_swap="beforeend" if not is_edit else "outerHTML",
        cls="sample-form",
        id="sample-form",
    )


def EmptyTableMessage():
    """Message shown when no samples exist."""
    return Tr(
        Td(
            "No samples yet. Use 'Paste Samples' above to add samples.",
            colspan="6",
            cls="empty-message",
        ),
        id="empty-row",
    )
