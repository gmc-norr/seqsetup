"""Index distance heatmap visualizations."""

from fasthtml.common import *

from ...models.validation import IndexDistanceMatrix, ValidationResult


def HeatmapsTabContent(run_id: str, result: ValidationResult, index_type: str = "i7"):
    """
    Content for the Heatmaps tab with global type controls.

    Args:
        run_id: Run ID for HTMX requests
        result: Validation result with distance matrices
        index_type: "i7", "i5", or "combined"
    """
    if not result.distance_matrices:
        return Div(
            P("No lanes with multiple indexed samples", cls="no-data-message"),
            cls="heatmaps-tab-content",
        )

    # Build heatmap sections for each lane (without individual controls)
    heatmap_sections = []
    for lane in sorted(result.distance_matrices.keys()):
        matrix = result.distance_matrices[lane]
        if len(matrix.sample_names) >= 2:
            heatmap_sections.append(
                LaneHeatmapSimple(lane, matrix, index_type)
            )

    return Div(
        # Global heatmap type controls
        Div(
            Span("Show distances for: ", cls="heatmap-type-label"),
            Button(
                "i7",
                cls="heatmap-toggle active" if index_type == "i7" else "heatmap-toggle",
                hx_get=f"/runs/{run_id}/validation/tab/heatmaps?type=i7",
                hx_target="#validation-tabs",
                hx_swap="outerHTML",
            ),
            Button(
                "i5",
                cls="heatmap-toggle active" if index_type == "i5" else "heatmap-toggle",
                hx_get=f"/runs/{run_id}/validation/tab/heatmaps?type=i5",
                hx_target="#validation-tabs",
                hx_swap="outerHTML",
            ),
            Button(
                "i7+i5",
                cls="heatmap-toggle active" if index_type == "combined" else "heatmap-toggle",
                hx_get=f"/runs/{run_id}/validation/tab/heatmaps?type=combined",
                hx_target="#validation-tabs",
                hx_swap="outerHTML",
            ),
            cls="global-heatmap-controls",
        ),
        P(
            "Lower values (red) indicate potential collision risk.",
            cls="heatmap-description",
        ),
        # All lane heatmaps
        Div(
            *heatmap_sections,
            cls="lane-heatmaps",
        ),
        HeatmapLegend(),
        cls="heatmaps-tab-content",
    )


def LaneHeatmapSimple(lane: int, matrix: IndexDistanceMatrix, index_type: str = "i7"):
    """
    Simple lane heatmap without individual controls (controlled globally).

    Args:
        lane: Lane number
        matrix: Distance matrix data for this lane
        index_type: "i7", "i5", or "combined" to display
    """
    if not matrix or len(matrix.sample_names) < 2:
        return None

    return Div(
        H4(f"Lane {lane}", cls="lane-header"),
        Span(f"({len(matrix.sample_names)} samples)", cls="lane-sample-count"),
        IndexDistanceHeatmap(matrix, index_type),
        cls="lane-heatmap-simple",
    )


def IndexDistanceHeatmap(matrix: IndexDistanceMatrix, index_type: str = "i7"):
    """
    Render index distances as an HTML table heatmap.

    Args:
        matrix: Distance matrix data
        index_type: "i7", "i5", or "combined" to display
    """
    if not matrix or len(matrix.sample_names) < 2:
        return P("Need at least 2 samples to show heatmap", cls="no-data-message")

    if index_type == "i7":
        distances = matrix.i7_distances
    elif index_type == "i5":
        distances = matrix.i5_distances
    else:  # combined
        distances = matrix.combined_distances
    n = len(matrix.sample_names)

    # Build header row
    header_cells = [Th("", cls="heatmap-corner")]
    for name in matrix.sample_names:
        # Truncate long names
        display_name = name[:8] + ".." if len(name) > 8 else name
        header_cells.append(Th(display_name, cls="heatmap-header", title=name))

    # Build data rows
    rows = [Tr(*header_cells, cls="heatmap-header-row")]

    for i, row_name in enumerate(matrix.sample_names):
        display_name = row_name[:8] + ".." if len(row_name) > 8 else row_name
        row_cells = [Th(display_name, cls="heatmap-row-header", title=row_name)]

        for j in range(n):
            dist = distances[i][j]
            if i == j:
                # Diagonal
                cell_cls = "heatmap-cell diagonal"
                cell_content = "-"
            elif dist is None:
                cell_cls = "heatmap-cell no-data"
                cell_content = "N/A"
            else:
                # Color based on distance (lower = more dangerous = redder)
                dist_class = min(dist, 10)
                cell_cls = f"heatmap-cell dist-{dist_class}"
                cell_content = str(dist)

            row_cells.append(Td(cell_content, cls=cell_cls, title=f"Distance: {dist}"))

        rows.append(Tr(*row_cells))

    return Table(*rows, cls="heatmap-table")


def HeatmapLegend():
    """Color legend for the heatmap."""
    return Div(
        Span("Distance: ", cls="legend-label"),
        Span("0", cls="legend-item dist-0"),
        Span("1", cls="legend-item dist-1"),
        Span("2", cls="legend-item dist-2"),
        Span("3", cls="legend-item dist-3"),
        Span("4+", cls="legend-item dist-4"),
        cls="heatmap-legend",
    )


# Legacy shims for backward compatibility
def LaneHeatmapSection(run_id: str, lane: int, matrix: IndexDistanceMatrix, index_type: str = "i7"):
    """Legacy: Section containing heatmaps for a single lane."""
    return LaneHeatmapSimple(lane, matrix, index_type)


def LaneHeatmapContent(run_id: str, lane: int, matrix: IndexDistanceMatrix, index_type: str = "i7"):
    """Legacy: Controls and heatmap for a lane."""
    return LaneHeatmapSimple(lane, matrix, index_type)
