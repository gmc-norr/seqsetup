"""Index kit display and drag-drop components for the wizard."""

from fasthtml.common import *

from ...models.index import IndexKit, IndexMode
from ..index_panel import (
    CombinatorialIndexContent,
    DraggableIndexPair,
    SingleIndexContent,
)
from ...utils.html import escape_html_attr, escape_js_string


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


def IndexKitPanel(kit: IndexKit):
    """
    Index kit panel with details, filter, and index list.

    Args:
        kit: Index kit to display
    """
    if kit is None:
        return P("Select an index kit", cls="no-kits-message")

    # Mode label
    mode_labels = {
        IndexMode.UNIQUE_DUAL: "Unique Dual",
        IndexMode.COMBINATORIAL: "Combinatorial",
        IndexMode.SINGLE: "Single (i7 only)",
    }
    mode_label = mode_labels.get(kit.index_mode, "Unknown")

    # Index count
    index_count = _get_kit_count(kit)

    return Div(
        # Kit details section
        Div(
            Div(
                Span("Mode: ", cls="kit-detail-label"),
                Span(mode_label, cls="kit-detail-value"),
                cls="kit-detail-item",
            ),
            Div(
                Span("Indexes: ", cls="kit-detail-label"),
                Span(str(index_count), cls="kit-detail-value"),
                cls="kit-detail-item",
            ),
            Div(
                Span(kit.description, cls="kit-description"),
                cls="kit-detail-item",
            ) if kit.description else None,
            cls="kit-details",
        ),
        # Filter input
        Div(
            Input(
                type="text",
                id="index-filter-input",
                placeholder="Filter indexes...",
                cls="index-filter-input",
                oninput="filterIndexesWizard(this.value)",
            ),
            cls="index-filter-section",
        ),
        # Index list
        IndexListCompact(kit),
        cls="index-kit-panel",
    )


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
            id="index-list-items",
        )
    elif kit.is_single():
        # Single mode - only i7
        return Div(
            *[DraggableIndexCompact(idx, kit.name, "i7") for idx in kit.i7_indexes],
            cls="index-list",
            id="index-list-items",
        )
    else:
        # Unique dual - show pairs with i7/i5 side by side
        return Div(
            *[DraggableIndexPairCompact(pair) for pair in kit.index_pairs],
            cls="index-list",
            id="index-list-items",
        )


def DraggableIndexPairCompact(pair):
    """Compact draggable index pair showing pair name, index names, and well position."""
    from ...models.index import IndexPair

    # Escape user data for safe use in JavaScript event handlers
    safe_id = escape_js_string(pair.id)
    safe_name = escape_html_attr(pair.name)

    # Get index names
    i7_name = pair.index1.name if pair.index1 else ""
    i5_name = pair.index2.name if pair.index2 else ""

    # Build display elements
    elements = [Span(pair.name, cls="index-name-compact")]

    # Show i7/i5 names if different from pair name
    if i7_name and i7_name != pair.name:
        elements.append(Span(i7_name, cls="index-i7-name-compact"))
    if i5_name and i5_name != pair.name:
        elements.append(Span(i5_name, cls="index-i5-name-compact"))

    # Show well position if available
    if pair.well_position:
        elements.append(Span(pair.well_position, cls="index-well-compact"))

    return Div(
        *elements,
        cls="draggable-index-compact draggable-pair",
        draggable="true",
        data_index_pair_id=pair.id,
        data_index_name=pair.name,
        data_index_type="pair",
        data_well=pair.well_position or "",
        onclick=f"handleIndexClick(event, '{safe_id}', 'pair')",
        ondragstart=f"handleDragStart(event, '{safe_id}', 'pair')",
        title=f"Pair: {safe_name}\ni7: {i7_name} ({pair.index1_sequence})\ni5: {i5_name} ({pair.index2_sequence or 'N/A'})\nWell: {pair.well_position or 'N/A'}",
    )


def DraggableIndexCompact(index, kit_name: str, index_type: str):
    """Compact draggable individual index (for combinatorial/single mode)."""
    from ...models.index import Index, IndexType

    index_id = f"{kit_name}_{index_type}_{index.name}"

    # Escape user data for safe use in JavaScript event handlers
    safe_index_id = escape_js_string(index_id)
    safe_name = escape_html_attr(index.name)

    # Show well position if available, otherwise nothing
    well_display = Span(index.well_position, cls="index-well-compact") if index.well_position else None

    return Div(
        Span(index.name, cls="index-name-compact"),
        well_display,
        cls=f"draggable-index-compact draggable-single {index_type}-index",
        draggable="true",
        data_index_id=index_id,
        data_index_name=index.name,
        data_index_type=index_type,
        data_kit_name=kit_name,
        data_well=index.well_position or "",
        onclick=f"handleIndexClick(event, '{safe_index_id}', '{index_type}')",
        ondragstart=f"handleDragStart(event, '{safe_index_id}', '{index_type}')",
        title=f"{safe_name}\nWell: {index.well_position or 'N/A'}\nSequence: {index.sequence}",
    )
