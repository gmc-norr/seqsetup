"""Color balance and dark cycles analysis components."""

from typing import Optional

from fasthtml.common import *

from ...models.validation import (
    ColorBalanceStatus,
    IndexColorBalance,
    LaneColorBalance,
    SampleDarkCycleInfo,
    ValidationResult,
)


def ColorBalanceTabContent(run_id: str, result: ValidationResult):
    """
    Content for the Color Balance tab.

    Shows per-lane, per-position base distribution for 2-color chemistry analysis.
    """
    # Check if color balance is disabled for this instrument
    if not result.color_balance_enabled:
        return Div(
            Div(
                P(
                    "Color balance analysis is not applicable for this instrument.",
                    cls="info-message",
                ),
                P(
                    "Color balance analysis is only enabled for modern 2-color chemistry "
                    "instruments (e.g., NovaSeq X) where it is critical for successful sequencing. "
                    "It is disabled for older instruments and 4-color chemistry platforms.",
                    cls="info-details",
                ),
                cls="instrument-not-supported-info",
            ),
            cls="colorbalance-tab-content",
        )

    if not result.color_balance:
        return Div(
            P("No indexed samples to analyze", cls="no-data-message"),
            cls="colorbalance-tab-content",
        )

    lane_sections = []
    for lane in sorted(result.color_balance.keys()):
        lane_balance = result.color_balance[lane]
        lane_sections.append(LaneColorBalanceSection(lane_balance))

    # Build description from channel config
    cc = result.channel_config
    if cc:
        ch1_name = cc["channel1_name"]
        ch1_bases = ", ".join(cc["channel1_bases"])
        ch2_name = cc["channel2_name"]
        ch2_bases = ", ".join(cc["channel2_bases"])
        dark = cc.get("dark_base", "G")
        desc_text = (
            f"This instrument uses {ch1_name} ({ch1_bases}) and {ch2_name} ({ch2_bases}) channels. "
            f"{dark} bases are dark (neither channel). Good color balance requires signals "
            f"in both channels at each position."
        )
    else:
        desc_text = (
            "2-color chemistry requires signals in both channels at each position. "
            "Good color balance ensures accurate base calling."
        )

    return Div(
        Div(
            P(desc_text, cls="colorbalance-description"),
            ColorBalanceLegend(result.channel_config),
            cls="colorbalance-header",
        ),
        Div(
            *lane_sections,
            cls="lane-colorbalance-sections",
        ),
        cls="colorbalance-tab-content",
    )


def LaneColorBalanceSection(lane_balance: LaneColorBalance):
    """Section showing color balance for a single lane."""
    status_class = "has-issues" if lane_balance.has_issues else "ok"

    content = []

    if lane_balance.i7_balance:
        content.append(IndexColorBalanceTable(lane_balance.i7_balance))

    if lane_balance.i5_balance:
        content.append(IndexColorBalanceTable(lane_balance.i5_balance))

    if not content:
        content.append(P("No indexed samples in this lane", cls="no-data-message"))

    return Div(
        H4(f"Lane {lane_balance.lane}", cls="lane-header"),
        Span(f"({lane_balance.sample_count} samples)", cls="lane-sample-count"),
        Div(*content, cls="lane-colorbalance-content"),
        cls=f"lane-colorbalance-section {status_class}",
    )


def IndexColorBalanceTable(index_balance: IndexColorBalance):
    """Table showing color balance for all positions of an index type."""
    if not index_balance.positions:
        return None

    # Get channel names from the first position (all positions share same config)
    first_pos = index_balance.positions[0]
    ch1_name = first_pos.channel1_name
    ch2_name = first_pos.channel2_name

    # Header row
    header_cells = [
        Th("Pos", cls="cb-header"),
        Th("A", cls="cb-header base-a"),
        Th("C", cls="cb-header base-c"),
        Th("G", cls="cb-header base-g"),
        Th("T", cls="cb-header base-t"),
        Th(f"{ch1_name} %", cls="cb-header channel-1"),
        Th(f"{ch2_name} %", cls="cb-header channel-2"),
        Th("Status", cls="cb-header"),
    ]

    rows = [Tr(*header_cells, cls="cb-header-row")]

    # Data rows for each position
    for pos in index_balance.positions:
        status_cls = f"status-{pos.status.value}"
        status_icon = "\u2713" if pos.status == ColorBalanceStatus.OK else (
            "\u26a0" if pos.status == ColorBalanceStatus.WARNING else "\u2717"
        )

        row_cells = [
            Td(str(pos.position), cls="cb-cell position"),
            Td(str(pos.a_count), cls="cb-cell base-a"),
            Td(str(pos.c_count), cls="cb-cell base-c"),
            Td(str(pos.g_count), cls="cb-cell base-g"),
            Td(str(pos.t_count), cls="cb-cell base-t"),
            Td(f"{pos.channel1_percent:.0f}%", cls=f"cb-cell channel-1 {_channel_class(pos.channel1_percent)}"),
            Td(f"{pos.channel2_percent:.0f}%", cls=f"cb-cell channel-2 {_channel_class(pos.channel2_percent)}"),
            Td(status_icon, cls=f"cb-cell status {status_cls}"),
        ]
        rows.append(Tr(*row_cells, cls=f"cb-row {status_cls}"))

    return Div(
        H5(f"{index_balance.index_type.upper()} Index", cls="index-type-header"),
        Table(*rows, cls="colorbalance-table"),
        cls="index-colorbalance",
    )


def _channel_class(percent: float) -> str:
    """Get CSS class for a channel percentage."""
    if percent >= 50:
        return "channel-high"
    elif percent >= 25:
        return "channel-medium"
    elif percent > 0:
        return "channel-low"
    return "channel-zero"


def ColorBalanceLegend(channel_config: Optional[dict] = None):
    """Legend explaining the color balance display."""
    if channel_config:
        ch1_name = channel_config["channel1_name"]
        ch1_bases = "+".join(channel_config["channel1_bases"])
        ch2_name = channel_config["channel2_name"]
        ch2_bases = "+".join(channel_config["channel2_bases"])
    else:
        ch1_name = "Channel 1"
        ch1_bases = "A+C"
        ch2_name = "Channel 2"
        ch2_bases = "C+T"

    return Div(
        Div(
            Span("Channels: ", cls="legend-label"),
            Span(f"{ch1_name} ({ch1_bases})", cls="legend-item channel-1-demo"),
            Span(f"{ch2_name} ({ch2_bases})", cls="legend-item channel-2-demo"),
            cls="legend-section",
        ),
        Div(
            Span("Status: ", cls="legend-label"),
            Span("\u2713 OK", cls="legend-item status-ok"),
            Span("\u26a0 Warning (<25%)", cls="legend-item status-warning"),
            Span("\u2717 Error (0%)", cls="legend-item status-error"),
            cls="legend-section",
        ),
        cls="colorbalance-legend",
    )


# Dark Cycles Tab Components

def DarkCyclesTabContent(run_id: str, result: ValidationResult):
    """
    Content for the Dark Cycles tab.

    Shows a visual representation of each sample's index sequences with
    dark bases highlighted. Warns when two consecutive dark bases appear
    at the start of an index.
    """
    if not result.color_balance_enabled:
        return Div(
            Div(
                P(
                    "Dark cycle analysis is not applicable for this instrument.",
                    cls="info-message",
                ),
                P(
                    "Dark cycle analysis is only relevant for 2-color chemistry instruments "
                    "where a dark base (producing no signal in either channel) can cause issues "
                    "if the first two bases of an index are both dark.",
                    cls="info-details",
                ),
                cls="instrument-not-supported-info",
            ),
            cls="darkcycles-tab-content",
        )

    samples = result.dark_cycle_samples
    if not samples:
        return Div(
            P("No indexed samples to analyze", cls="no-data-message"),
            cls="darkcycles-tab-content",
        )

    dark_base = samples[0].dark_base
    cc = result.channel_config
    if cc:
        ch1_bases = ", ".join(cc["channel1_bases"])
        ch2_bases = ", ".join(cc["channel2_bases"])
        desc_text = (
            f"Dark base for this chemistry: {dark_base} (no signal in either channel). "
            f"Two consecutive dark bases at the start of an index prevent reliable detection "
            f"of the index read start. One dark base in the first two positions is acceptable."
        )
    else:
        desc_text = (
            f"Dark base: {dark_base}. Two consecutive dark bases at the start of an index "
            f"prevent reliable detection of the index read start."
        )

    # Count issues
    error_count = sum(1 for s in samples if s.i7_leading_dark >= 2 or s.i5_leading_dark >= 2)
    warning_count = sum(1 for s in samples if (s.i7_leading_dark == 1 or s.i5_leading_dark == 1)
                        and s.i7_leading_dark < 2 and s.i5_leading_dark < 2)

    status_summary = []
    if error_count > 0:
        status_summary.append(Span(f"{error_count} error(s)", cls="dc-summary-error"))
    if warning_count > 0:
        status_summary.append(Span(f"{warning_count} warning(s)", cls="dc-summary-warning"))
    if not status_summary:
        status_summary.append(Span("No dark cycle issues", cls="dc-summary-ok"))

    return Div(
        Div(
            P(desc_text, cls="darkcycles-description"),
            Div(*status_summary, cls="dc-summary"),
            DarkCyclesLegend(dark_base),
            cls="darkcycles-header",
        ),
        DarkCyclesTable(samples),
        cls="darkcycles-tab-content",
    )


def DarkCyclesTable(samples: list[SampleDarkCycleInfo]):
    """Table showing dark cycle analysis for all samples."""
    header_cells = [
        Th("Sample", cls="dc-header"),
        Th("i7 Index", cls="dc-header"),
        Th("i7 Status", cls="dc-header"),
        Th("i5 Index", cls="dc-header"),
        Th("i5 Status", cls="dc-header"),
    ]
    rows = [Tr(*header_cells, cls="dc-header-row")]

    for sample in samples:
        # Determine row-level status
        has_error = sample.i7_leading_dark >= 2 or sample.i5_leading_dark >= 2
        has_warning = (not has_error and
                       (sample.i7_leading_dark == 1 or sample.i5_leading_dark == 1))
        row_cls = "dc-row"
        if has_error:
            row_cls += " dc-row-error"
        elif has_warning:
            row_cls += " dc-row-warning"

        # i7 sequence visualization
        if sample.i7_sequence:
            i7_viz = _dark_cycle_sequence_viz(sample.i7_sequence, sample.dark_base)
            i7_status = _dark_cycle_status(sample.i7_leading_dark)
        else:
            i7_viz = Span("\u2014", cls="no-index")
            i7_status = Span("\u2014", cls="no-index")

        # i5 sequence visualization (show read orientation)
        if sample.i5_sequence:
            i5_viz = _dark_cycle_sequence_viz(sample.i5_read_sequence, sample.dark_base)
            i5_status = _dark_cycle_status(sample.i5_leading_dark)
        else:
            i5_viz = Span("\u2014", cls="no-index")
            i5_status = Span("\u2014", cls="no-index")

        rows.append(Tr(
            Td(sample.sample_name, cls="dc-cell dc-sample"),
            Td(i7_viz, cls="dc-cell dc-sequence"),
            Td(i7_status, cls="dc-cell dc-status"),
            Td(i5_viz, cls="dc-cell dc-sequence"),
            Td(i5_status, cls="dc-cell dc-status"),
            cls=row_cls,
        ))

    return Table(*rows, cls="darkcycles-table")


def _dark_cycle_sequence_viz(sequence: str, dark_base: str):
    """
    Render a sequence with each base color-coded.
    Dark bases are highlighted. The first two positions are marked specially.
    """
    if not sequence:
        return Span("\u2014")

    bases = []
    for i, base in enumerate(sequence):
        is_dark = base.upper() == dark_base.upper()
        is_leading = i < 2
        cls_parts = ["dc-base"]
        if is_dark:
            cls_parts.append("dc-dark")
        if is_leading:
            cls_parts.append("dc-leading")
        if is_dark and is_leading:
            cls_parts.append("dc-dark-leading")

        bases.append(Span(base.upper(), cls=" ".join(cls_parts)))

    return Span(*bases, cls="dc-sequence-viz")


def _dark_cycle_status(leading_dark: int):
    """Return a status indicator for the number of leading dark bases."""
    if leading_dark >= 2:
        return Span("Error \u2014 two dark", cls="dc-status-error")
    elif leading_dark == 1:
        return Span("OK \u2014 one dark", cls="dc-status-warning")
    return Span("OK", cls="dc-status-ok")


def DarkCyclesLegend(dark_base: str):
    """Legend for the dark cycles visualization."""
    return Div(
        Div(
            Span("Base colors: ", cls="legend-label"),
            Span(f"{dark_base} (dark)", cls="legend-item dc-legend-dark"),
            Span("Other bases", cls="legend-item dc-legend-normal"),
            cls="legend-section",
        ),
        Div(
            Span("Status: ", cls="legend-label"),
            Span("OK", cls="legend-item dc-status-ok"),
            Span("OK \u2014 one dark leading", cls="legend-item dc-status-warning"),
            Span("Error \u2014 two dark leading", cls="legend-item dc-status-error"),
            cls="legend-section",
        ),
        cls="darkcycles-legend",
    )
