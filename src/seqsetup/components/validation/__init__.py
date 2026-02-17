"""Validation panel UI components.

This package splits the validation UI into focused submodules:
- page: ValidationPage, ValidationApprovalBar, ValidationTabs
- issues: Error/warning rendering, collision details
- heatmaps: Index distance heatmap visualizations
- color_balance: Color balance and dark cycles analysis
"""

from .page import (
    ValidationPage,
    ValidationApprovalBar,
    ValidationTabs,
)
from .issues import (
    IssuesTabContent,
    ValidationErrorList,
    IndexCollisionDetail,
)
from .heatmaps import (
    HeatmapsTabContent,
    LaneHeatmapSimple,
    IndexDistanceHeatmap,
    HeatmapLegend,
    LaneHeatmapSection,
    LaneHeatmapContent,
)
from .color_balance import (
    ColorBalanceTabContent,
    LaneColorBalanceSection,
    IndexColorBalanceTable,
    ColorBalanceLegend,
    DarkCyclesTabContent,
    DarkCyclesTable,
    DarkCyclesLegend,
)

# Legacy shim — imports ValidationService to avoid circular deps in submodules
from ...services.validation import ValidationService


def ValidationPanel(run, show_heatmap=True):
    """Legacy: Complete validation panel."""
    result = ValidationService.validate_run(run)
    return ValidationTabs(run.id, result, "issues")


__all__ = [
    # page
    "ValidationPage",
    "ValidationApprovalBar",
    "ValidationTabs",
    # issues
    "IssuesTabContent",
    "ValidationErrorList",
    "IndexCollisionDetail",
    # heatmaps
    "HeatmapsTabContent",
    "LaneHeatmapSimple",
    "IndexDistanceHeatmap",
    "HeatmapLegend",
    "LaneHeatmapSection",
    "LaneHeatmapContent",
    # color_balance
    "ColorBalanceTabContent",
    "LaneColorBalanceSection",
    "IndexColorBalanceTable",
    "ColorBalanceLegend",
    "DarkCyclesTabContent",
    "DarkCyclesTable",
    "DarkCyclesLegend",
    # legacy
    "ValidationPanel",
]
