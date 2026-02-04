"""Validation report exporters (JSON and PDF)."""

import json
from datetime import datetime
from io import BytesIO
from typing import Any, Optional

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import numpy as np
from reportlab.lib import colors as rl_colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from ..models.sequencing_run import SequencingRun
from ..models.validation import (
    ColorBalanceStatus,
    IndexColorBalance,
    IndexDistanceMatrix,
    LaneColorBalance,
    ValidationResult,
    ValidationSeverity,
)


class ValidationReportJSON:
    """Export validation results to structured JSON."""

    @classmethod
    def export(cls, run: SequencingRun, result: ValidationResult) -> str:
        """Serialize ValidationResult to JSON string."""
        data = cls._build_report(run, result)
        return json.dumps(data, indent=2, default=str)

    @classmethod
    def _build_report(cls, run: SequencingRun, result: ValidationResult) -> dict[str, Any]:
        return {
            "run_id": run.id,
            "run_name": run.run_name,
            "instrument": run.instrument_platform.value,
            "flowcell": run.flowcell_type,
            "timestamp": datetime.now().isoformat(),
            "validation_approved": run.validation_approved,
            "summary": {
                "error_count": result.error_count,
                "warning_count": result.warning_count,
                "collision_count": len(result.index_collisions),
                "dark_cycle_error_count": len(result.dark_cycle_errors),
                "color_balance_issue_count": result.color_balance_issue_count,
                "application_error_count": len(result.application_errors),
                "configuration_error_count": len(result.configuration_errors),
                "duplicate_sample_id_count": len(result.duplicate_sample_ids),
            },
            "errors": {
                "duplicate_sample_ids": result.duplicate_sample_ids,
                "index_collisions": [
                    {
                        "lane": c.lane,
                        "index_type": c.index_type,
                        "sample1_name": c.sample1_name,
                        "sample2_name": c.sample2_name,
                        "sequence1": c.sequence1,
                        "sequence2": c.sequence2,
                        "hamming_distance": c.hamming_distance,
                        "mismatch_threshold": c.mismatch_threshold,
                    }
                    for c in result.index_collisions
                ],
                "dark_cycle_errors": [
                    {
                        "sample_name": e.sample_name,
                        "index_type": e.index_type,
                        "sequence": e.sequence,
                        "dark_base": e.dark_base,
                    }
                    for e in result.dark_cycle_errors
                ],
                "application_errors": [
                    {
                        "sample_name": e.sample_name,
                        "test_id": e.test_id,
                        "application_name": e.application_name,
                        "profile_name": e.profile_name,
                        "error_type": e.error_type,
                        "detail": e.detail,
                    }
                    for e in result.application_errors
                ],
                "configuration_errors": [
                    {
                        "severity": e.severity.value,
                        "category": e.category,
                        "message": e.message,
                        "lane": e.lane,
                    }
                    for e in result.configuration_errors
                ],
            },
            "per_lane": cls._serialize_per_lane(result),
        }

    @classmethod
    def _serialize_per_lane(cls, result: ValidationResult) -> dict[str, Any]:
        lanes: dict[str, Any] = {}

        # Merge all lane keys from matrices and color balance
        all_lane_keys = set(result.distance_matrices.keys()) | set(result.color_balance.keys())

        for lane in sorted(all_lane_keys):
            lane_data: dict[str, Any] = {}

            # Distance matrix
            matrix = result.distance_matrices.get(lane)
            if matrix:
                lane_data["sample_count"] = len(matrix.sample_names)
                lane_data["distance_matrix"] = {
                    "sample_names": matrix.sample_names,
                    "i7": matrix.i7_distances,
                    "i5": matrix.i5_distances,
                    "combined": matrix.combined_distances,
                }

            # Color balance
            cb = result.color_balance.get(lane)
            if cb:
                lane_data["sample_count"] = lane_data.get("sample_count", cb.sample_count)
                lane_data["color_balance"] = {}
                for idx_type, balance in [("i7", cb.i7_balance), ("i5", cb.i5_balance)]:
                    if balance:
                        lane_data["color_balance"][idx_type] = [
                            {
                                "position": p.position,
                                "A": p.a_count,
                                "C": p.c_count,
                                "G": p.g_count,
                                "T": p.t_count,
                                "channel1_pct": round(p.channel1_percent, 1),
                                "channel2_pct": round(p.channel2_percent, 1),
                                "status": p.status.value,
                            }
                            for p in balance.positions
                        ]

            lanes[str(lane)] = lane_data

        return lanes


class ValidationReportPDF:
    """Generate PDF validation report with heatmaps and color balance charts."""

    @classmethod
    def export(cls, run: SequencingRun, result: ValidationResult) -> bytes:
        """Generate PDF report bytes."""
        buf = BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            topMargin=1.5 * cm,
            bottomMargin=1.5 * cm,
            leftMargin=1.5 * cm,
            rightMargin=1.5 * cm,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontSize=18, spaceAfter=6)
        heading_style = ParagraphStyle("ReportHeading", parent=styles["Heading2"], spaceAfter=4, spaceBefore=12)
        subheading_style = ParagraphStyle("ReportSubheading", parent=styles["Heading3"], spaceAfter=2, spaceBefore=8)
        body_style = styles["Normal"]
        small_style = ParagraphStyle("Small", parent=body_style, fontSize=8)

        elements = []

        # Header
        elements.append(Paragraph("Validation Report", title_style))
        elements.append(Spacer(1, 4 * mm))

        # Run info table
        run_info = [
            ["Run Name", run.run_name or "—"],
            ["Run ID", run.id],
            ["Instrument", run.instrument_platform.value],
            ["Flowcell", run.flowcell_type or "—"],
            ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Validation Approved", "Yes" if run.validation_approved else "No"],
        ]
        info_table = Table(run_info, colWidths=[5 * cm, 12 * cm])
        info_table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(info_table)
        elements.append(Spacer(1, 6 * mm))

        # Summary
        elements.append(Paragraph("Summary", heading_style))
        summary_data = [
            ["Category", "Count"],
            ["Errors", str(result.error_count)],
            ["Warnings", str(result.warning_count)],
            ["Index Collisions", str(len(result.index_collisions))],
            ["Dark Cycle Errors", str(len(result.dark_cycle_errors))],
            ["Application Errors", str(len(result.application_errors))],
            ["Configuration Issues", str(len(result.configuration_errors))],
            ["Duplicate Sample IDs", str(len(result.duplicate_sample_ids))],
            ["Color Balance Issues (lanes)", str(result.color_balance_issue_count)],
        ]
        summary_table = Table(summary_data, colWidths=[8 * cm, 4 * cm])
        summary_table.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), rl_colors.Color(0.9, 0.9, 0.9)),
            ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.Color(0.8, 0.8, 0.8)),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
        ]))
        elements.append(summary_table)

        # Errors & Warnings
        all_errors = cls._collect_error_messages(result)
        all_warnings = cls._collect_warning_messages(result)

        if all_errors:
            elements.append(Paragraph("Errors", heading_style))
            for msg in all_errors:
                elements.append(Paragraph(f"&bull; {msg}", small_style))

        if all_warnings:
            elements.append(Paragraph("Warnings", heading_style))
            for msg in all_warnings:
                elements.append(Paragraph(f"&bull; {msg}", small_style))

        # Per-lane heatmaps
        if result.distance_matrices:
            elements.append(PageBreak())
            elements.append(Paragraph("Index Distance Heatmaps", heading_style))
            for lane in sorted(result.distance_matrices.keys()):
                matrix = result.distance_matrices[lane]
                if len(matrix.sample_names) < 2:
                    continue
                elements.append(Paragraph(f"Lane {lane} ({len(matrix.sample_names)} samples)", subheading_style))
                img = cls._render_heatmap(matrix)
                if img:
                    elements.append(img)
                    elements.append(Spacer(1, 4 * mm))

        # Color balance
        if result.color_balance:
            elements.append(PageBreak())
            elements.append(Paragraph("Color Balance", heading_style))
            for lane in sorted(result.color_balance.keys()):
                cb = result.color_balance[lane]
                if not cb.has_issues and not (cb.i7_balance or cb.i5_balance):
                    continue
                elements.append(Paragraph(f"Lane {lane} ({cb.sample_count} samples)", subheading_style))
                for idx_type, balance in [("i7", cb.i7_balance), ("i5", cb.i5_balance)]:
                    if balance and balance.positions:
                        img = cls._render_color_balance(balance, idx_type, result.channel_config)
                        if img:
                            elements.append(img)
                            elements.append(Spacer(1, 3 * mm))

        # Dark cycles summary
        if result.dark_cycle_samples:
            elements.append(PageBreak())
            elements.append(Paragraph("Dark Cycles Summary", heading_style))
            dc_header = ["Sample", "i7 Sequence", "i7 Dark", "i5 Sequence (read)", "i5 Dark"]
            dc_rows = [dc_header]
            for info in result.dark_cycle_samples:
                dc_rows.append([
                    info.sample_name,
                    info.i7_sequence or "—",
                    str(info.i7_leading_dark),
                    info.i5_read_sequence or "—",
                    str(info.i5_leading_dark),
                ])
            dc_table = Table(dc_rows, repeatRows=1)
            dc_table.setStyle(TableStyle([
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BACKGROUND", (0, 0), (-1, 0), rl_colors.Color(0.9, 0.9, 0.9)),
                ("GRID", (0, 0), (-1, -1), 0.5, rl_colors.Color(0.8, 0.8, 0.8)),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
            ]))
            elements.append(dc_table)

        doc.build(elements)
        return buf.getvalue()

    @classmethod
    def _collect_error_messages(cls, result: ValidationResult) -> list[str]:
        msgs = []
        msgs.extend(result.duplicate_sample_ids)
        for c in result.index_collisions:
            msgs.append(c.collision_description)
        for e in result.dark_cycle_errors:
            msgs.append(e.description)
        for e in result.application_errors:
            msgs.append(e.detail)
        for e in result.configuration_errors:
            if e.severity == ValidationSeverity.ERROR:
                msgs.append(e.message)
        return msgs

    @classmethod
    def _collect_warning_messages(cls, result: ValidationResult) -> list[str]:
        return [
            e.message for e in result.configuration_errors
            if e.severity == ValidationSeverity.WARNING
        ]

    @classmethod
    def _render_heatmap(cls, matrix: IndexDistanceMatrix) -> Optional[Image]:
        """Render a combined distance heatmap as an embedded image."""
        n = len(matrix.sample_names)
        if n < 2:
            return None

        # Use combined distances
        data = np.zeros((n, n), dtype=float)
        for i in range(n):
            for j in range(n):
                val = matrix.combined_distances[i][j]
                data[i][j] = val if val is not None else 0

        # Create figure
        fig_width = max(3, min(7, n * 0.5 + 1.5))
        fig_height = max(2.5, min(6, n * 0.4 + 1.5))
        fig, ax = plt.subplots(figsize=(fig_width, fig_height))

        # Custom colormap: red (low/dangerous) to green (high/safe)
        cmap = mcolors.LinearSegmentedColormap.from_list(
            "dist", ["#d32f2f", "#ff9800", "#ffeb3b", "#8bc34a", "#2e7d32"]
        )

        im = ax.imshow(data, cmap=cmap, aspect="auto")
        ax.set_xticks(range(n))
        ax.set_yticks(range(n))

        # Truncate labels if too long
        labels = [name[:12] for name in matrix.sample_names]
        ax.set_xticklabels(labels, fontsize=6, rotation=45, ha="right")
        ax.set_yticklabels(labels, fontsize=6)

        # Add distance values in cells
        for i in range(n):
            for j in range(n):
                if i != j:
                    val = matrix.combined_distances[i][j]
                    if val is not None:
                        ax.text(j, i, str(val), ha="center", va="center", fontsize=5, color="black")

        ax.set_title("Combined Index Distance (i7+i5)", fontsize=8)
        fig.colorbar(im, ax=ax, shrink=0.8)
        plt.tight_layout()

        buf = BytesIO()
        fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
        plt.close(fig)
        buf.seek(0)

        img_width = min(17 * cm, fig_width * 2.2 * cm)
        img_height = min(14 * cm, fig_height * 2.2 * cm)
        return Image(buf, width=img_width, height=img_height)

    @classmethod
    def _render_color_balance(
        cls,
        balance: IndexColorBalance,
        index_type: str,
        channel_config: Optional[dict] = None,
    ) -> Optional[Image]:
        """Render color balance as stacked bar chart."""
        if not balance.positions:
            return None

        positions = sorted(balance.positions, key=lambda p: p.position)
        n = len(positions)
        x = np.arange(n)

        a_counts = [p.a_count for p in positions]
        c_counts = [p.c_count for p in positions]
        g_counts = [p.g_count for p in positions]
        t_counts = [p.t_count for p in positions]

        fig_width = max(4, min(8, n * 0.4 + 2))
        fig, ax = plt.subplots(figsize=(fig_width, 2.5))

        bar_width = 0.6
        ax.bar(x, a_counts, bar_width, label="A", color="#4caf50")
        ax.bar(x, c_counts, bar_width, bottom=a_counts, label="C", color="#2196f3")
        bottom_gc = [a + c for a, c in zip(a_counts, c_counts)]
        ax.bar(x, g_counts, bar_width, bottom=bottom_gc, label="G", color="#333333")
        bottom_gct = [b + g for b, g in zip(bottom_gc, g_counts)]
        ax.bar(x, t_counts, bar_width, bottom=bottom_gct, label="T", color="#f44336")

        # Mark positions with issues
        for i, p in enumerate(positions):
            if p.status == ColorBalanceStatus.ERROR:
                ax.axvspan(i - 0.4, i + 0.4, color="red", alpha=0.15)
            elif p.status == ColorBalanceStatus.WARNING:
                ax.axvspan(i - 0.4, i + 0.4, color="orange", alpha=0.1)

        ax.set_xticks(x)
        ax.set_xticklabels([str(p.position) for p in positions], fontsize=6)
        ax.set_xlabel("Position", fontsize=7)
        ax.set_ylabel("Count", fontsize=7)
        ax.set_title(f"{index_type} Color Balance", fontsize=8)
        ax.legend(fontsize=6, loc="upper right")
        ax.tick_params(axis="y", labelsize=6)
        plt.tight_layout()

        buf = BytesIO()
        fig.savefig(buf, format="png", dpi=150, bbox_inches="tight")
        plt.close(fig)
        buf.seek(0)

        img_width = min(17 * cm, fig_width * 2.2 * cm)
        return Image(buf, width=img_width, height=5.5 * cm)
