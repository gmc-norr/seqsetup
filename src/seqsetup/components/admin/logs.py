"""Application log viewer components."""

from typing import Optional

from fasthtml.common import *


def LogsPage(
    entries: list,
    stats: dict,
    level_filter: str = "",
    search_filter: str = "",
    message: Optional[str] = None,
):
    """Admin logs viewer page."""
    return Div(
        H2("Application Logs"),
        P(
            "View recent application logs including sync operations and validation errors.",
            cls="page-description",
        ),

        # Success message
        Div(message, cls="settings-message success") if message else None,

        # Stats summary
        LogStats(stats),

        # Filters
        LogFilters(level_filter, search_filter),

        # Log entries
        LogEntriesTable(entries),

        cls="admin-logs-page",
        id="logs-page",
    )


def LogStats(stats: dict):
    """Display log statistics."""
    by_level = stats.get("by_level", {})

    level_badges = []
    for level in ["ERROR", "WARNING", "INFO", "DEBUG"]:
        count = by_level.get(level, 0)
        if count > 0:
            badge_cls = f"log-badge log-badge-{level.lower()}"
            level_badges.append(
                Span(f"{level}: {count}", cls=badge_cls)
            )

    return Div(
        Div(
            Span(f"Total: {stats.get('total', 0)} / {stats.get('max_entries', 0)} max"),
            *level_badges,
            cls="log-stats-row",
        ),
        Button(
            "Clear Logs",
            hx_post="/admin/logs/clear",
            hx_target="#logs-page",
            hx_swap="outerHTML",
            hx_confirm="Clear all captured logs?",
            cls="btn-secondary btn-small",
        ),
        cls="log-stats-panel",
        style="display: flex; justify-content: space-between; align-items: center; background: var(--bg); padding: 0.75rem 1rem; border-radius: 8px; margin-bottom: 1rem;",
    )


def LogFilters(level_filter: str = "", search_filter: str = ""):
    """Log filtering controls."""
    return Form(
        Div(
            Label("Level:", fr="level"),
            Select(
                Option("All Levels", value="", selected=not level_filter),
                Option("ERROR", value="ERROR", selected=level_filter == "ERROR"),
                Option("WARNING", value="WARNING", selected=level_filter == "WARNING"),
                Option("INFO", value="INFO", selected=level_filter == "INFO"),
                Option("DEBUG", value="DEBUG", selected=level_filter == "DEBUG"),
                name="level",
                id="level",
                cls="settings-input settings-input-small",
            ),
            cls="filter-field",
        ),
        Div(
            Label("Search:", fr="search"),
            Input(
                type="text",
                name="search",
                id="search",
                value=search_filter,
                placeholder="Search in messages...",
                cls="settings-input",
            ),
            cls="filter-field",
        ),
        Button("Filter", type="submit", cls="btn-primary btn-small"),
        Button(
            "Refresh",
            type="button",
            hx_get="/admin/logs",
            hx_target="#logs-page",
            hx_swap="outerHTML",
            cls="btn-secondary btn-small",
        ),
        hx_get="/admin/logs",
        hx_target="#logs-page",
        hx_swap="outerHTML",
        cls="log-filters",
        style="display: flex; gap: 1rem; align-items: end; margin-bottom: 1rem; flex-wrap: wrap;",
    )


def LogEntriesTable(entries: list):
    """Table of log entries."""
    if not entries:
        return Div(
            P("No log entries found.", cls="empty-message"),
            cls="log-entries-empty",
            style="padding: 2rem; text-align: center; color: var(--text-muted);",
        )

    rows = []
    for entry in entries:
        level_cls = f"log-level log-level-{entry.level.lower()}"
        timestamp_str = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")

        rows.append(
            Tr(
                Td(timestamp_str, cls="log-col-time"),
                Td(Span(entry.level, cls=level_cls), cls="log-col-level"),
                Td(entry.logger_name, cls="log-col-logger"),
                Td(
                    Pre(entry.message, cls="log-message"),
                    cls="log-col-message",
                ),
            )
        )

    return Div(
        Table(
            Thead(
                Tr(
                    Th("Time", cls="log-col-time"),
                    Th("Level", cls="log-col-level"),
                    Th("Logger", cls="log-col-logger"),
                    Th("Message", cls="log-col-message"),
                )
            ),
            Tbody(*rows),
            cls="log-table",
        ),
        cls="log-entries-container",
        style="overflow-x: auto;",
    )
