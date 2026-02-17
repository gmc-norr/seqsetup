"""Instrument visibility settings components."""

from typing import Optional

from fasthtml.common import *

from ...models.instrument_definition import InstrumentDefinition


def InstrumentsPage(
    synced_instruments: list[InstrumentDefinition] = None,
    message: Optional[str] = None,
):
    """Instrument visibility settings page."""
    synced_instruments = synced_instruments or []

    # Show message if using local config fallback
    fallback_notice = None
    if not synced_instruments:
        fallback_notice = Div(
            Strong("Note: "),
            "No instruments have been synced from GitHub. ",
            "Using local configuration file (config/instruments.yaml) as fallback. ",
            A("Configure sync", href="/admin/config-sync"),
            " to enable instrument management.",
            cls="settings-message info",
            style="background: var(--bg-info, #e0f2fe); border-color: var(--border-info, #0ea5e9); margin-bottom: 1rem;",
        )

    return Div(
        H2("Instruments"),
        P(
            "Configure which instruments are available when setting up a new run.",
            cls="page-description",
        ),
        Div(message, cls="settings-message success") if message else None,
        fallback_notice,
        SyncedInstrumentsSection(synced_instruments) if synced_instruments else None,
        cls="admin-settings-page",
        id="instruments-page",
    )


def SyncedInstrumentsSection(instruments: list[InstrumentDefinition], message: Optional[str] = None):
    """Section showing synced instruments with enable/disable toggles."""
    if not instruments:
        return None

    # Group by chemistry type
    two_color = [i for i in instruments if i.chemistry_type == "2-color"]
    four_color = [i for i in instruments if i.chemistry_type == "4-color"]

    def instrument_row(inst: InstrumentDefinition):
        flowcell_names = ", ".join(fc.name for fc in inst.flowcells) if inst.flowcells else "None"
        return Tr(
            Td(
                Label(
                    Input(
                        type="checkbox",
                        name="enabled_instruments",
                        value=inst.id,
                        checked=inst.enabled,
                        hx_post="/admin/instruments/synced/toggle",
                        hx_vals=f'{{"instrument_id": "{inst.id}", "enabled": "{str(not inst.enabled).lower()}"}}',
                        hx_target="#synced-instruments-section",
                        hx_swap="outerHTML",
                    ),
                    cls="checkbox-label",
                ),
            ),
            Td(inst.name),
            Td(inst.version or "-"),
            Td(inst.chemistry_type),
            Td(flowcell_names),
            Td("Yes" if inst.has_dragen_onboard else "No"),
            Td(inst.source_file),
        )

    def instrument_table(instruments_list: list[InstrumentDefinition], title: str):
        if not instruments_list:
            return None
        return Div(
            H4(title),
            Table(
                Thead(
                    Tr(
                        Th("Enabled", style="width: 60px;"),
                        Th("Name"),
                        Th("Version"),
                        Th("Chemistry"),
                        Th("Flowcells"),
                        Th("DRAGEN"),
                        Th("Source"),
                    )
                ),
                Tbody(*[instrument_row(inst) for inst in instruments_list]),
                cls="sample-table",
            ),
            style="margin-bottom: 1rem;",
        )

    return Div(
        H3("Synced Instruments"),
        Div(message, cls="settings-message success", style="margin: 0.5rem 0;") if message else None,
        P(
            "Instruments synced from GitHub. Enable or disable which ones are available for new runs.",
            cls="field-hint",
            style="margin-bottom: 0.75rem;",
        ),
        instrument_table(two_color, "Two-Color SBS Instruments"),
        instrument_table(four_color, "Four-Color SBS Instruments"),
        Div(
            Button(
                "Enable All",
                type="button",
                hx_post="/admin/instruments/synced/enable-all",
                hx_target="#synced-instruments-section",
                hx_swap="outerHTML",
                cls="btn-secondary btn-small",
            ),
            Button(
                "Disable All",
                type="button",
                hx_post="/admin/instruments/synced/disable-all",
                hx_target="#synced-instruments-section",
                hx_swap="outerHTML",
                cls="btn-secondary btn-small",
                style="margin-left: 0.5rem;",
            ),
            style="margin-top: 0.5rem;",
        ),
        cls="synced-instruments-section",
        style="margin-bottom: 2rem; padding-bottom: 1.5rem; border-bottom: 1px solid var(--border);",
        id="synced-instruments-section",
    )
