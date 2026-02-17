"""LIMS/Sample API configuration components."""

from typing import Optional

from fasthtml.common import *

from ...models.sample_api_config import SampleApiConfig


def SampleApiPage(config: SampleApiConfig, message: Optional[str] = None):
    """Sample API configuration page."""
    return Div(
        H2("LIMS Integration"),
        P(
            "Configure a connection to an external LIMS for fetching worklists and sample data.",
            cls="page-description",
        ),
        Div(message, cls="settings-message success") if message else None,
        SampleApiConfigForm(config),
        cls="admin-settings-page",
        id="sample-api-page",
    )


def SampleApiConfigForm(config: SampleApiConfig, message: Optional[str] = None, error: Optional[str] = None):
    """Form for sample API configuration."""
    return Div(
        Div(message, cls="settings-message success") if message else None,
        Div(
            error,
            style="background: rgba(220, 38, 38, 0.1); color: #dc2626; border: 1px solid #dc2626; padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem; font-size: 0.875rem;",
        ) if error else None,
        Form(
            Fieldset(
                Legend("API Endpoint"),
                Div(
                    Label("Base URL:", fr="base_url"),
                    Input(
                        type="text",
                        name="base_url",
                        id="base_url",
                        value=config.base_url,
                        placeholder="https://lims.example.com/api",
                        cls="settings-input",
                    ),
                    P("Base URL for the worksheet API. Endpoints used:", cls="field-hint"),
                    P(
                        Code("{base_url}/worksheets?detail=true"),
                        " \u2014 list available worksheets",
                        cls="field-hint",
                        style="margin-top:0.1rem;",
                    ),
                    P(
                        Code("{base_url}/worksheets/{id}"),
                        " \u2014 get samples for a worksheet",
                        cls="field-hint",
                        style="margin-top:0.1rem;",
                    ),
                    cls="form-row",
                ),
                Div(
                    Label("API Key:", fr="api_key"),
                    Input(
                        type="password",
                        name="api_key",
                        id="api_key",
                        placeholder="Leave blank to keep existing key",
                        cls="settings-input",
                    ),
                    P(
                        "Sent as 'api-key' header."
                        + (" Key is configured." if config.api_key else ""),
                        cls="field-hint",
                    ),
                    cls="form-row",
                ),
            ),
            Fieldset(
                Legend("Settings"),
                Div(
                    Label(
                        Input(
                            type="checkbox",
                            name="enabled",
                            checked=config.enabled,
                        ),
                        " Enable LIMS Integration",
                        cls="checkbox-label",
                    ),
                    P("When enabled, a 'Fetch Worklist' option appears in sample forms.", cls="field-hint"),
                    cls="form-row",
                ),
            ),
            Fieldset(
                Legend("Field Mappings"),
                P(
                    "Map API field names to SeqSetup fields. Leave blank to use defaults.",
                    cls="field-hint",
                    style="margin-bottom: 0.75rem;",
                ),
                Div(
                    Label("Worksheet ID field:", fr="field_worksheet_id"),
                    Input(
                        type="text",
                        name="field_worksheet_id",
                        id="field_worksheet_id",
                        value=config.field_mappings.get("worksheet_id", ""),
                        placeholder="e.g., AL",
                        cls="settings-input",
                    ),
                    P("API field name for worksheet ID (default: 'id').", cls="field-hint"),
                    cls="form-row",
                ),
                Div(
                    Label("Investigator field:", fr="field_investigator"),
                    Input(
                        type="text",
                        name="field_investigator",
                        id="field_investigator",
                        value=config.field_mappings.get("investigator", ""),
                        placeholder="e.g., Investigator",
                        cls="settings-input",
                    ),
                    P("API field name for investigator.", cls="field-hint"),
                    cls="form-row",
                ),
                Div(
                    Label("Updated timestamp field:", fr="field_updated_at"),
                    Input(
                        type="text",
                        name="field_updated_at",
                        id="field_updated_at",
                        value=config.field_mappings.get("updated_at", ""),
                        placeholder="e.g., updatedAt",
                        cls="settings-input",
                    ),
                    P("API field name for last updated timestamp.", cls="field-hint"),
                    cls="form-row",
                ),
                Div(
                    Label("Samples field:", fr="field_samples"),
                    Input(
                        type="text",
                        name="field_samples",
                        id="field_samples",
                        value=config.field_mappings.get("samples", ""),
                        placeholder="e.g., samples",
                        cls="settings-input",
                    ),
                    P("API field name for embedded samples data.", cls="field-hint"),
                    cls="form-row",
                ),
            ),
            Div(
                Button("Save Configuration", type="submit", cls="btn-primary"),
                cls="form-actions",
            ),
            hx_post="/admin/settings/sample-api",
            hx_target="#sample-api-config-form",
            hx_swap="outerHTML",
        ),
        id="sample-api-config-form",
    )
