"""API token management page components."""

from typing import Optional

from fasthtml.common import *

from ..models.api_token import ApiToken


def ApiTokensPage(
    tokens: list[ApiToken],
    new_token: Optional[str] = None,
    message: Optional[str] = None,
):
    """API tokens management page.

    Args:
        tokens: List of existing API tokens.
        new_token: Plaintext of a newly created token (shown once).
        message: Optional status message.
    """
    return Div(
        H2("API Tokens"),
        P(
            "Manage tokens for programmatic API access. "
            "Requests to /api/ endpoints require an Authorization: Bearer <token> header.",
            cls="page-description",
        ),

        # Status message
        Div(message, cls="settings-message success") if message else None,

        # Show newly created token
        NewTokenAlert(new_token) if new_token else None,

        # Create token form
        CreateTokenForm(),

        # Existing tokens table
        TokenTable(tokens),

        cls="admin-settings-page",
        id="api-tokens-page",
    )


def NewTokenAlert(plaintext_token: str):
    """Alert showing a newly created token (displayed only once)."""
    return Div(
        H3("Token Created"),
        P(
            "Copy this token now. It will not be shown again.",
            style="color: var(--warning); font-weight: 500;",
        ),
        Div(
            Code(plaintext_token),
            style=(
                "background: #1e293b; color: #e2e8f0; padding: 0.75rem;"
                " border-radius: 4px; font-size: 0.9rem; word-break: break-all;"
                " margin-bottom: 1rem;"
            ),
        ),
        style=(
            "background: #fffbeb; border: 1px solid #fbbf24;"
            " border-radius: 8px; padding: 1rem; margin-bottom: 1rem;"
        ),
    )


def CreateTokenForm():
    """Form for creating a new API token."""
    return Form(
        Fieldset(
            Legend("Create New Token"),
            Div(
                Label("Token Name:", fr="token_name"),
                Input(
                    type="text",
                    name="name",
                    id="token_name",
                    placeholder="e.g. LIMS integration",
                    required=True,
                    cls="settings-input settings-input-small",
                ),
                P("A descriptive name to identify this token.", cls="field-hint"),
                cls="form-row",
            ),
            Div(
                Button("Create Token", type="submit", cls="btn-primary"),
                cls="form-actions",
            ),
        ),
        hx_post="/admin/api-tokens/create",
        hx_target="#api-tokens-page",
        hx_swap="outerHTML",
    )


def TokenTable(tokens: list[ApiToken]):
    """Table listing existing API tokens."""
    if not tokens:
        return Div(
            P("No API tokens have been created yet.", cls="empty-message"),
            style="margin-top: 1rem;",
        )

    rows = []
    for token in tokens:
        rows.append(
            Tr(
                Td(token.name),
                Td(token.created_by),
                Td(token.created_at.strftime("%Y-%m-%d %H:%M")),
                Td(
                    Button(
                        "Revoke",
                        hx_post=f"/admin/api-tokens/{token.id}/revoke",
                        hx_target="#api-tokens-page",
                        hx_swap="outerHTML",
                        hx_confirm=f"Revoke token '{token.name}'? This cannot be undone.",
                        cls="btn-danger btn-small",
                    ),
                ),
            )
        )

    return Div(
        H3(f"Active Tokens ({len(tokens)})"),
        Table(
            Thead(
                Tr(
                    Th("Name"),
                    Th("Created By"),
                    Th("Created At"),
                    Th("Actions"),
                ),
            ),
            Tbody(*rows),
            cls="sample-table",
        ),
        style="margin-top: 1.5rem;",
    )
