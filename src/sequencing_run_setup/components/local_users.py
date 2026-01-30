"""Local user management page components."""

from typing import Optional

from fasthtml.common import *

from ..models.local_user import LocalUser
from ..models.user import UserRole


def LocalUsersPage(
    users: list[LocalUser],
    message: Optional[str] = None,
    error: Optional[str] = None,
):
    """Local users management page.

    Args:
        users: List of existing local users.
        message: Optional success message.
        error: Optional error message.
    """
    return Div(
        H2("Local Users"),
        P(
            "Manage local user accounts. These users authenticate with username and password.",
            cls="page-description",
        ),
        Div(message, cls="settings-message success") if message else None,
        Div(error, cls="error-message") if error else None,
        CreateUserForm(),
        UserTable(users),
        cls="admin-settings-page",
        id="local-users-page",
    )


def CreateUserForm():
    """Form for creating a new local user."""
    return Form(
        Fieldset(
            Legend("Create New User"),
            Div(
                Label("Username:", fr="new_username"),
                Input(
                    type="text",
                    name="username",
                    id="new_username",
                    placeholder="e.g. jdoe",
                    required=True,
                    cls="settings-input settings-input-small",
                ),
                cls="form-row",
            ),
            Div(
                Label("Display Name:", fr="new_display_name"),
                Input(
                    type="text",
                    name="display_name",
                    id="new_display_name",
                    placeholder="e.g. Jane Doe",
                    required=True,
                    cls="settings-input settings-input-small",
                ),
                cls="form-row",
            ),
            Div(
                Label("Email:", fr="new_email"),
                Input(
                    type="email",
                    name="email",
                    id="new_email",
                    placeholder="e.g. jdoe@example.com",
                    cls="settings-input settings-input-small",
                ),
                cls="form-row",
            ),
            Div(
                Label("Role:", fr="new_role"),
                Select(
                    Option("Standard", value="standard", selected=True),
                    Option("Admin", value="admin"),
                    name="role",
                    id="new_role",
                    cls="settings-input settings-input-small",
                ),
                cls="form-row",
            ),
            Div(
                Label("Password:", fr="new_password"),
                Input(
                    type="password",
                    name="password",
                    id="new_password",
                    required=True,
                    cls="settings-input settings-input-small",
                ),
                cls="form-row",
            ),
            Div(
                Button("Create User", type="submit", cls="btn-primary"),
                cls="form-actions",
            ),
        ),
        hx_post="/admin/users/create",
        hx_target="#local-users-page",
        hx_swap="outerHTML",
    )


def UserTable(users: list[LocalUser]):
    """Table listing existing local users."""
    if not users:
        return Div(
            P("No local users have been created yet.", cls="empty-message"),
            style="margin-top: 1rem;",
        )

    rows = []
    for user in users:
        role_label = "Admin" if user.role == UserRole.ADMIN else "Standard"
        rows.append(
            Tr(
                Td(user.username),
                Td(user.display_name),
                Td(user.email or "-"),
                Td(role_label),
                Td(user.created_at.strftime("%Y-%m-%d %H:%M") if user.created_at else "-"),
                Td(
                    Div(
                        Button(
                            "Edit",
                            hx_get=f"/admin/users/{user.username}/edit-form",
                            hx_target=f"#user-row-{user.username}",
                            hx_swap="outerHTML",
                            cls="btn-secondary btn-small",
                        ),
                        Button(
                            "Delete",
                            hx_post=f"/admin/users/{user.username}/delete",
                            hx_target="#local-users-page",
                            hx_swap="outerHTML",
                            hx_confirm=f"Delete user '{user.username}'? This cannot be undone.",
                            cls="btn-danger btn-small",
                        ),
                        cls="actions",
                    ),
                ),
                id=f"user-row-{user.username}",
            )
        )

    return Div(
        H3(f"Users ({len(users)})"),
        Table(
            Thead(
                Tr(
                    Th("Username"),
                    Th("Display Name"),
                    Th("Email"),
                    Th("Role"),
                    Th("Created"),
                    Th("Actions"),
                ),
            ),
            Tbody(*rows),
            cls="sample-table",
        ),
        style="margin-top: 1.5rem;",
    )


def EditUserRow(user: LocalUser):
    """Inline edit form replacing a user table row."""
    return Tr(
        Td(user.username),
        Td(
            Input(
                type="text",
                name="display_name",
                value=user.display_name,
                required=True,
                cls="settings-input settings-input-small",
                style="width: 100%;",
            ),
        ),
        Td(
            Input(
                type="email",
                name="email",
                value=user.email or "",
                cls="settings-input settings-input-small",
                style="width: 100%;",
            ),
        ),
        Td(
            Select(
                Option("Standard", value="standard", selected=user.role == UserRole.STANDARD),
                Option("Admin", value="admin", selected=user.role == UserRole.ADMIN),
                name="role",
                cls="settings-input settings-input-small",
            ),
        ),
        Td(
            Input(
                type="password",
                name="password",
                placeholder="Leave blank to keep",
                cls="settings-input settings-input-small",
                style="width: 100%;",
            ),
        ),
        Td(
            Div(
                Button("Save", type="submit", cls="btn-primary btn-small"),
                Button(
                    "Cancel",
                    type="button",
                    hx_get=f"/admin/users/{user.username}/cancel-edit",
                    hx_target=f"#user-row-{user.username}",
                    hx_swap="outerHTML",
                    cls="btn-secondary btn-small",
                ),
                cls="actions",
            ),
        ),
        id=f"user-row-{user.username}",
        hx_post=f"/admin/users/{user.username}/edit",
        hx_target="#local-users-page",
        hx_swap="outerHTML",
        hx_include="find input, find select",
    )
