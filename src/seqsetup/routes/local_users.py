"""Admin routes for local user management."""

from fasthtml.common import *
from starlette.responses import Response

from .utils import require_admin
from ..components.layout import AppShell
from ..components.local_users import EditUserRow, LocalUsersPage, UserTable
from ..models.local_user import LocalUser
from ..models.user import UserRole


def register(app, rt, get_local_user_repo):
    """Register local user management routes."""

    @app.get("/admin/users")
    def admin_users(req):
        """Local user management page."""
        error = require_admin(req)
        if error:
            return error

        user = req.scope.get("auth")
        users = get_local_user_repo().list_all()

        return AppShell(
            user=user,
            active_route="/admin/users",
            content=LocalUsersPage(users),
            title="Local Users",
        )

    @app.post("/admin/users/create")
    def create_user(
        req,
        username: str = "",
        display_name: str = "",
        email: str = "",
        role: str = "standard",
        password: str = "",
    ):
        """Create a new local user."""
        error = require_admin(req)
        if error:
            return error

        repo = get_local_user_repo()
        username = username.strip()
        display_name = display_name.strip()

        if not username:
            return LocalUsersPage(repo.list_all(), error="Username is required.")

        if not display_name:
            return LocalUsersPage(repo.list_all(), error="Display name is required.")

        if not password:
            return LocalUsersPage(repo.list_all(), error="Password is required.")

        if repo.exists(username):
            return LocalUsersPage(
                repo.list_all(), error=f"User '{username}' already exists."
            )

        try:
            user_role = UserRole(role)
        except ValueError:
            user_role = UserRole.STANDARD

        new_user = LocalUser(
            username=username,
            display_name=display_name,
            role=user_role,
            email=email.strip(),
        )
        new_user.set_password(password)
        repo.save(new_user)

        return LocalUsersPage(
            repo.list_all(), message=f"User '{username}' created successfully."
        )

    @app.get("/admin/users/{username}/edit-form")
    def edit_user_form(req, username: str):
        """Return inline edit form for a user row."""
        error = require_admin(req)
        if error:
            return error

        repo = get_local_user_repo()
        user = repo.get_by_username(username)
        if not user:
            return Response("User not found", status_code=404)

        return EditUserRow(user)

    @app.get("/admin/users/{username}/cancel-edit")
    def cancel_edit(req, username: str):
        """Return the normal user row (cancel inline edit)."""
        error = require_admin(req)
        if error:
            return error

        repo = get_local_user_repo()
        user = repo.get_by_username(username)
        if not user:
            return Response("User not found", status_code=404)

        role_label = "Admin" if user.role == UserRole.ADMIN else "Standard"
        return Tr(
            Td(user.username),
            Td(user.display_name),
            Td(user.email or "-"),
            Td(role_label),
            Td(
                user.created_at.strftime("%Y-%m-%d %H:%M")
                if user.created_at
                else "-"
            ),
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

    @app.post("/admin/users/{username}/edit")
    def edit_user(
        req,
        username: str,
        display_name: str = "",
        email: str = "",
        role: str = "standard",
        password: str = "",
    ):
        """Update a local user."""
        error = require_admin(req)
        if error:
            return error

        repo = get_local_user_repo()
        user = repo.get_by_username(username)
        if not user:
            return LocalUsersPage(repo.list_all(), error=f"User '{username}' not found.")

        display_name = display_name.strip()
        if not display_name:
            return LocalUsersPage(repo.list_all(), error="Display name is required.")

        # Prevent demoting the last admin
        try:
            new_role = UserRole(role)
        except ValueError:
            new_role = UserRole.STANDARD

        if user.role == UserRole.ADMIN and new_role != UserRole.ADMIN:
            if repo.count_admins() <= 1:
                return LocalUsersPage(
                    repo.list_all(),
                    error="Cannot change role: this is the last admin user.",
                )

        user.display_name = display_name
        user.email = email.strip()
        user.role = new_role

        if password:
            user.set_password(password)

        from datetime import datetime
        user.updated_at = datetime.now()
        repo.save(user)

        return LocalUsersPage(
            repo.list_all(), message=f"User '{username}' updated successfully."
        )

    @app.post("/admin/users/{username}/delete")
    def delete_user(req, username: str):
        """Delete a local user."""
        error = require_admin(req)
        if error:
            return error

        repo = get_local_user_repo()
        user = repo.get_by_username(username)

        if not user:
            return LocalUsersPage(repo.list_all(), error=f"User '{username}' not found.")

        # Prevent deleting the last admin
        if user.role == UserRole.ADMIN and repo.count_admins() <= 1:
            return LocalUsersPage(
                repo.list_all(),
                error="Cannot delete the last admin user.",
            )

        repo.delete(username)
        return LocalUsersPage(
            repo.list_all(), message=f"User '{username}' deleted."
        )
