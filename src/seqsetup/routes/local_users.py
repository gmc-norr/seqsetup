"""Admin routes for local user management.

Migrated to Starlette ``Route(...)`` registration; LocalUsersPage /
EditUserRow / UserRow FT components stay (transitional). All mutation
audits + last-admin guards + weak-password policy preserved.
"""

from datetime import datetime

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from ..components.local_users import EditUserRow, LocalUsersPage, UserRow
from ..context import AppContext
from ..models.local_user import LocalUser, WeakPasswordError
from ..models.user import UserRole
from ..services.audit_log import audit
from ..templating import ft_page_response, ft_response
from .utils import get_username, require_admin, sanitize_string


def register(app, ctx: AppContext) -> None:
    """Register local user management routes."""
    if not hasattr(app, "routes") or not isinstance(app.routes, list):
        raise TypeError(
            f"local_users.register requires a Starlette-style app with a mutable "
            f"routes list, got {type(app).__name__}"
        )

    def _page_response(users, message=None, error=None):
        """Convenience wrapper for the page fragment after mutations."""
        return ft_response(LocalUsersPage(users, message=message, error=error))

    def admin_users(request: Request) -> Response:
        """GET /admin/users — full page."""
        if err := require_admin(request):
            return err
        return ft_page_response(
            request,
            LocalUsersPage(ctx.local_user_repo.list_all()),
            page_title="Local Users",
            active_route="/admin/users",
        )

    async def create_user(request: Request) -> Response:
        """POST /admin/users/create — create a user."""
        if err := require_admin(request):
            return err

        form = await request.form()
        username = sanitize_string(form.get("username", ""), 256)
        display_name = sanitize_string(form.get("display_name", ""), 256)
        email = sanitize_string(form.get("email", ""), 256)
        role = form.get("role", "standard")
        password = form.get("password", "")

        repo = ctx.local_user_repo

        if not username:
            return _page_response(repo.list_all(), error="Username is required.")
        if not display_name:
            return _page_response(repo.list_all(), error="Display name is required.")
        if not password:
            return _page_response(repo.list_all(), error="Password is required.")
        if repo.exists(username):
            return _page_response(repo.list_all(), error=f"User '{username}' already exists.")

        try:
            user_role = UserRole(role)
        except ValueError:
            user_role = UserRole.STANDARD

        new_user = LocalUser(
            username=username,
            display_name=display_name,
            role=user_role,
            email=email,
        )
        try:
            new_user.set_password(password)
        except WeakPasswordError as e:
            return _page_response(repo.list_all(), error=str(e))
        repo.save(new_user)

        audit(
            "user.created",
            actor=get_username(request),
            target=username,
            role=user_role.value,
        )

        return _page_response(
            repo.list_all(),
            message=f"User '{username}' created successfully.",
        )

    def edit_user_form(request: Request) -> Response:
        """GET /admin/users/{username}/edit-form — inline edit form."""
        if err := require_admin(request):
            return err
        username = request.path_params["username"]
        user = ctx.local_user_repo.get_by_username(username)
        if not user:
            return Response("User not found", status_code=404)
        return ft_response(EditUserRow(user))

    def cancel_edit(request: Request) -> Response:
        """GET /admin/users/{username}/cancel-edit — restore read-only row."""
        if err := require_admin(request):
            return err
        username = request.path_params["username"]
        user = ctx.local_user_repo.get_by_username(username)
        if not user:
            return Response("User not found", status_code=404)
        return ft_response(UserRow(user))

    async def edit_user(request: Request) -> Response:
        """POST /admin/users/{username}/edit — update a user."""
        if err := require_admin(request):
            return err

        username = request.path_params["username"]
        form = await request.form()
        display_name = sanitize_string(form.get("display_name", ""), 256)
        email = sanitize_string(form.get("email", ""), 256)
        role = form.get("role", "standard")
        password = form.get("password", "")

        repo = ctx.local_user_repo
        user = repo.get_by_username(username)
        if not user:
            return _page_response(repo.list_all(), error=f"User '{username}' not found.")

        if not display_name:
            return _page_response(repo.list_all(), error="Display name is required.")

        try:
            new_role = UserRole(role)
        except ValueError:
            new_role = UserRole.STANDARD

        # Prevent demoting the last admin.
        if user.role == UserRole.ADMIN and new_role != UserRole.ADMIN:
            if repo.count_admins() <= 1:
                return _page_response(
                    repo.list_all(),
                    error="Cannot change role: this is the last admin user.",
                )

        previous_role = user.role
        user.display_name = display_name
        user.email = email
        user.role = new_role

        password_changed = bool(password)
        if password:
            try:
                user.set_password(password)
            except WeakPasswordError as e:
                return _page_response(repo.list_all(), error=str(e))

        user.updated_at = datetime.now()
        repo.save(user)

        audit(
            "user.updated",
            actor=get_username(request),
            target=username,
            from_role=previous_role.value,
            to_role=new_role.value,
            password_changed=password_changed,
        )

        return _page_response(
            repo.list_all(),
            message=f"User '{username}' updated successfully.",
        )

    def delete_user(request: Request) -> Response:
        """POST /admin/users/{username}/delete — delete a user."""
        if err := require_admin(request):
            return err
        username = request.path_params["username"]
        repo = ctx.local_user_repo
        user = repo.get_by_username(username)
        if not user:
            return _page_response(repo.list_all(), error=f"User '{username}' not found.")

        if user.role == UserRole.ADMIN and repo.count_admins() <= 1:
            return _page_response(
                repo.list_all(),
                error="Cannot delete the last admin user.",
            )

        deleted_role = user.role.value
        repo.delete(username)
        audit(
            "user.deleted",
            actor=get_username(request),
            target=username,
            deleted_role=deleted_role,
        )
        return _page_response(repo.list_all(), message=f"User '{username}' deleted.")

    app.routes.append(Route("/admin/users", admin_users, methods=["GET"]))
    app.routes.append(Route("/admin/users/create", create_user, methods=["POST"]))
    app.routes.append(Route("/admin/users/{username}/edit-form", edit_user_form, methods=["GET"]))
    app.routes.append(Route("/admin/users/{username}/cancel-edit", cancel_edit, methods=["GET"]))
    app.routes.append(Route("/admin/users/{username}/edit", edit_user, methods=["POST"]))
    app.routes.append(Route("/admin/users/{username}/delete", delete_user, methods=["POST"]))
