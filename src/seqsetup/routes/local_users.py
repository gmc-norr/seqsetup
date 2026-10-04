"""Admin routes for local user management.

Migrated to APIRouter + Pydantic. The two inline-edit HTMX routes
(.../edit-form and .../cancel-edit) are GONE — the read-only row and
the edit form share a single Jinja2 partial gated by an Alpine
`x-data="{ editing: false }"` toggle. Save still uses HTMX POST so
the server stays the source of truth for the user list.

URL change in this commit: POST /admin/users/{username}/delete is
now DELETE /admin/users/{username} (REST cleanup).

Admin-only via router-level require_admin_dep. Preserves:
  - Last-admin guard (can't demote or delete the last admin)
  - WeakPasswordError → re-render with error
  - Full audit trail (user.created, user.updated, user.deleted)
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from pydantic import BaseModel, Field
from pydantic.functional_validators import BeforeValidator
from starlette.responses import HTMLResponse, Response

from ..context import AppContext
from ..forms.validators import strip_and_truncate
from ..models.local_user import USERNAME_PATTERN, LocalUser, WeakPasswordError
from ..models.user import UserRole
from ..services import web_sessions
from ..services.audit_log import audit
from ..templating import render
from .dependencies import get_ctx, require_admin_dep
from .utils import get_username
from ..utils.clock import utcnow

logger = logging.getLogger(__name__)


router = APIRouter(
    tags=["admin-users"],
    dependencies=[Depends(require_admin_dep)],
)


_USERNAME_RE = USERNAME_PATTERN      # one limit with sign-in and create-admin (review P3)


class CreateUserForm(BaseModel):
    """Create-local-user form.

    All string fields CLAMP. Password REJECT empty (the model's
    set_password() rejects weak passwords; we let an empty password
    fail-fast at the form-validation boundary).

    ``username`` is also character-restricted: it appears as a URL path
    parameter in ``DELETE /admin/users/{username}`` and as an HTML ``id``
    attribute (``user-row-{{ user.username }}``). A username containing
    ``/`` would make the row undeletable via the UI; HTML metacharacters
    would couple the form value to template safety. Pinning to
    ``[A-Za-z0-9._@-]`` (the common admin-username alphabet) eliminates
    that class of problem at the form-validation boundary.

    role: Pydantic rejects unknown enum values automatically (422).
    """
    username: Annotated[
        str,
        BeforeValidator(strip_and_truncate(128)),
        Field(min_length=1, pattern=_USERNAME_RE),
    ]
    display_name: Annotated[str, BeforeValidator(strip_and_truncate(256)), Field(min_length=1)]
    email: Annotated[str, BeforeValidator(strip_and_truncate(256))] = ""
    role: UserRole = UserRole.STANDARD
    password: str = Field(min_length=1, max_length=512)


class EditUserForm(BaseModel):
    """Edit-local-user form.

    Same clamp/reject semantics as CreateUserForm but:
      - username is in the URL, not the form
      - password is optional (empty = keep existing) — REJECT oversize
        per same reasoning as LoginForm.
    """
    display_name: Annotated[str, BeforeValidator(strip_and_truncate(256)), Field(min_length=1)]
    email: Annotated[str, BeforeValidator(strip_and_truncate(256))] = ""
    role: UserRole = UserRole.STANDARD
    password: str = Field(default="", max_length=512)


def _clean_up_logins(ctx, username: str):
    """Remove the user's login rows. The account write already ended them
    (session stamp changed, or the record is gone), so a failure here is
    logged, not fatal. Returns the number removed, or None on failure."""
    try:
        return web_sessions.end_all_for(ctx.web_session_repo, username)
    except Exception:
        logger.warning("Could not remove login rows for %s", username, exc_info=True)
        return None


def _render_page(request, ctx, message="", error=""):
    """Render the full page (or the page fragment via block_name)."""
    return render(
        request,
        "admin/local_users.html",
        {
            "users": ctx.local_user_repo.list_all(),
            "message": message,
            "error": error,
        },
        block_name="local_users_page",
    )


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /admin/users — full page."""
    return render(
        request,
        "admin/local_users.html",
        {
            "users": ctx.local_user_repo.list_all(),
            "message": "",
            "error": "",
        },
    )


@router.post("/admin/users/create", response_class=HTMLResponse)
def create_user(
    request: Request,
    form: Annotated[CreateUserForm, Form()],
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /admin/users/create — create a new local user."""
    repo = ctx.local_user_repo
    if repo.exists(form.username):
        return _render_page(request, ctx, error=f"User '{form.username}' already exists.")

    new_user = LocalUser(
        username=form.username,
        display_name=form.display_name,
        role=form.role,
        email=form.email,
    )
    try:
        new_user.set_password(form.password)
    except WeakPasswordError as e:
        return _render_page(request, ctx, error=str(e))
    repo.save(new_user)

    audit(
        "user.created",
        actor=get_username(request),
        target=form.username,
        role=form.role.value,
    )
    return _render_page(request, ctx, message=f"User '{form.username}' created successfully.")


@router.post("/admin/users/{username}/edit", response_class=HTMLResponse)
def edit_user(
    request: Request,
    username: str,
    form: Annotated[EditUserForm, Form()],
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /admin/users/{username}/edit — update a user.

    HTMX fragment swap into #local-users-page (the whole page wrapper)
    — full re-render so the Alpine edit toggle on every row resets,
    matching the previous "save closes the edit form" UX.
    """
    repo = ctx.local_user_repo
    user = repo.get_by_username(username)
    if not user:
        return _render_page(request, ctx, error=f"User '{username}' not found.")

    # Last-admin guard: if this user IS the only admin and we're
    # demoting them, reject.
    if user.role == UserRole.ADMIN and form.role != UserRole.ADMIN:
        if repo.count_admins() <= 1:
            return _render_page(
                request, ctx,
                error="Cannot change role: this is the last admin user.",
            )

    previous_role = user.role
    user.display_name = form.display_name
    user.email = form.email
    user.role = form.role

    password_changed = bool(form.password)
    if form.password:
        try:
            user.set_password(form.password)
        except WeakPasswordError as e:
            return _render_page(request, ctx, error=str(e))

    user.updated_at = utcnow()
    repo.save(user)

    # A role or password change also changed the user's session stamp
    # (models/local_user.py), so the save above already ended their logins.
    logins_ended = form.role != previous_role or password_changed
    extra = {}
    if logins_ended:
        extra = {"sessions_ended": True,
                 "session_rows_removed": _clean_up_logins(ctx, username)}
    audit(
        "user.updated",
        actor=get_username(request),
        target=username,
        from_role=previous_role.value,
        to_role=form.role.value,
        password_changed=password_changed,
        **extra,
    )
    message = f"User '{username}' updated."
    if logins_ended:
        message += " Their open logins were ended."
    return _render_page(request, ctx, message=message)


@router.delete("/admin/users/{username}", response_class=HTMLResponse)
def delete_user(
    request: Request,
    username: str,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """DELETE /admin/users/{username} — delete a user.

    URL change: was POST .../{username}/delete. The last-admin guard
    rejects with an error message rendered into the page.
    """
    repo = ctx.local_user_repo
    user = repo.get_by_username(username)
    if not user:
        return _render_page(request, ctx, error=f"User '{username}' not found.")

    if user.role == UserRole.ADMIN and repo.count_admins() <= 1:
        return _render_page(request, ctx, error="Cannot delete the last admin user.")

    deleted_role = user.role.value
    repo.delete(username)
    # With the record gone its logins are refused already; this is cleanup.
    removed = _clean_up_logins(ctx, username)
    audit(
        "user.deleted",
        actor=get_username(request),
        target=username,
        deleted_role=deleted_role,
        sessions_ended=True,
        session_rows_removed=removed,
    )
    return _render_page(
        request, ctx, message=f"User '{username}' deleted. Their open logins were ended.")
