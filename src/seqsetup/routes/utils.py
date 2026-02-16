"""Shared utilities for route handlers."""

import re

from starlette.responses import Response

from ..models.sequencing_run import RunStatus
from ..models.user import UserRole


def get_username(req) -> str:
    """Extract username from request auth scope."""
    user = req.scope.get("auth")
    if user:
        return user.username
    api_token = req.scope.get("api_token")
    if api_token:
        return f"api:{api_token.name}"
    return ""


def check_run_editable(run) -> Response | None:
    """Check if run is in DRAFT status (editable).

    Returns error Response if not editable, None if OK.
    """
    if run.status != RunStatus.DRAFT:
        return Response("Run is not in draft status and cannot be edited", status_code=403)
    return None


def require_admin(req) -> Response | None:
    """Check if user is admin, return error response if not."""
    user = req.scope.get("auth")
    if not user or user.role != UserRole.ADMIN:
        return Response("Admin access required", status_code=403)
    return None


def sanitize_filename(name: str, default: str = "export") -> str:
    """Sanitize a filename for use in Content-Disposition headers.

    Removes or replaces characters that could be used for header injection
    or cause filesystem issues.
    """
    if not name:
        return default
    sanitized = re.sub(r'[^\w\-. ]', '', name)
    sanitized = sanitized.replace(' ', '_')
    sanitized = sanitized.strip('. ')
    sanitized = sanitized[:100]
    return sanitized if sanitized else default
