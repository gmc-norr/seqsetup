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


# Valid state transitions: source -> set of allowed targets
_VALID_TRANSITIONS: dict[RunStatus, set[RunStatus]] = {
    RunStatus.DRAFT: {RunStatus.READY},
    RunStatus.READY: {RunStatus.DRAFT, RunStatus.ARCHIVED},
    RunStatus.ARCHIVED: set(),  # Terminal state
}


def check_status_transition(current: RunStatus, target: RunStatus) -> Response | None:
    """Validate a run status transition against the state machine.

    Valid transitions: DRAFT → READY, READY → DRAFT, READY → ARCHIVED.
    ARCHIVED is a terminal state.

    Returns error Response if transition is invalid, None if OK.
    """
    allowed = _VALID_TRANSITIONS.get(current, set())
    if target not in allowed:
        return Response(
            f"Invalid status transition: {current.value} → {target.value}",
            status_code=400,
        )
    return None


def check_run_exportable(run) -> Response | None:
    """Check if run is in an exportable state (READY or ARCHIVED).

    Returns error Response if not exportable, None if OK.
    """
    if run.status not in (RunStatus.READY, RunStatus.ARCHIVED):
        return Response("Exports are only available for ready or archived runs", status_code=403)
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


def sanitize_string(value: str, max_len: int = 256) -> str:
    """Sanitize user input string: strip whitespace and limit length.
    
    Args:
        value: String to sanitize
        max_len: Maximum length after stripping (default: 256)
    
    Returns:
        Stripped and length-limited string
    """
    return value.strip()[:max_len] if value else ""
