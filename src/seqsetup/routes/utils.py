"""Shared utilities for route handlers."""

from starlette.responses import Response

from ..models.sequencing_run import RunStatus


def get_username(req) -> str:
    """Extract username from request auth scope."""
    user = req.scope.get("auth")
    return user.username if user else ""


def check_run_editable(run) -> Response | None:
    """Check if run is in DRAFT status (editable).

    Returns error Response if not editable, None if OK.
    """
    if run.status != RunStatus.DRAFT:
        return Response("Run is not in draft status and cannot be edited", status_code=403)
    return None
