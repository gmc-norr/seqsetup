"""Shared utilities for route handlers.

Access-model note (audit L1)
----------------------------
SeqSetup is intentionally single-tenant: any authenticated user with
``standard`` role can view, edit, and (when archived) delete any run in the
system. There is no per-resource owner field and no ACL check beyond the
auth gate. The ``admin`` role is the only authorization boundary, used for
config changes (instruments, auth, LIMS, index kits) and user management.

If you find yourself adding per-resource ownership checks (e.g. only the
creator can edit a run), STOP — that's a multi-tenant design decision that
must be coordinated across the whole route surface, model layer, and UI.
Implement it consistently or not at all.
"""

import re
from urllib.parse import unquote

from starlette.responses import Response

from ..models.sequencing_run import RunStatus


def get_username(req) -> str:
    """Extract username from request auth scope."""
    user = req.scope.get("auth")
    if user:
        return user.username
    api_token = req.scope.get("api_token")
    if api_token:
        return f"api:{api_token.name}"
    return ""


def selected_kit_id(request) -> str:
    """The kit the page's index-kit dropdown shows, sent by app.js on every
    HTMX request as the X-Selected-Kit header (URI-encoded), so a re-rendered
    sample section keeps it. Only ever compared with existing kit ids."""
    return unquote(request.headers.get("X-Selected-Kit", ""))[:512]


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


class UploadTooLargeError(Exception):
    """Raised by ``read_upload_capped`` when an upload exceeds the byte cap."""

    def __init__(self, max_bytes: int):
        self.max_bytes = max_bytes
        super().__init__(f"Upload exceeds maximum size of {max_bytes} bytes")


async def read_upload_capped(
    upload, max_bytes: int, chunk_size: int = 64 * 1024
) -> bytes:
    """Read an UploadFile in bounded chunks, refusing oversize bodies early.

    ``UploadFile.read()`` with no argument buffers the ENTIRE body into memory
    before any size check can run — a multi-GB POST then spikes RAM regardless
    of the cap. Reading fixed-size chunks and short-circuiting as soon as the
    cumulative size exceeds ``max_bytes`` bounds the worst-case allocation to
    roughly ``max_bytes + chunk_size``.

    Raises ``UploadTooLargeError`` once the cap is exceeded (before reading the
    rest of the stream). Shared by every multipart upload route so the bound
    cannot be forgotten on one of them.
    """
    chunks: list[bytes] = []
    bytes_so_far = 0
    while True:
        chunk = await upload.read(chunk_size)
        if not chunk:
            break
        bytes_so_far += len(chunk)
        if bytes_so_far > max_bytes:
            raise UploadTooLargeError(max_bytes)
        chunks.append(chunk)
    return b"".join(chunks)
