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
import unicodedata
from urllib.parse import quote, unquote

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


# IndexKit caps name and version at 256 characters each; kit_id is "name:version".
MAX_KIT_ID_LEN = 256 + 1 + 256


def selected_kit_id(request) -> str:
    """The kit the page's index-kit dropdown shows, sent by app.js on every
    HTMX request as the X-Selected-Kit header (URI-encoded), so a re-rendered
    sample section keeps it. Only ever compared with existing kit ids."""
    return unquote(request.headers.get("X-Selected-Kit", ""))[:MAX_KIT_ID_LEN]


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


def setup_panel_context(run, *, is_editable: bool, oob: bool = False) -> dict:
    """What ``runs/_run_config_panel.html`` needs, in one place.

    The run page (``routes/main.py``) and the status answer
    (``routes/runs.py``: ``update_status``) both render that panel. Building
    its context twice by hand is the condition that put the two out of step
    in the first place -- the page knew the run was Ready and the panel did
    not -- so both read it from here.
    """
    from ..data.instruments import get_flowcells_for_instrument, i5_workflow_names

    flowcells = get_flowcells_for_instrument(run.instrument_platform)
    return {
        "run": run,
        "flowcell_desc": flowcells.get(run.flowcell_type, {}).get(
            "description", run.flowcell_type),
        # No default: a run with no counts showed 150/10/10/150, and pressing
        # Continue would have saved those unseen (review F2).
        "cycles": run.run_cycles,
        "i5_workflows": i5_workflow_names(run.instrument_platform.value),
        "is_editable": is_editable,
        "oob": oob,
    }


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


def _ascii_only(name: str) -> str:
    """``name`` with its accents removed and every other non-ASCII character
    dropped, so the result is always encodable in a header value."""
    return unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")


def attachment_disposition(stem: str, default: str, suffix: str = "") -> str:
    """The ``Content-Disposition`` value for a download named ``stem + suffix``.

    ``stem`` is the variable part of the name — a run name or a kit name —
    already scrubbed of anything that cannot appear in a header (see
    ``sanitize_filename``), and ``default`` stands in for it when nothing
    ASCII is left of it.

    Starlette encodes header values as latin-1, so a name in a script
    outside latin-1 (Polish, Czech, Turkish, Cyrillic, CJK, …) raises there
    and the route reports a failure it does not have. The ``filename``
    parameter is therefore always ASCII, and the name as typed rides in
    ``filename*`` (RFC 6266 / RFC 5987) — added only when the two differ, so
    a header for a name that is ASCII is unchanged.
    """
    ascii_stem = _ascii_only(stem) or default
    header = f'attachment; filename="{ascii_stem}{suffix}"'
    if ascii_stem != stem:
        header += f"; filename*=UTF-8''{quote(stem + suffix, safe='')}"
    return header


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
