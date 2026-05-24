"""Index kit management routes.

Migrated to APIRouter. Three pages (list, import, detail) plus an
upload action, a permission-gated delete, a wizard-side kit-content
fragment, and a YAML download.

Upload validation invariants (clinical-safety — never relaxed):
  - 1 MB size cap (DoS guard)
  - Binary magic-byte sniff rejects mis-uploaded PDFs/zips/exes/etc.
  - NUL-byte sniff in first 8 KB
  - UTF-8 decode check on sniff prefix
  - Audit on every upload outcome (success AND failure)

URL change in this commit:
  POST /indexes/kits/{name}/{version}/delete →
  DELETE /indexes/kits/{name}/{version}
"""

import logging
import re
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from starlette.responses import HTMLResponse, Response

from ..context import AppContext
from ..models.index import IndexMode
from ..services.audit_log import audit
from ..services.index_kit_yaml_exporter import IndexKitYamlExporter
from ..services.index_parser import IndexParser
from ..services.index_validator import IndexValidator
from ..templating import render
from .dependencies import get_ctx, require_admin_dep
from .utils import get_username


logger = logging.getLogger("seqsetup")


router = APIRouter(prefix="/indexes", tags=["indexes"])


# ---- Validation helpers (PRESERVE VERBATIM from the previous handler) ----

def _parse_index_override(pattern: str) -> Optional[int]:
    """Parse an index override pattern into a cycle count.

    "I*" or empty → None (use actual sequence length)
    "I8" or "I8N2" → 8 (use 8 index cycles)
    """
    val = pattern.strip().upper()
    if not val or val == "I*":
        return None
    m = re.match(r"I(\d+)", val)
    if m:
        return int(m.group(1))
    return None


_BINARY_MAGIC_BYTES: tuple[bytes, ...] = (
    b"\x89PNG\r\n\x1a\n",   # PNG
    b"\xff\xd8\xff",         # JPEG
    b"%PDF-",                # PDF
    b"PK\x03\x04",           # ZIP (xlsx, docx, jar, ...)
    b"PK\x05\x06",           # ZIP empty archive
    b"PK\x07\x08",           # ZIP spanned archive
    b"\x1f\x8b",             # gzip
    b"BZh",                  # bzip2
    b"\xfd7zXZ\x00",         # xz
    b"7z\xbc\xaf\x27\x1c",   # 7z
    b"\x7fELF",              # ELF binary
    b"MZ",                   # PE/DOS exe
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",  # OLE (legacy Office)
    b"{\\rtf",               # RTF
    b"\x00\x00\x01\x00",     # Windows ICO
)


def _reject_binary_upload(content: bytes) -> Optional[str]:
    """Return a rejection reason if content looks binary, else None."""
    if not content:
        return None
    for prefix in _BINARY_MAGIC_BYTES:
        if content.startswith(prefix):
            return (
                f"File looks like a binary format (magic bytes {prefix[:8]!r}). "
                f"Index kits must be plain text (YAML, CSV, or TSV)."
            )
    sniff = content[:8192]
    if b"\x00" in sniff:
        return (
            "File contains NUL bytes in the first 8 KB. "
            "Index kits must be plain text (YAML, CSV, or TSV)."
        )
    try:
        sniff.decode("utf-8")
    except UnicodeDecodeError:
        return (
            "File is not valid UTF-8 text. "
            "Index kits must be plain text (YAML, CSV, or TSV)."
        )
    return None


# ---- Routes ----

@router.get("", response_class=HTMLResponse)
def index_kits_page(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /indexes — index kits list page."""
    user = request.scope.get("auth")
    return render(
        request,
        "indexes/list.html",
        {"kits": ctx.index_kit_repo.list_all(), "user": user},
    )


@router.get("/import", response_class=HTMLResponse)
def index_kit_import_page(request: Request) -> Response:
    """GET /indexes/import — import form page."""
    return render(request, "indexes/import.html", {"error_message": ""})


@router.post("/upload", response_class=HTMLResponse, dependencies=[Depends(require_admin_dep)])
async def upload_index_kit(
    request: Request,
    index_file: Annotated[UploadFile, File()],
    index_mode: Annotated[str, Form()] = "unique_dual",
    kit_name: Annotated[str, Form()] = "",
    kit_version: Annotated[str, Form()] = "",
    kit_description: Annotated[str, Form()] = "",
    default_index1_override: Annotated[str, Form()] = "",
    default_index2_override: Annotated[str, Form()] = "",
    adapter_read1: Annotated[str, Form()] = "",
    adapter_read2: Annotated[str, Form()] = "",
    default_read1_override: Annotated[str, Form()] = "",
    default_read2_override: Annotated[str, Form()] = "",
    comments: Annotated[str, Form()] = "",
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /indexes/upload — parse & save an uploaded index-kit file.

    Multipart form; admin-only. HX-Redirect to /indexes on success;
    returns an HTML error fragment on validation failure.
    """
    if not index_file or not index_file.filename:
        return _error_fragment(request, "Please select a file to import.")

    MAX_INDEX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB DoS guard
    file_content = await index_file.read()
    if len(file_content) > MAX_INDEX_FILE_SIZE:
        return _error_fragment(
            request,
            f"File too large. Maximum size is {MAX_INDEX_FILE_SIZE // 1024} KB.",
        )

    if reason := _reject_binary_upload(file_content):
        audit(
            "index_kit.upload",
            actor=get_username(request),
            target=index_file.filename or "",
            outcome="failure",
            reason="binary_content",
        )
        return _error_fragment(request, reason)

    user = request.scope.get("auth")
    try:
        mode = IndexMode(index_mode)
        idx1_cycles = _parse_index_override(default_index1_override)
        idx2_cycles = _parse_index_override(default_index2_override)

        content = file_content.decode("utf-8")
        kit = IndexParser.parse_from_content(
            content,
            index_file.filename,
            index_mode=mode,
            kit_name=kit_name.strip() if kit_name else None,
            kit_version=kit_version.strip() if kit_version else None,
            kit_description=kit_description.strip() if kit_description else None,
        )

        if idx1_cycles is not None:
            kit.default_index1_cycles = idx1_cycles
        if idx2_cycles is not None:
            kit.default_index2_cycles = idx2_cycles
        if adapter_read1.strip():
            kit.adapter_read1 = adapter_read1.strip()
        if adapter_read2.strip():
            kit.adapter_read2 = adapter_read2.strip()
        r1 = default_read1_override.strip().upper()
        if r1 and r1 != "Y*":
            kit.default_read1_override = r1
        r2 = default_read2_override.strip().upper()
        if r2 and r2 != "Y*":
            kit.default_read2_override = r2
        if comments.strip():
            kit.comments = comments.strip()

        kit.created_by = user.username if user else ""

        validation = IndexValidator.validate(kit)
        if not validation.is_valid:
            return _error_fragment_list(request, "Validation errors:", validation.errors)

        if ctx.index_kit_repo.exists(kit.name, kit.version):
            return _error_fragment(
                request,
                f"An index kit named '{kit.name}' version '{kit.version}' already exists.",
            )

        ctx.index_kit_repo.save(kit)
    except Exception:
        logger.exception("Failed to parse index kit file")
        audit(
            "index_kit.upload",
            actor=get_username(request),
            target=index_file.filename or "",
            outcome="failure",
        )
        return _error_fragment(
            request,
            "Failed to parse file. Please check the format and try again.",
        )

    audit(
        "index_kit.upload",
        actor=get_username(request),
        target=kit.kit_id,
        kit_name=kit.name,
        kit_version=kit.version,
        mode=kit.index_mode.value,
    )
    # HTMX redirect to refresh the kits list page.
    return Response(content="", status_code=200, headers={"HX-Redirect": "/indexes"})


@router.delete("/kits/{name}/{version}", response_class=HTMLResponse)
def remove_index_kit(
    request: Request,
    name: str,
    version: str,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """DELETE /indexes/kits/{name}/{version} — delete a kit.

    Per-user permission: admin can delete any kit, others can only
    delete kits they created. URL change in this commit (was POST .../delete).
    """
    user = request.scope.get("auth")
    if not user:
        raise HTTPException(status_code=403, detail="Authentication required")

    if not user.is_admin:
        kit = ctx.index_kit_repo.get_by_name_and_version(name, version)
        if not kit:
            raise HTTPException(
                status_code=404,
                detail=f"Index kit '{name}' version '{version}' not found.",
            )
        if kit.created_by != user.username:
            raise HTTPException(status_code=403, detail="You can only remove kits you created")

    deleted = ctx.index_kit_repo.delete(name, version)
    if deleted:
        audit(
            "index_kit.deleted",
            actor=get_username(request),
            target=f"{name}:{version}",
            kit_name=name,
            kit_version=version,
        )

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail=f"Index kit '{name}' version '{version}' not found.",
        )
    kits = ctx.index_kit_repo.list_all()
    return render(
        request,
        "indexes/list.html",
        {"kits": kits, "user": user, "error_message": ""},
        block_name="kit_list_section",
    )


@router.get("/detail/{name}/{version}", response_class=HTMLResponse)
def index_kit_detail(
    request: Request,
    name: str,
    version: str,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /indexes/detail/{name}/{version} — single-kit detail page."""
    user = request.scope.get("auth")
    kit = ctx.index_kit_repo.get_by_name_and_version(name, version)
    if not kit:
        return Response("Index kit not found", status_code=404)
    return render(
        request,
        "indexes/detail.html",
        {"kit": kit, "user": user, "name": name, "version": version},
    )


@router.get("/kit-content", response_class=HTMLResponse)
def get_kit_content(
    request: Request,
    selected_kit: str = "",
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /indexes/kit-content — wizard dropdown content fragment."""
    if not selected_kit:
        return render(request, "wizard/_index_kit_panel_empty.html", {})
    kit = ctx.index_kit_repo.get_by_kit_id(selected_kit)
    if not kit:
        return render(
            request,
            "wizard/_index_kit_panel_empty.html",
            {"error_message": f"Index kit '{selected_kit}' not found"},
        )
    return render(request, "wizard/_index_kit_panel.html", {"kit": kit})


@router.get("/download/{name}/{version}")
def download_index_kit(
    name: str,
    version: str,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /indexes/download/{name}/{version} — YAML export."""
    kit = ctx.index_kit_repo.get_by_name_and_version(name, version)
    if not kit:
        return Response("Index kit not found", status_code=404)
    return Response(
        content=IndexKitYamlExporter.export(kit),
        media_type="application/x-yaml",
        headers={
            "Content-Disposition": f'attachment; filename="{IndexKitYamlExporter.get_filename(kit)}"',
        },
    )


# ---- Error-fragment helpers ----

def _error_fragment(request: Request, message: str) -> Response:
    """Render a simple error fragment for HTMX swap."""
    return render(
        request,
        "indexes/_error_fragment.html",
        {"messages": [message]},
    )


def _error_fragment_list(request: Request, title: str, errors: list[str]) -> Response:
    """Render an error fragment with a title + list of messages."""
    return render(
        request,
        "indexes/_error_fragment.html",
        {"title": title, "messages": errors},
    )
