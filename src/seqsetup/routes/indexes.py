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
from ..input_rules.kits import FORM_BOXES, KitFileProblems, check_form_boxes
from ..services.index_parser import IndexParser, KitFileRefused
from ..services.index_validator import IndexValidator
from ..services.validation import clear_validation_cache
from ..templating import render
from .dependencies import get_ctx, require_admin_dep
from .utils import (
    UploadTooLargeError,
    attachment_disposition,
    get_username,
    read_upload_capped,
)


logger = logging.getLogger("seqsetup")


router = APIRouter(prefix="/indexes", tags=["indexes"])


# ---- Validation helpers ----

# What an index override box takes, as the form says: I and a number of
# cycles, I* or empty. Read whole: only its start was read, so N2I8 meant no
# override, I8garbage meant 8, and the N2 of I8N2 went nowhere -- and the box
# check saw the converted value (outside review of 51eb3c4, P2-3).
# ASCII only: \d took any digit (I followed by a full-width 8 gave 8), and
# .upper() made a dotless i an I (fresh review of the P2 fixes, P3-4).
_INDEX_OVERRIDE_RE = re.compile(r"I([0-9]{1,6})|I\*|", re.IGNORECASE | re.ASCII)
_INDEX_OVERRIDE_RULE = ("must be I and the number of index cycles, such as I8, or I* or "
                        "empty for each index's own length")


class IndexOverrideNotRead(ValueError):
    """An index override box that is not I and a number, I* or empty."""


def _parse_index_override(pattern: str) -> Optional[int]:
    """Parse an index override pattern into a cycle count.

    "I*" or empty → None (use actual sequence length)
    "I8" → 8 (use 8 index cycles)
    Anything else raises IndexOverrideNotRead.
    """
    m = _INDEX_OVERRIDE_RE.fullmatch(pattern.strip())
    if m is None:
        raise IndexOverrideNotRead(pattern)
    return int(m.group(1)) if m.group(1) else None


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


@router.get("/import", response_class=HTMLResponse, dependencies=[Depends(require_admin_dep)])
def index_kit_import_page(request: Request) -> Response:
    """GET /indexes/import — import form page (admin-only).

    The corresponding ``POST /indexes/upload`` is already admin-gated, but
    showing the form to non-admins would invite them to fill it in and
    bounce off the 403 at submit — inconsistent with the documented
    "index-kit upload requires admin" invariant.
    """
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
    # Stream-read in bounded chunks via the shared helper so a multi-GB POST
    # can't exhaust memory before the size check fires.
    try:
        file_content = await read_upload_capped(index_file, MAX_INDEX_FILE_SIZE)
    except UploadTooLargeError:
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

    # The boxes are checked before the file, by the same rules as its keys:
    # a value typed here becomes the kit's identity or its stored text, and
    # the model cut it instead of refusing it.
    index_cycles, box_problems = {}, []
    for box, typed in (("default_index1_override", default_index1_override),
                       ("default_index2_override", default_index2_override)):
        try:
            index_cycles[box] = _parse_index_override(typed)
        except IndexOverrideNotRead:
            index_cycles[box] = None
            box_problems.append(f"{FORM_BOXES[box]}: {_INDEX_OVERRIDE_RULE}")
    box_problems += check_form_boxes(
        kit_name=kit_name.strip(), kit_version=kit_version.strip(),
        kit_description=kit_description.strip(), comments=comments.strip(),
        adapter_read1=adapter_read1.strip(), adapter_read2=adapter_read2.strip(),
        default_read1_override=default_read1_override.strip().upper(),
        default_read2_override=default_read2_override.strip().upper(),
        default_index1_override=index_cycles["default_index1_override"],
        default_index2_override=index_cycles["default_index2_override"],
    )
    if box_problems:
        audit(
            "index_kit.upload",
            actor=get_username(request),
            target=index_file.filename or "",
            outcome="failure",
            reason="form_box_refused",
        )
        return _error_fragment_list(request, "This kit was not saved:", box_problems)

    user = request.scope.get("auth")
    try:
        mode = IndexMode(index_mode)
        idx1_cycles = index_cycles["default_index1_override"]
        idx2_cycles = index_cycles["default_index2_override"]

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
        # Index-kit content changes can flip per-sample index-collision and
        # color-balance outcomes; invalidate validation cache so any future
        # validate_run() recomputes against the new kit set.
        clear_validation_cache()
    except KitFileProblems as refused:
        # Every problem the rules found, each with its line, where one
        # "Failed to parse file. Please check the format and try again."
        # once stood for all of them.
        audit(
            "index_kit.upload",
            actor=get_username(request),
            target=index_file.filename or "",
            outcome="failure",
            reason=refused.reason,
        )
        return _error_fragment_list(request, "This kit was not saved:", refused.errors)
    except KitFileRefused as refused:
        # The file's own fault, said in full: which indexes do not pair up
        # or are named twice, and what to upload instead.
        audit(
            "index_kit.upload",
            actor=get_username(request),
            target=index_file.filename or "",
            outcome="failure",
            reason=refused.reason,
        )
        return _error_fragment(request, str(refused))
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


def _name_and_version(kit_path: str) -> tuple[str, str]:
    """A kit's name and version from the part of the path that carries both.

    The version is the LAST segment and may not hold a "/" (models/index.py),
    so everything before it is the name — which may hold any number of them.
    The shipped "IDT for Illumina DNA/RNA UD Indexes Set A" answered 404 on
    its detail page and download, and its Delete missed, while one name per
    segment was all these routes could read.
    """
    name, _, version = kit_path.rpartition("/")
    return name, version


@router.delete("/kits/{kit_path:path}", response_class=HTMLResponse)
def remove_index_kit(
    request: Request,
    kit_path: str,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """DELETE /indexes/kits/{name}/{version} — delete a kit.

    Per-user permission: admin can delete any kit, others can only
    delete kits they created. URL change in this commit (was POST .../delete).
    """
    name, version = _name_and_version(kit_path)
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
        # See save() above — removing a kit can also change validation outcomes.
        clear_validation_cache()
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


@router.get("/detail/{kit_path:path}", response_class=HTMLResponse)
def index_kit_detail(
    request: Request,
    kit_path: str,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /indexes/detail/{name}/{version} — single-kit detail page."""
    name, version = _name_and_version(kit_path)
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


@router.get("/download/{kit_path:path}")
def download_index_kit(
    kit_path: str,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /indexes/download/{name}/{version} — YAML export."""
    name, version = _name_and_version(kit_path)
    kit = ctx.index_kit_repo.get_by_name_and_version(name, version)
    if not kit:
        return Response("Index kit not found", status_code=404)
    # Before the export: a kit named outside latin-1 used to raise inside
    # Response(), uncaught, as a raw 500. get_filename lower-cases the name,
    # turns spaces into _ and / into -, and drops everything that is not
    # alphanumeric, _ or - (which leaves non-latin-1 letters in);
    # attachment_disposition is what makes the header encodable.
    headers = {
        "Content-Disposition": attachment_disposition(
            IndexKitYamlExporter.get_filename(kit), "index_kit.yaml"),
    }
    return Response(
        content=IndexKitYamlExporter.export(kit),
        media_type="application/x-yaml",
        headers=headers,
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
