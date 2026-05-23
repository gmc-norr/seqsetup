"""Index management routes for global index kits.

Migrated to Starlette ``Route(...)`` registration. Index-panel FT
components are still rendered via the transitional ``ft_response`` /
``ft_page_response`` helpers — converted to Jinja2 in a later phase.
"""

import logging
import re
from typing import Optional

from fasthtml.common import Div, H4, Li, P, Ul  # used by error fragments below
from starlette.datastructures import UploadFile
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from ..components.index_panel import (
    IndexKitDetailPage,
    IndexKitImportPage,
    IndexKitSummaryTable,
    IndexKitsPage,
    NoIndexKitsMessage,
)
from ..components.wizard import IndexKitPanel
from ..context import AppContext
from ..models.index import IndexMode
from ..services.audit_log import audit
from ..services.index_parser import IndexParser
from ..services.index_validator import IndexValidator
from ..services.index_kit_yaml_exporter import IndexKitYamlExporter
from ..templating import ft_page_response, ft_response
from .utils import get_username, require_admin


logger = logging.getLogger("seqsetup")


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


# Magic-byte prefixes that identify common binary formats. Index kit files
# must be plain UTF-8 text (YAML/CSV/TSV); a file starting with any of these
# was almost certainly mis-selected (PDF/Word/zip-of-spreadsheet/etc.).
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
    """Return a rejection reason if ``content`` looks binary, else None.

    Index kit files are YAML/CSV/TSV — all UTF-8 text. We reject by:
      1. Known binary magic-byte prefixes (catches PDF/zip/exe mis-uploads).
      2. NUL bytes in the first 8 KB (text rarely contains them, binaries often do).
      3. UTF-8 decode failure on a sniff prefix (binary garbage decodes as
         random bytes, valid UTF-8 doesn't).

    Returns an admin-friendly message on rejection, or None to allow.
    """
    if not content:
        return None  # empty content is handled by the upstream check

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


def register(app, ctx: AppContext) -> None:
    """Register index routes."""
    if not hasattr(app, "routes") or not isinstance(app.routes, list):
        raise TypeError(
            f"indexes.register requires a Starlette-style app with a mutable "
            f"routes list, got {type(app).__name__}"
        )

    def index_kits_page(request: Request) -> Response:
        """GET /indexes — index kits management page."""
        user = request.scope.get("auth")
        return ft_page_response(
            request,
            IndexKitsPage(ctx.index_kit_repo.list_all(), user),
            page_title="Index Kits",
            active_route="/indexes",
        )

    def index_kit_import_page(request: Request) -> Response:
        """GET /indexes/import — import form page."""
        return ft_page_response(
            request,
            IndexKitImportPage(),
            page_title="Import Index Kit",
            active_route="/indexes",
        )

    async def upload_index_kit(request: Request) -> Response:
        """POST /indexes/upload — parse a YAML/CSV/TSV index kit file."""
        if err := require_admin(request):
            return err

        form = await request.form()
        index_file = form.get("index_file")
        if not isinstance(index_file, UploadFile) or not index_file.filename:
            return ft_response(Div("Please select a file to import.", cls="error-message"))

        # Limit file size to prevent DoS (1 MB suffices for index kit files).
        MAX_INDEX_FILE_SIZE = 1 * 1024 * 1024
        file_content = await index_file.read()
        if len(file_content) > MAX_INDEX_FILE_SIZE:
            return ft_response(Div(
                f"File too large. Maximum size is {MAX_INDEX_FILE_SIZE // 1024} KB.",
                cls="error-message",
            ))

        # Reject obviously-binary uploads before parsing — extension is
        # admin-supplied and unreliable; content sniff is the actual defence.
        if reason := _reject_binary_upload(file_content):
            audit(
                "index_kit.upload",
                actor=get_username(request),
                target=index_file.filename or "",
                outcome="failure",
                reason="binary_content",
            )
            return ft_response(Div(reason, cls="error-message"))

        user = request.scope.get("auth")
        index_mode = form.get("index_mode", "unique_dual")
        kit_name = form.get("kit_name", "")
        kit_version = form.get("kit_version", "")
        kit_description = form.get("kit_description", "")
        default_index1_override = form.get("default_index1_override", "")
        default_index2_override = form.get("default_index2_override", "")
        adapter_read1 = form.get("adapter_read1", "")
        adapter_read2 = form.get("adapter_read2", "")
        default_read1_override = form.get("default_read1_override", "")
        default_read2_override = form.get("default_read2_override", "")
        comments = form.get("comments", "")

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
                error_list = Ul(*[Li(e) for e in validation.errors], cls="error-list")
                return ft_response(Div(
                    H4("Validation errors:"),
                    error_list,
                    cls="error-message",
                ))

            if ctx.index_kit_repo.exists(kit.name, kit.version):
                return ft_response(Div(
                    f"An index kit named '{kit.name}' version '{kit.version}' already exists.",
                    cls="error-message",
                ))

            ctx.index_kit_repo.save(kit)
        except Exception:
            logger.exception("Failed to parse index kit file")
            audit(
                "index_kit.upload",
                actor=get_username(request),
                target=index_file.filename or "",
                outcome="failure",
            )
            return ft_response(Div(
                "Failed to parse file. Please check the format and try again.",
                cls="error-message",
            ))

        audit(
            "index_kit.upload",
            actor=get_username(request),
            target=kit.kit_id,
            kit_name=kit.name,
            kit_version=kit.version,
            mode=kit.index_mode.value,
        )

        # Success — HTMX redirect to the kits page.
        return Response(
            content="",
            status_code=200,
            headers={"HX-Redirect": "/indexes"},
        )

    def remove_index_kit(request: Request) -> Response:
        """POST /indexes/kits/{name}/{version}/delete — delete a kit."""
        user = request.scope.get("auth")
        if not user:
            return Response("Forbidden: Authentication required", status_code=403)

        name = request.path_params["name"]
        version = request.path_params["version"]

        # Per-user permission: admin can delete any, others only their own.
        if not user.is_admin:
            kit = ctx.index_kit_repo.get_by_name_and_version(name, version)
            if not kit:
                return ft_response(Div(
                    Div(
                        f"Index kit '{name}' version '{version}' not found.",
                        cls="error-message",
                    ),
                ))
            if kit.created_by != user.username:
                return Response("Forbidden: You can only remove kits you created", status_code=403)

        deleted = ctx.index_kit_repo.delete(name, version)
        if deleted:
            audit(
                "index_kit.deleted",
                actor=get_username(request),
                target=f"{name}:{version}",
                kit_name=name,
                kit_version=version,
            )

        kits = ctx.index_kit_repo.list_all()
        if not deleted:
            return ft_response(Div(
                IndexKitSummaryTable(kits, user=user) if kits else None,
                Div(
                    f"Index kit '{name}' version '{version}' not found.",
                    cls="error-message",
                ),
            ))
        if kits:
            return ft_response(IndexKitSummaryTable(kits, user=user))
        return ft_response(NoIndexKitsMessage(can_upload=True))

    def index_kit_detail(request: Request) -> Response:
        """GET /indexes/detail/{name}/{version} — single-kit detail page."""
        name = request.path_params["name"]
        version = request.path_params["version"]
        user = request.scope.get("auth")

        kit = ctx.index_kit_repo.get_by_name_and_version(name, version)
        if not kit:
            return Response("Index kit not found", status_code=404)

        return ft_page_response(
            request,
            IndexKitDetailPage(kit, user),
            page_title=f"Index Kit: {name}",
            active_route="/indexes",
        )

    def get_kit_content(request: Request) -> Response:
        """GET /indexes/kit-content — wizard dropdown content."""
        selected_kit = request.query_params.get("selected_kit", "")
        if not selected_kit:
            return ft_response(P("Select an index kit", cls="no-kits-message"))

        kit = ctx.index_kit_repo.get_by_kit_id(selected_kit)
        if not kit:
            return ft_response(P(f"Index kit '{selected_kit}' not found", cls="error-message"))

        return ft_response(IndexKitPanel(kit))

    def download_index_kit(request: Request) -> Response:
        """GET /indexes/download/{name}/{version} — download kit as YAML."""
        name = request.path_params["name"]
        version = request.path_params["version"]
        kit = ctx.index_kit_repo.get_by_name_and_version(name, version)
        if not kit:
            return Response("Index kit not found", status_code=404)

        return Response(
            content=IndexKitYamlExporter.export(kit),
            media_type="application/x-yaml",
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{IndexKitYamlExporter.get_filename(kit)}"'
                ),
            },
        )

    app.routes.append(Route("/indexes", index_kits_page, methods=["GET"]))
    app.routes.append(Route("/indexes/import", index_kit_import_page, methods=["GET"]))
    app.routes.append(Route("/indexes/upload", upload_index_kit, methods=["POST"]))
    app.routes.append(Route("/indexes/kits/{name}/{version}/delete", remove_index_kit, methods=["POST"]))
    app.routes.append(Route("/indexes/detail/{name}/{version}", index_kit_detail, methods=["GET"]))
    app.routes.append(Route("/indexes/kit-content", get_kit_content, methods=["GET"]))
    app.routes.append(Route("/indexes/download/{name}/{version}", download_index_kit, methods=["GET"]))
