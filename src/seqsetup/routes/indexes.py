"""Index management routes for global index kits."""

import logging
import re
from typing import Optional

from fasthtml.common import *
from starlette.datastructures import UploadFile
from starlette.responses import Response

logger = logging.getLogger("seqsetup")

from ..components.index_panel import (
    IndexKitDetailPage,
    IndexKitImportPage,
    IndexKitSection,
    IndexKitSummaryTable,
    IndexKitsPage,
    NoIndexKitsMessage,
)
from ..components.layout import AppShell
from ..components.wizard import IndexKitPanel
from ..context import AppContext
from ..models.index import IndexMode
from ..services.index_parser import IndexParser
from ..services.index_validator import IndexValidator
from ..services.index_kit_yaml_exporter import IndexKitYamlExporter
from .utils import require_admin


def _parse_index_override(pattern: str) -> Optional[int]:
    """Parse an index override pattern into a cycle count.

    "I*" or empty → None (use actual sequence length)
    "I8" or "I8N2" → 8 (use 8 index cycles)
    """
    val = pattern.strip().upper()
    if not val or val == "I*":
        return None
    # Extract the first I segment's cycle count
    m = re.match(r"I(\d+)", val)
    if m:
        return int(m.group(1))
    return None


def register(app, rt, ctx: AppContext):
    """Register index routes."""

    @rt("/indexes")
    def index_kits_page(req):
        """Display the global index kits management page."""
        user = req.scope.get("auth")

        return AppShell(
            user=user,
            active_route="/indexes",
            content=IndexKitsPage(ctx.index_kit_repo.list_all(), user),
            title="Index Kits",
        )

    @rt("/indexes/import")
    def index_kit_import_page(req):
        """Display the index kit import page."""
        user = req.scope.get("auth")

        return AppShell(
            user=user,
            active_route="/indexes",
            content=IndexKitImportPage(),
            title="Import Index Kit",
        )

    @app.post("/indexes/upload")
    async def upload_index_kit(
        req,
        index_file: UploadFile,
        index_mode: str = "unique_dual",
        kit_name: str = "",
        kit_version: str = "",
        kit_description: str = "",
        default_index1_override: str = "",
        default_index2_override: str = "",
        adapter_read1: str = "",
        adapter_read2: str = "",
        default_read1_override: str = "",
        default_read2_override: str = "",
        comments: str = "",
    ):
        """Upload and parse an index kit file."""
        if err := require_admin(req):
            return err
        user = req.scope.get("auth")

        if not index_file or not index_file.filename:
            return Div("Please select a file to import.", cls="error-message")

        # Limit file size to prevent DoS (1MB should be plenty for index kit files)
        MAX_INDEX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB
        file_content = await index_file.read()
        if len(file_content) > MAX_INDEX_FILE_SIZE:
            return Div(
                f"File too large. Maximum size is {MAX_INDEX_FILE_SIZE // 1024} KB.",
                cls="error-message",
            )

        try:
            # Convert string to IndexMode enum
            mode = IndexMode(index_mode)

            # Parse index override patterns into cycle counts.
            # "I*" or empty = use actual sequence length (None)
            # "I8" or "I8N2" = use 8 cycles
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

            # Set default index cycles if provided
            if idx1_cycles is not None:
                kit.default_index1_cycles = idx1_cycles
            if idx2_cycles is not None:
                kit.default_index2_cycles = idx2_cycles

            # Set adapter sequences if provided
            if adapter_read1.strip():
                kit.adapter_read1 = adapter_read1.strip()
            if adapter_read2.strip():
                kit.adapter_read2 = adapter_read2.strip()

            # Set read override patterns if provided (Y* is default, treat as None)
            r1 = default_read1_override.strip().upper()
            if r1 and r1 != "Y*":
                kit.default_read1_override = r1
            r2 = default_read2_override.strip().upper()
            if r2 and r2 != "Y*":
                kit.default_read2_override = r2

            # Set comments if provided
            if comments.strip():
                kit.comments = comments.strip()

            # Set ownership
            kit.created_by = user.username

            # Validate the parsed kit
            validation = IndexValidator.validate(kit)
            if not validation.is_valid:
                error_list = Ul(*[Li(e) for e in validation.errors], cls="error-list")
                return Div(
                    H4("Validation errors:"),
                    error_list,
                    cls="error-message",
                )

            # Check for duplicate name+version
            if ctx.index_kit_repo.exists(kit.name, kit.version):
                return Div(
                    f"An index kit named '{kit.name}' version '{kit.version}' already exists.",
                    cls="error-message",
                )

            ctx.index_kit_repo.save(kit)
        except Exception:
            logger.exception("Failed to parse index kit file")
            return Div("Failed to parse file. Please check the format and try again.", cls="error-message")

        # Success - redirect to index kits page
        return Response(
            content="",
            status_code=200,
            headers={"HX-Redirect": "/indexes"},
        )

    @app.post("/indexes/kits/{name}/{version}/delete")
    def remove_index_kit(req, name: str, version: str):
        """Remove an index kit. Admins can delete any; standard users only their own."""
        user = req.scope.get("auth")
        if not user:
            return Response("Forbidden: Authentication required", status_code=403)

        # Check per-user permission: admin can delete any, others only their own
        if not user.is_admin:
            kit = ctx.index_kit_repo.get_by_name_and_version(name, version)
            if not kit:
                return Div(
                    Div(
                        f"Index kit '{name}' version '{version}' not found.",
                        cls="error-message",
                    ),
                )
            if kit.created_by != user.username:
                return Response("Forbidden: You can only remove kits you created", status_code=403)

        deleted = ctx.index_kit_repo.delete(name, version)

        kits = ctx.index_kit_repo.list_all()
        if not deleted:
            return Div(
                IndexKitSummaryTable(kits, user=user) if kits else None,
                Div(
                    f"Index kit '{name}' version '{version}' not found.",
                    cls="error-message",
                ),
            )
        if kits:
            return IndexKitSummaryTable(kits, user=user)
        return NoIndexKitsMessage(can_upload=True)

    @app.get("/indexes/detail/{name}/{version}")
    def index_kit_detail(req, name: str, version: str):
        """Detail page for a single index kit."""
        user = req.scope.get("auth")

        kit = ctx.index_kit_repo.get_by_name_and_version(name, version)
        if not kit:
            return Response("Index kit not found", status_code=404)

        return AppShell(
            user=user,
            active_route="/indexes",
            content=IndexKitDetailPage(kit, user),
            title=f"Index Kit: {name}",
        )

    @rt("/indexes/kit-content")
    def get_kit_content(req, selected_kit: str = ""):
        """Get the content of a specific index kit for the wizard dropdown."""
        if not selected_kit:
            return P("Select an index kit", cls="no-kits-message")

        # selected_kit is the composite kit_id (name:version)
        kit = ctx.index_kit_repo.get_by_kit_id(selected_kit)
        if not kit:
            return P(f"Index kit '{selected_kit}' not found", cls="error-message")

        return IndexKitPanel(kit)

    @app.get("/indexes/download/{name}/{version}")
    def download_index_kit(req, name: str, version: str):
        """Download an index kit as a YAML file."""
        kit = ctx.index_kit_repo.get_by_name_and_version(name, version)
        if not kit:
            return Response("Index kit not found", status_code=404)

        # Export to YAML
        yaml_content = IndexKitYamlExporter.export(kit)
        filename = IndexKitYamlExporter.get_filename(kit)

        return Response(
            content=yaml_content,
            media_type="application/x-yaml",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )
