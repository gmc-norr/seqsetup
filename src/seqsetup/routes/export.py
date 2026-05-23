"""Export routes for SampleSheet and JSON.

Pure data endpoints (CSV / JSON / PDF), no HTML rendering. Migrated to
Starlette directly — no FT components were used here.
"""

import logging

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from ..context import AppContext
from ..services.audit_log import audit
from ..services.json_exporter import JSONExporter
from ..services.samplesheet_v2_exporter import SampleSheetV2Exporter
from ..services.samplesheet_v1_exporter import SampleSheetV1Exporter
from ..services.validation import ValidationService
from ..services.validation_report import ValidationReportJSON, ValidationReportPDF
from .utils import check_run_exportable, get_username, sanitize_filename

logger = logging.getLogger("seqsetup")


def register(app, ctx: AppContext) -> None:
    """Register export routes on the parent Starlette app."""
    if not hasattr(app, "routes") or not isinstance(app.routes, list):
        raise TypeError(
            f"export.register requires a Starlette-style app with a mutable "
            f"routes list, got {type(app).__name__}"
        )

    def _run_validation(run):
        return ValidationService.validate_run(
            run,
            test_profile_repo=ctx.test_profile_repo,
            app_profile_repo=ctx.app_profile_repo,
            instrument_config=ctx.instrument_config,
        )

    def _get_run_or_404(run_id: str):
        run = ctx.run_repo.get_by_id(run_id)
        if not run:
            return None, Response(content="Run not found", status_code=404)
        if err := check_run_exportable(run):
            return None, err
        return run, None

    def _attachment_headers(filename: str) -> dict:
        return {"Content-Disposition": f'attachment; filename="{filename}"'}

    def export_samplesheet_v2(request: Request) -> Response:
        run_id = request.path_params["run_id"]
        run, err = _get_run_or_404(run_id)
        if err:
            return err
        try:
            if run.generated_samplesheet_v2:
                content = run.generated_samplesheet_v2
            else:
                content = SampleSheetV2Exporter.export(
                    run,
                    test_profile_repo=ctx.test_profile_repo,
                    app_profile_repo=ctx.app_profile_repo,
                )
            filename = f"{sanitize_filename(run.run_name, 'SampleSheet_v2')}.csv"
            audit(
                "export.downloaded",
                actor=get_username(request),
                target=run_id,
                format="samplesheet_v2",
            )
            return Response(
                content=content,
                media_type="text/csv",
                headers=_attachment_headers(filename),
            )
        except Exception:
            logger.exception("Failed to generate SampleSheet v2")
            return Response(
                content="Failed to generate SampleSheet v2. Please try again.",
                status_code=500,
            )

    def export_samplesheet_v1(request: Request) -> Response:
        run_id = request.path_params["run_id"]
        run, err = _get_run_or_404(run_id)
        if err:
            return err
        if not SampleSheetV1Exporter.supports(run.instrument_platform):
            return Response(
                content="SampleSheet v1 not supported for this instrument",
                status_code=400,
            )
        try:
            content = run.generated_samplesheet_v1 or SampleSheetV1Exporter.export(run)
            filename = f"{sanitize_filename(run.run_name, 'SampleSheet')}.csv"
            audit(
                "export.downloaded",
                actor=get_username(request),
                target=run_id,
                format="samplesheet_v1",
            )
            return Response(
                content=content,
                media_type="text/csv",
                headers=_attachment_headers(filename),
            )
        except Exception:
            logger.exception("Failed to generate SampleSheet v1")
            return Response(
                content="Failed to generate SampleSheet v1. Please try again.",
                status_code=500,
            )

    def export_json(request: Request) -> Response:
        run_id = request.path_params["run_id"]
        run, err = _get_run_or_404(run_id)
        if err:
            return err
        try:
            content = run.generated_json or JSONExporter.export(run)
            filename = f"{sanitize_filename(run.run_name, 'run_metadata')}.json"
            audit(
                "export.downloaded",
                actor=get_username(request),
                target=run_id,
                format="json",
            )
            return Response(
                content=content,
                media_type="application/json",
                headers=_attachment_headers(filename),
            )
        except Exception:
            logger.exception("Failed to generate JSON export")
            return Response(
                content="Failed to generate JSON export. Please try again.",
                status_code=500,
            )

    def export_validation_json(request: Request) -> Response:
        run_id = request.path_params["run_id"]
        run, err = _get_run_or_404(run_id)
        if err:
            return err
        try:
            if run.generated_validation_json:
                content = run.generated_validation_json
            else:
                content = ValidationReportJSON.export(run, _run_validation(run))
            filename = f"{sanitize_filename(run.run_name, 'validation_report')}_validation.json"
            audit(
                "export.downloaded",
                actor=get_username(request),
                target=run_id,
                format="validation_json",
            )
            return Response(
                content=content,
                media_type="application/json",
                headers=_attachment_headers(filename),
            )
        except Exception:
            logger.exception("Failed to generate validation report")
            return Response(
                content="Failed to generate validation report. Please try again.",
                status_code=500,
            )

    def export_validation_pdf(request: Request) -> Response:
        run_id = request.path_params["run_id"]
        run, err = _get_run_or_404(run_id)
        if err:
            return err
        try:
            # PDF is pre-generated on DRAFT→READY transition (see routes/runs.py
            # update_run_status). Never write back here — that would mutate a
            # READY/ARCHIVED run. Older runs created before pre-generation lack
            # the cached PDF; generate fresh in-memory and serve without
            # persisting.
            pdf_bytes = run.generated_validation_pdf or ValidationReportPDF.export(
                run, _run_validation(run)
            )
            filename = f"{sanitize_filename(run.run_name, 'validation_report')}_validation.pdf"
            audit(
                "export.downloaded",
                actor=get_username(request),
                target=run_id,
                format="validation_pdf",
            )
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers=_attachment_headers(filename),
            )
        except Exception:
            logger.exception("Failed to generate validation PDF")
            return Response(
                content="Failed to generate validation PDF. Please try again.",
                status_code=500,
            )

    app.routes.append(Route("/runs/{run_id}/export/samplesheet-v2", export_samplesheet_v2, methods=["GET"]))
    app.routes.append(Route("/runs/{run_id}/export/samplesheet-v1", export_samplesheet_v1, methods=["GET"]))
    app.routes.append(Route("/runs/{run_id}/export/json", export_json, methods=["GET"]))
    app.routes.append(Route("/runs/{run_id}/export/validation-report", export_validation_json, methods=["GET"]))
    app.routes.append(Route("/runs/{run_id}/export/validation-pdf", export_validation_pdf, methods=["GET"]))
