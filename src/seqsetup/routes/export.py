"""Export routes for SampleSheet, JSON, and validation reports.

Pure data endpoints (CSV / JSON / PDF), no HTML rendering. The run
must be in READY or ARCHIVED status — exports are pre-generated on
DRAFT→READY transition (see routes/runs.py:update_run_status) and
served verbatim from the run's stored fields. Older runs created
before pre-generation lack the cached export bytes; in that case
we generate fresh in-memory and serve without persisting (which
would mutate a READY/ARCHIVED run).
"""

import logging

from fastapi import APIRouter, Depends, Request
from starlette.responses import Response

from ..context import AppContext
from ..data.instruments import SyncedInstrumentsUnusable
from ..models.instrument_definition import InstrumentRecordError
from ..models.sequencing_run import SequencingRun
from ..services.audit_log import audit
from ..services.json_exporter import JSONExporter
from ..services.samplesheet_v2_exporter import SampleSheetV2Exporter
from ..services.samplesheet_v1_exporter import SampleSheetV1Exporter
from ..services.validation import ValidationService
from ..services.validation_report import ValidationReportJSON, ValidationReportPDF
from .dependencies import get_ctx, get_exportable_run
from .utils import get_username, sanitize_filename


logger = logging.getLogger("seqsetup")


router = APIRouter(tags=["export"])


def _attachment_headers(filename: str) -> dict:
    # ``no-store`` blocks corporate caching proxies from holding onto a
    # clinical Sample Sheet / validation report. The body identifies a
    # specific run and is not safe to re-serve from an intermediary.
    return {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
    }


def _run_validation(run, ctx: AppContext):
    return ValidationService.validate_run(
        run,
        test_profile_repo=ctx.test_profile_repo,
        app_profile_repo=ctx.app_profile_repo,
        instrument_config=ctx.instrument_config,
    )


@router.get("/runs/{run_id}/export/samplesheet-v2")
def export_samplesheet_v2(
    request: Request,
    run: SequencingRun = Depends(get_exportable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
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
            target=run.id,
            format="samplesheet_v2",
        )
        return Response(
            content=content,
            media_type="text/csv",
            headers=_attachment_headers(filename),
        )
    except (InstrumentRecordError, SyncedInstrumentsUnusable):
        # Shown with what to do, not as a failed export (spec 2026-10-04
        # group A2, §5).
        raise
    except Exception:
        logger.exception("Failed to generate SampleSheet v2")
        return Response(
            content="Failed to generate SampleSheet v2. Please try again.",
            status_code=500,
        )


@router.get("/runs/{run_id}/export/samplesheet-v1")
def export_samplesheet_v1(
    request: Request,
    run: SequencingRun = Depends(get_exportable_run),
) -> Response:
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
            target=run.id,
            format="samplesheet_v1",
        )
        return Response(
            content=content,
            media_type="text/csv",
            headers=_attachment_headers(filename),
        )
    except (InstrumentRecordError, SyncedInstrumentsUnusable):
        # Shown with what to do, not as a failed export (spec 2026-10-04
        # group A2, §5).
        raise
    except Exception:
        logger.exception("Failed to generate SampleSheet v1")
        return Response(
            content="Failed to generate SampleSheet v1. Please try again.",
            status_code=500,
        )


@router.get("/runs/{run_id}/export/json")
def export_json(
    request: Request,
    run: SequencingRun = Depends(get_exportable_run),
) -> Response:
    try:
        content = run.generated_json or JSONExporter.export(run)
        filename = f"{sanitize_filename(run.run_name, 'run_metadata')}.json"
        audit(
            "export.downloaded",
            actor=get_username(request),
            target=run.id,
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


@router.get("/runs/{run_id}/export/validation-report")
def export_validation_json(
    request: Request,
    run: SequencingRun = Depends(get_exportable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    try:
        if run.generated_validation_json:
            content = run.generated_validation_json
        else:
            content = ValidationReportJSON.export(run, _run_validation(run, ctx))
        filename = f"{sanitize_filename(run.run_name, 'validation_report')}_validation.json"
        audit(
            "export.downloaded",
            actor=get_username(request),
            target=run.id,
            format="validation_json",
        )
        return Response(
            content=content,
            media_type="application/json",
            headers=_attachment_headers(filename),
        )
    except (InstrumentRecordError, SyncedInstrumentsUnusable):
        # Shown with what to do, not as a failed export (spec 2026-10-04
        # group A2, §5).
        raise
    except Exception:
        logger.exception("Failed to generate validation report")
        return Response(
            content="Failed to generate validation report. Please try again.",
            status_code=500,
        )


@router.get("/runs/{run_id}/export/validation-pdf")
def export_validation_pdf(
    request: Request,
    run: SequencingRun = Depends(get_exportable_run),
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    try:
        # PDF is pre-generated on DRAFT→READY transition (see routes/runs.py
        # update_run_status). Never write back here — that would mutate a
        # READY/ARCHIVED run. Older runs created before pre-generation lack
        # the cached PDF; generate fresh in-memory and serve without
        # persisting.
        pdf_bytes = run.generated_validation_pdf or ValidationReportPDF.export(
            run, _run_validation(run, ctx)
        )
        filename = f"{sanitize_filename(run.run_name, 'validation_report')}_validation.pdf"
        audit(
            "export.downloaded",
            actor=get_username(request),
            target=run.id,
            format="validation_pdf",
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers=_attachment_headers(filename),
        )
    except (InstrumentRecordError, SyncedInstrumentsUnusable):
        # Shown with what to do, not as a failed export (spec 2026-10-04
        # group A2, §5).
        raise
    except Exception:
        logger.exception("Failed to generate validation PDF")
        return Response(
            content="Failed to generate validation PDF. Please try again.",
            status_code=500,
        )
