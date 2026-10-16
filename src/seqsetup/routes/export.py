"""Export routes for SampleSheet, JSON, and validation reports.

Pure data endpoints (CSV / JSON / PDF), no HTML rendering. The run must be in
READY or ARCHIVED status — exports are written on the DRAFT→READY transition
(see routes/runs.py:update_status), each into its own record, and served
verbatim through ``read_export`` (services/run_exports.py), which checks the
bytes against the hash and length the run names. A file that cannot be served
as it was stored raises ExportDamaged: answered 500, never replaced with a
fresh export. Runs created before pre-generation carry no file at all; for
those, and only those, we generate fresh in-memory and serve without
persisting (which would mutate a READY/ARCHIVED run).
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
from ..services.run_exports import ExportDamaged, read_export
from ..services.samplesheet_v2_exporter import SampleSheetV2Exporter
from ..services.samplesheet_v1_exporter import SampleSheetV1Exporter
from ..services.validation import ValidationService
from ..services.validation_report import ValidationReportJSON, ValidationReportPDF
from .dependencies import get_ctx, get_exportable_run
from .utils import attachment_disposition, get_username, sanitize_filename


logger = logging.getLogger("seqsetup")


router = APIRouter(tags=["export"])


def _attachment_headers(name: str, default: str, suffix: str) -> dict:
    # ``no-store`` blocks corporate caching proxies from holding onto a
    # clinical Sample Sheet / validation report. The body identifies a
    # specific run and is not safe to re-serve from an intermediary.
    return {
        "Content-Disposition": attachment_disposition(
            sanitize_filename(name, default), default, suffix),
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
    # Before the try: a header that cannot be built is not a failed export.
    # The name says the version and the software that reads it (the user's
    # request, 2026-10-13): the v1 and v2 sheets never share one.
    headers = _attachment_headers(run.run_name, "SampleSheet", "_v2_BCLConvert.csv")
    try:
        content = read_export(ctx, run, "samplesheet_v2", actor=get_username(request))
        if content is None:
            content = SampleSheetV2Exporter.export(
                run,
                test_profile_repo=ctx.test_profile_repo,
                app_profile_repo=ctx.app_profile_repo,
                instrument_config=ctx.instrument_config,
            )
        audit(
            "export.downloaded",
            actor=get_username(request),
            target=run.id,
            format="samplesheet_v2",
        )
        return Response(content=content, media_type="text/csv", headers=headers)
    except (ExportDamaged, InstrumentRecordError, SyncedInstrumentsUnusable):
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
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    if not SampleSheetV1Exporter.supports(run.instrument_platform):
        return Response(
            content="SampleSheet v1 not supported for this instrument",
            status_code=400,
        )
    # Before the try: a header that cannot be built is not a failed export.
    headers = _attachment_headers(run.run_name, "SampleSheet", "_v1_bcl2fastq.csv")
    try:
        # Mark Ready stored why it made no v1 sheet (spec 2026-10-05 group
        # A3, §3); a run made before exports were stored gets one on the
        # spot only when the check, against the profiles stored now, finds
        # no reason.
        if run.samplesheet_v1_withheld:
            return Response(
                content=f"No v1 sheet for this run: {run.samplesheet_v1_withheld}.",
                status_code=409,
            )
        content = read_export(ctx, run, "samplesheet_v1", actor=get_username(request))
        if content is None:
            withheld = ValidationService.validate_run(
                run,
                test_profile_repo=ctx.test_profile_repo,
                app_profile_repo=ctx.app_profile_repo,
                instrument_config=ctx.instrument_config,
            ).v1_sheet_withheld
            if withheld:
                return Response(content=f"No v1 sheet for this run: {withheld}.", status_code=409)
            content = SampleSheetV1Exporter.export(run)
        audit(
            "export.downloaded",
            actor=get_username(request),
            target=run.id,
            format="samplesheet_v1",
        )
        return Response(content=content, media_type="text/csv", headers=headers)
    except (ExportDamaged, InstrumentRecordError, SyncedInstrumentsUnusable):
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
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    # Before the try: a header that cannot be built is not a failed export.
    headers = _attachment_headers(run.run_name, "run_metadata", ".json")
    try:
        content = read_export(ctx, run, "json", actor=get_username(request))
        if content is None:
            content = JSONExporter.export(run)
        audit(
            "export.downloaded",
            actor=get_username(request),
            target=run.id,
            format="json",
        )
        return Response(content=content, media_type="application/json", headers=headers)
    except (ExportDamaged, InstrumentRecordError, SyncedInstrumentsUnusable):
        # Shown with what to do, not as a failed export (spec 2026-10-04
        # group A2, §5).
        raise
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
    # Before the try: a header that cannot be built is not a failed export.
    headers = _attachment_headers(run.run_name, "validation_report", "_validation.json")
    try:
        content = read_export(ctx, run, "validation_json", actor=get_username(request))
        if content is None:
            content = ValidationReportJSON.export(run, _run_validation(run, ctx))
        audit(
            "export.downloaded",
            actor=get_username(request),
            target=run.id,
            format="validation_json",
        )
        return Response(content=content, media_type="application/json", headers=headers)
    except (ExportDamaged, InstrumentRecordError, SyncedInstrumentsUnusable):
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
    # Before the try: a header that cannot be built is not a failed export.
    headers = _attachment_headers(run.run_name, "validation_report", "_validation.pdf")
    try:
        # The PDF is written on the DRAFT→READY transition (see
        # routes/runs.py update_status). Never write back here — that would
        # mutate a READY/ARCHIVED run. Older runs created before
        # pre-generation carry no PDF; generate fresh in-memory and serve
        # without persisting.
        pdf_bytes = read_export(ctx, run, "validation_pdf", actor=get_username(request))
        if pdf_bytes is None:
            pdf_bytes = ValidationReportPDF.export(run, _run_validation(run, ctx))
        audit(
            "export.downloaded",
            actor=get_username(request),
            target=run.id,
            format="validation_pdf",
        )
        return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)
    except (ExportDamaged, InstrumentRecordError, SyncedInstrumentsUnusable):
        # Shown with what to do, not as a failed export (spec 2026-10-04
        # group A2, §5).
        raise
    except Exception:
        logger.exception("Failed to generate validation PDF")
        return Response(
            content="Failed to generate validation PDF. Please try again.",
            status_code=500,
        )
