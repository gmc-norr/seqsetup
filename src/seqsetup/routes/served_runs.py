"""What the API serves, shown in the web app.

GET /served-runs           — the runs GET /api/runs lists: Ready (default) or
                             Archived, never a Draft, in the API's order.
GET /served-runs/{run_id}  — each stored file a per-run API address hands
                             out, byte for byte, or the answer the API gives
                             when it has none.

Read-only: it shows what Mark Ready stored and never makes a file anew (the
Export downloads do that for runs made before files were stored; the API
does not). The not-stored answers repeat api/app.py's;
tests/integration/test_served_runs.py checks each against the API itself.
Anyone signed in may look: they can already download these files.
"""

from dataclasses import dataclass
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.responses import HTMLResponse, Response

from ..context import AppContext
from ..models.sequencing_run import RunStatus
from ..services.audit_log import audit
from ..templating import render
from .dependencies import get_ctx
from .utils import get_username


router = APIRouter(tags=["served-runs"])

_STATUSES = ("ready", "archived")
_NOT_SERVED = "Run not available via API. Only ready or archived runs can be accessed."
_BAD_STATUS = "Invalid status. Only 'ready' and 'archived' are allowed via API."


@dataclass
class ServedFile:
    """One per-run API address and what it answers."""
    resource: str
    label: str
    text: Optional[str] = None       # a text file's stored content
    pdf_size: Optional[int] = None   # the stored PDF's size in bytes
    pdf_size_text: str = ""          # the same, written for reading ("1,033")
    missing: str = ""                # the API's 404 detail when nothing is stored


def _served_files(run) -> list[ServedFile]:
    if run.generated_samplesheet_v1:
        v1 = ServedFile("samplesheet-v1", "Sample Sheet v1", text=run.generated_samplesheet_v1)
    elif run.samplesheet_v1_withheld:
        v1 = ServedFile("samplesheet-v1", "Sample Sheet v1",
                        missing=f"No v1 sheet for this run: {run.samplesheet_v1_withheld}.")
    else:
        v1 = ServedFile("samplesheet-v1", "Sample Sheet v1", missing="SampleSheet v1 not available for this run")
    pdf = run.generated_validation_pdf
    return [
        ServedFile("samplesheet-v2", "Sample Sheet v2", text=run.generated_samplesheet_v2,
                   missing="" if run.generated_samplesheet_v2 else "SampleSheet v2 not yet generated"),
        v1,
        ServedFile("json", "JSON", text=run.generated_json,
                   missing="" if run.generated_json else "JSON metadata not yet generated"),
        ServedFile("validation-report", "Validation report (JSON)", text=run.generated_validation_json,
                   missing="" if run.generated_validation_json else "Validation report not yet generated"),
        ServedFile("validation-pdf", "Validation report (PDF)", pdf_size=len(pdf) if pdf else None,
                   pdf_size_text=f"{len(pdf):,}" if pdf else "",
                   missing="" if pdf else "Validation PDF not yet generated"),
    ]


@router.get("/served-runs", response_class=HTMLResponse)
def served_runs(request: Request, status: str = "ready", ctx: AppContext = Depends(get_ctx)) -> Response:
    if status not in _STATUSES:
        raise HTTPException(status_code=400, detail=_BAD_STATUS)
    runs = ctx.run_repo.list_by_status(status)
    # The API's order: newest change first (api/app.py list_runs).
    runs.sort(key=lambda r: r.updated_at or r.created_at, reverse=True)
    return render(request, "served_runs/list.html", {"runs": runs, "status": status})


@router.get("/served-runs/{run_id}", response_class=HTMLResponse)
def served_run(request: Request, run_id: str, ctx: AppContext = Depends(get_ctx)) -> Response:
    run = ctx.run_repo.get_by_id(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    served = run.status in (RunStatus.READY, RunStatus.ARCHIVED)
    if served:
        audit("export.viewed", actor=get_username(request), target=run.id)
    return render(request, "served_runs/run.html", {
        "run": run,
        "files": _served_files(run) if served else [],
        "not_served": "" if served else _NOT_SERVED,
        "back_status": "archived" if run.status == RunStatus.ARCHIVED else "ready",
    })
