"""API Exports: what the API serves, shown in the web app.

GET /served-runs           — the runs GET /api/runs lists: Ready (default) or
                             Archived, never a Draft, in the API's order.
GET /served-runs/{run_id}  — each stored file a per-run API address hands
                             out, byte for byte, with a download of it, or the
                             answer the API gives when it has none; above each
                             sheet, the target instrument and software Mark
                             Ready saved with it.

Read-only: it shows what Mark Ready stored and never makes a file anew (the
Export downloads do that for runs made before files were stored; the API
does not, so a download is offered only for a stored file). The not-stored
answers repeat api/app.py's; tests/integration/test_served_runs.py checks
each against the API itself. Anyone signed in may look: they can already
download these files.
"""

from dataclasses import dataclass, field
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
# The collision check follows DRAGEN's built-in BCL conversion (the user's
# decision, 2026-10-13; services/index_collision_validator.py).
_DRAGEN_RULE_NOTE = ("Index collisions were checked as DRAGEN's built-in BCL conversion checks them: "
                     "standalone bcl-convert 3.10.5 or later is stricter and may stop.")
_RUNINFO_NOTE = ('This sheet relies on BCL Convert acting on the IsReverseComplement="Y" mark '
                 "that RunInfo.xml puts on the i5 read.")


@dataclass
class ServedFile:
    """One per-run API address and what it answers."""
    resource: str
    label: str
    text: Optional[str] = None       # a text file's stored content
    pdf_size: Optional[int] = None   # the stored PDF's size in bytes
    pdf_size_text: str = ""          # the same, written for reading ("1,033")
    missing: str = ""                # the API's 404 detail when nothing is stored
    download: str = ""               # the stored file's download address
    target: list[tuple[str, str]] = field(default_factory=list)  # a sheet's target, as (label, value) rows
    target_note: str = ""            # what the sheet relies on BCL Convert to do
    target_rule_note: str = ""       # the converter whose collision rule was checked
    target_missing: bool = False     # a stored sheet whose target was never saved


def _target_rows(target: dict) -> list[tuple[str, str]]:
    software = target["software"]
    if target["software_version"]:
        software += f" {target['software_version']}"
    elif software == "BCL Convert":
        software += " (the sheet states no version)"
    column = {"forward": "Forward: each sample's i5 as stored",
              "reverse-complement": "Reverse complement of each sample's stored i5",
              "none": "None: no sample has an i5"}[target["index2_column"]]
    return [("Instrument", target["instrument"]), ("Software", software),
            ("i5 workflow", target["i5_workflow"]), ("i5 column", column)]


def _with_target(f: ServedFile, run) -> ServedFile:
    """A stored sheet with the target Mark Ready saved for it."""
    if f.missing:
        return f
    target = (run.sheet_targets or {}).get(f.resource.replace("-", "_"))
    if not target:
        f.target_missing = True
        return f
    f.target = _target_rows(target)
    f.target_note = _RUNINFO_NOTE if target["needs_runinfo_reverse_mark"] else ""
    f.target_rule_note = _DRAGEN_RULE_NOTE if target["software"] == "BCL Convert" else ""
    return f


def _served_files(run) -> list[ServedFile]:
    if run.generated_samplesheet_v1:
        v1 = ServedFile("samplesheet-v1", "Sample Sheet v1", text=run.generated_samplesheet_v1)
    elif run.samplesheet_v1_withheld:
        v1 = ServedFile("samplesheet-v1", "Sample Sheet v1",
                        missing=f"No v1 sheet for this run: {run.samplesheet_v1_withheld}.")
    else:
        v1 = ServedFile("samplesheet-v1", "Sample Sheet v1", missing="SampleSheet v1 not available for this run")
    pdf = run.generated_validation_pdf
    files = [
        _with_target(ServedFile("samplesheet-v2", "Sample Sheet v2", text=run.generated_samplesheet_v2,
                                missing="" if run.generated_samplesheet_v2 else "SampleSheet v2 not yet generated"),
                     run),
        _with_target(v1, run),
        ServedFile("json", "JSON", text=run.generated_json,
                   missing="" if run.generated_json else "JSON metadata not yet generated"),
        ServedFile("validation-report", "Validation report (JSON)", text=run.generated_validation_json,
                   missing="" if run.generated_validation_json else "Validation report not yet generated"),
        ServedFile("validation-pdf", "Validation report (PDF)", pdf_size=len(pdf) if pdf else None,
                   pdf_size_text=f"{len(pdf):,}" if pdf else "",
                   missing="" if pdf else "Validation PDF not yet generated"),
    ]
    for f in files:
        if not f.missing:
            f.download = f"/runs/{run.id}/export/{f.resource}"
    return files


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
