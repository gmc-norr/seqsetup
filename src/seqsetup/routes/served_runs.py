"""API Exports: what the API serves, shown in the web app.

GET /served-runs           — the runs GET /api/runs lists: Ready (default) or
                             Archived, never a Draft, in the API's order.
GET /served-runs/{run_id}  — each stored file a per-run API address hands
                             out, byte for byte (the check report without its
                             per-lane tables, see below), with a download of
                             it, or the
                             answer the API gives when it has none; above each
                             sheet, the target instrument and software Mark
                             Ready saved with it.

Read-only: it shows what Mark Ready stored and never makes a file anew (the
Export downloads do that for runs made before files were stored; the API
does not, so a download is offered only for a stored file). Every file is
read through ``read_export`` (services/run_exports.py), so what this page
shows is what the API serves, byte for byte -- except the check report's
per-lane tables, which are nearly all of its size (up to about 15 MB): the
page leaves them out, says so, and its download gives the whole file (the
user's decision, 2026-10-17). A file that cannot be served as
it was stored gets its own row saying so, with the answer the API gives for
it -- the other files are still shown. The not-stored answers repeat
api/app.py's; tests/integration/test_served_runs.py checks each against the
API itself. Anyone signed in may look: they can already download these
files.
"""

import json
from dataclasses import dataclass, field
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from starlette.responses import HTMLResponse, Response

from ..context import AppContext
from ..models.sequencing_run import RunStatus
from ..services.audit_log import audit
from ..services.run_exports import ExportDamaged, read_export
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
_LEFT_OUT_NOTE = ("The per-lane tables (the index distances and the color balance) are left out "
                  "here. The whole file is {size} bytes: download it to see them.")
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
    damaged: str = ""                # why a stored file cannot be served
    left_out: str = ""               # what of the file the page does not show, and why


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
    if f.missing or f.damaged:
        return f
    target = (run.sheet_targets or {}).get(f.resource.replace("-", "_"))
    if not target:
        f.target_missing = True
        return f
    f.target = _target_rows(target)
    f.target_note = _RUNINFO_NOTE if target["needs_runinfo_reverse_mark"] else ""
    f.target_rule_note = _DRAGEN_RULE_NOTE if target["software"] == "BCL Convert" else ""
    return f


def _without_per_lane_tables(text: str) -> tuple[str, bool]:
    """The check report without its per-lane tables, and whether any were
    left out. A report that is not a JSON object with per-lane tables is
    shown as stored."""
    try:
        report = json.loads(text)
    except (ValueError, RecursionError):
        # RecursionError: nested too deep for the reader -- only a report
        # edited by hand, which is still shown rather than a 500.
        return text, False
    if not isinstance(report, dict) or not report.get("per_lane"):
        return text, False
    del report["per_lane"]
    # As ValidationReportJSON writes it, so what is shown reads as the file.
    return json.dumps(report, indent=2), True


# resource -> (label, export kind, the API's 404 detail when nothing is stored)
_FILES = (
    ("samplesheet-v2", "Sample Sheet v2", "samplesheet_v2", "SampleSheet v2 not yet generated"),
    ("samplesheet-v1", "Sample Sheet v1", "samplesheet_v1",
     "SampleSheet v1 not available for this run"),
    ("json", "JSON", "json", "JSON metadata not yet generated"),
    ("validation-report", "Validation report (JSON)", "validation_json",
     "Validation report not yet generated"),
    ("validation-pdf", "Validation report (PDF)", "validation_pdf",
     "Validation PDF not yet generated"),
)


def _served_files(ctx, run, actor: str = "") -> list[ServedFile]:
    files = []
    for resource, label, kind, not_stored in _FILES:
        if kind == "samplesheet_v1" and run.samplesheet_v1_withheld:
            # Why Mark Ready made none (spec 2026-10-05 group A3, §3).
            files.append(ServedFile(resource, label,
                                    missing=f"No v1 sheet for this run: {run.samplesheet_v1_withheld}."))
            continue
        try:
            content = read_export(ctx, run, kind, actor=actor)
        except ExportDamaged as exc:
            # This one file's own row, with the answer the API gives for it;
            # the rest of the page is still shown.
            files.append(ServedFile(resource, label, damaged=str(exc)))
            continue
        if content is None:
            files.append(ServedFile(resource, label, missing=not_stored))
        elif kind == "validation_pdf":
            files.append(ServedFile(resource, label, pdf_size=len(content),
                                    pdf_size_text=f"{len(content):,}"))
        elif kind == "validation_json":
            shown, cut = _without_per_lane_tables(content)
            note = _LEFT_OUT_NOTE.format(size=f"{len(content.encode('utf-8')):,}") if cut else ""
            files.append(ServedFile(resource, label, text=shown, left_out=note))
        else:
            files.append(ServedFile(resource, label, text=content))
    files = [_with_target(f, run) if f.resource in ("samplesheet-v2", "samplesheet-v1")
             else f for f in files]
    for f in files:
        if not f.missing and not f.damaged:
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
        "files": _served_files(ctx, run, get_username(request)) if served else [],
        "not_served": "" if served else _NOT_SERVED,
        "back_status": "archived" if run.status == RunStatus.ARCHIVED else "ready",
    })
