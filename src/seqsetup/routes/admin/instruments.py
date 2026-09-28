"""Admin instruments page — synced-instrument visibility toggles.

GET /admin/instruments               — full page
POST /admin/instruments/synced/toggle      — single-instrument toggle
POST /admin/instruments/synced/enable-all  — bulk enable
POST /admin/instruments/synced/disable-all — bulk disable

All POSTs return the {% block synced_instruments_section %} fragment
(HTMX outerHTML swap into #synced-instruments-section).

Admin-only: router-level dependency `require_admin_dep`. The dep must
RAISE (router-level dep return values are ignored).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from pydantic import BaseModel
from pydantic.functional_validators import BeforeValidator
from starlette.responses import HTMLResponse, Response

from ...context import AppContext
from ...data.instruments import clear_synced_instruments_cache
from ...forms.validators import strip_and_truncate
from ...services.audit_log import audit
from ...services.validation import clear_validation_cache
from ...templating import render
from ..dependencies import get_ctx, require_admin_dep
from ..utils import get_username


router = APIRouter(
    tags=["admin-instruments"],
    dependencies=[Depends(require_admin_dep)],
)


class ToggleInstrumentForm(BaseModel):
    """Toggle a single synced instrument.

    instrument_id: CLAMP — strip + truncate to 256. Defensive; the repo
        lookup keys on the exact ID, so an oversized value with extra
        bytes wouldn't match anyway.
    enabled: REJECT non-bool. Pydantic handles bool coercion ("true",
        "false", "1", "0", "on", "off" all accepted).
    """
    instrument_id: Annotated[str, BeforeValidator(strip_and_truncate(256))]
    enabled: bool


@router.get("/admin/instruments", response_class=HTMLResponse)
def admin_instruments(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /admin/instruments — full page."""
    synced = (
        ctx.instrument_definition_repo.list_all()
        if ctx.instrument_definition_repo else []
    )
    return render(
        request,
        "admin/instruments.html",
        _page_ctx(synced),
    )


@router.post("/admin/instruments/synced/toggle", response_class=HTMLResponse)
def toggle_synced_instrument(
    request: Request,
    form: Annotated[ToggleInstrumentForm, Form()],
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /admin/instruments/synced/toggle — HTMX fragment swap."""
    if ctx.instrument_definition_repo is None:
        return Response("Instrument repo not configured", status_code=404)
    ctx.instrument_definition_repo.set_enabled(form.instrument_id, form.enabled)
    # New Run, the instrument route and Mark Ready read the flag through the
    # synced-instrument cache; drop it so they see this change now (F27).
    clear_synced_instruments_cache()
    # Instrument enable/disable changes which color-chemistry rules apply at
    # validation time; invalidate the cache so stale results don't survive.
    clear_validation_cache()
    audit(
        "instrument.toggled",
        actor=get_username(request),
        target=form.instrument_id,
        enabled=form.enabled,
    )
    synced = ctx.instrument_definition_repo.list_all()
    return render(
        request,
        "admin/instruments.html",
        _page_ctx(synced),
        block_name="synced_instruments_section",
    )


@router.post("/admin/instruments/synced/enable-all", response_class=HTMLResponse)
def enable_all_synced_instruments(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /admin/instruments/synced/enable-all — bulk enable all."""
    return _bulk_set(request, ctx, enabled=True, message="All instruments enabled")


@router.post("/admin/instruments/synced/disable-all", response_class=HTMLResponse)
def disable_all_synced_instruments(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /admin/instruments/synced/disable-all — bulk disable all."""
    return _bulk_set(request, ctx, enabled=False, message="All instruments disabled")


def _bulk_set(request: Request, ctx: AppContext, *, enabled: bool, message: str) -> Response:
    if ctx.instrument_definition_repo is None:
        return Response("Instrument repo not configured", status_code=404)
    repo = ctx.instrument_definition_repo
    for inst in repo.list_all():
        repo.set_enabled(inst.id, enabled)
    clear_synced_instruments_cache()  # see toggle_synced_instrument
    # See toggle_synced_instrument — invalidate stale validation results.
    clear_validation_cache()
    audit(
        "instrument.bulk_toggled",
        actor=get_username(request),
        target="all",
        enabled=enabled,
    )
    return render(
        request,
        "admin/instruments.html",
        _page_ctx(repo.list_all(), message=message),
        block_name="synced_instruments_section",
    )


def _page_ctx(synced: list, message: str = "") -> dict:
    """Build the template context. Splits synced instruments by chemistry
    type so the template can iterate two pre-grouped lists rather than
    filtering in Jinja.
    """
    two_color = [i for i in synced if i.chemistry_type == "2-color"]
    four_color = [i for i in synced if i.chemistry_type == "4-color"]
    return {
        "synced_instruments": synced,
        "two_color": two_color,
        "four_color": four_color,
        "message": message,
    }
