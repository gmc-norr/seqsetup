"""Admin sample-API (LIMS) configuration page.

GET  /admin/sample-api          — full page
POST /admin/settings/sample-api — save config; HTMX fragment swap
                                   into #sample-api-config-form

Save flow:
  1. Pydantic clamps every text field; api_key empty → keep existing.
  2. If enabled + base_url present, ping check_connection().
  3. On connection failure, force enabled=False, save, audit
     outcome="failure" + reason="connection_failed", and re-render
     the form with an error banner. Behaviour preserved verbatim from
     the original handler (clinical: auto-disabling on bad config
     prevents broken pipeline writes).
  4. Otherwise save + audit "lims_config.updated" with no outcome.

Admin-only via router-level require_admin_dep.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from pydantic import BaseModel
from pydantic.functional_validators import BeforeValidator
from starlette.responses import HTMLResponse, Response

from ...context import AppContext
from ...forms.validators import strip_and_truncate
from ...models.sample_api_config import SampleApiConfig
from ...services.audit_log import audit
from ...templating import render
from ..dependencies import get_ctx, require_admin_dep
from ..utils import get_username


router = APIRouter(
    tags=["admin-sample-api"],
    dependencies=[Depends(require_admin_dep)],
)


class SampleApiForm(BaseModel):
    """LIMS sample-API configuration form.

    All text fields CLAMP (strip + truncate). The api_key behaves like
    a "leave blank to keep existing" field — empty string is preserved
    and the handler swaps in the existing stored key.

    enabled is a checkbox; absent = unchecked = False. Pydantic lax
    coercion handles the "on" string browsers send when checked.
    """
    base_url: Annotated[str, BeforeValidator(strip_and_truncate(1024))] = ""
    api_key: Annotated[str, BeforeValidator(strip_and_truncate(512))] = ""
    enabled: bool = False
    field_worksheet_id: Annotated[str, BeforeValidator(strip_and_truncate(256))] = ""
    field_investigator: Annotated[str, BeforeValidator(strip_and_truncate(256))] = ""
    field_updated_at: Annotated[str, BeforeValidator(strip_and_truncate(256))] = ""
    field_samples: Annotated[str, BeforeValidator(strip_and_truncate(256))] = ""
    field_test_version: Annotated[str, BeforeValidator(strip_and_truncate(256))] = ""

    def field_mappings(self) -> dict[str, str]:
        """Build the field_mappings dict, dropping empty values."""
        mapping = {
            "worksheet_id": self.field_worksheet_id,
            "investigator": self.field_investigator,
            "updated_at": self.field_updated_at,
            "samples": self.field_samples,
            "test_version": self.field_test_version,
        }
        return {k: v for k, v in mapping.items() if v}


@router.get("/admin/sample-api", response_class=HTMLResponse)
def admin_sample_api(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /admin/sample-api — full page (404 if LIMS repo not configured)."""
    if ctx.sample_api_config_repo is None:
        return Response("LIMS sample-API repo not configured", status_code=404)
    config = ctx.sample_api_config_repo.get()
    return render(
        request,
        "admin/sample_api.html",
        {"config": config, "message": "", "error": ""},
    )


@router.post("/admin/settings/sample-api", response_class=HTMLResponse)
def update_sample_api_config(
    request: Request,
    form: Annotated[SampleApiForm, Form()],
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /admin/settings/sample-api — save + ping; HTMX fragment swap."""
    if ctx.sample_api_config_repo is None:
        return Response("LIMS sample-API repo not configured", status_code=404)

    existing = ctx.sample_api_config_repo.get()
    config = SampleApiConfig(
        base_url=form.base_url,
        api_key=form.api_key if form.api_key else existing.api_key,
        enabled=form.enabled,
        field_mappings=form.field_mappings(),
    )

    # Clinical: if the user enables an unreachable backend, force-disable
    # before saving so a broken LIMS doesn't enter the pipeline.
    if config.enabled and config.base_url:
        from ...services.sample_api import check_connection
        success, msg = check_connection(config)
        if not success:
            config.enabled = False
            ctx.sample_api_config_repo.save(config)
            audit(
                "lims_config.updated",
                actor=get_username(request),
                target="sample_api_config",
                outcome="failure",
                base_url=config.base_url,
                enabled=False,
                reason="connection_failed",
            )
            return render(
                request,
                "admin/sample_api.html",
                {
                    "config": config,
                    "message": "",
                    "error": f"Connection failed: {msg}. Integration has been disabled.",
                },
                block_name="sample_api_config_form",
            )

    ctx.sample_api_config_repo.save(config)
    audit(
        "lims_config.updated",
        actor=get_username(request),
        target="sample_api_config",
        base_url=config.base_url,
        enabled=config.enabled,
    )
    return render(
        request,
        "admin/sample_api.html",
        {
            "config": config,
            "message": "LIMS integration configuration saved",
            "error": "",
        },
        block_name="sample_api_config_form",
    )
