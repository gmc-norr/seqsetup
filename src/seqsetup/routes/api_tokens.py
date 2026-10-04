"""Admin routes for API token management.

Migrated to APIRouter + Pydantic. Tokens are stored as bcrypt-style
hashes via ApiToken.hash_token; plaintext is shown to the admin
exactly once at creation time (the new_token context var). No
plaintext is ever persisted or logged.

URL change in this commit: POST /admin/api-tokens/{token_id}/revoke
is now DELETE /admin/api-tokens/{token_id} (REST cleanup).

Admin-only via router-level require_admin_dep.
"""

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from pydantic import BaseModel, Field
from pydantic.functional_validators import BeforeValidator
from starlette.responses import HTMLResponse, Response

from ..context import AppContext
from ..forms.validators import clamp, strip_and_truncate
from ..models.api_token import ApiToken
from ..services.audit_log import audit
from ..templating import render
from .dependencies import get_ctx, require_admin_dep
from .utils import get_username
from ..utils.clock import as_utc, utcnow


_DEFAULT_EXPIRY_DAYS = 90
_MAX_EXPIRY_DAYS = 730


router = APIRouter(
    tags=["admin-api-tokens"],
    dependencies=[Depends(require_admin_dep)],
)


class CreateTokenForm(BaseModel):
    """Create-API-token form.

    name: CLAMP — strip + truncate to 256. min_length=1 rejects empty
        submissions (the HTML form has `required` which blocks the
        common case; scripted empties get a 422 minimal-error page).
    expiry_days: CLAMP to [0, 730]. 0 = never expires (discouraged).
        Default 90.
    """
    name: Annotated[str, BeforeValidator(strip_and_truncate(256)), Field(min_length=1)]
    expiry_days: Annotated[int, BeforeValidator(clamp(0, _MAX_EXPIRY_DAYS))] = _DEFAULT_EXPIRY_DAYS


@router.get("/admin/api-tokens", response_class=HTMLResponse)
def admin_api_tokens(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /admin/api-tokens — full page."""
    return render(
        request,
        "admin/api_tokens.html",
        {
            "tokens": ctx.api_token_repo.list_all(),
            "new_token": "",
            "message": "",
            "now": utcnow(),
        },
    )


@router.post("/admin/api-tokens/create", response_class=HTMLResponse)
def create_api_token(
    request: Request,
    form: Annotated[CreateTokenForm, Form()],
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /admin/api-tokens/create — create a token; HTMX fragment swap.

    The plaintext token is shown to the admin EXACTLY ONCE in the
    response — never stored, never logged, never returned again.
    """
    expires_at = (
        utcnow() + timedelta(days=form.expiry_days)
        if form.expiry_days > 0 else None
    )

    user = request.scope.get("auth")
    plaintext = ApiToken.generate_token()
    token_hash, token_prefix = ApiToken.hash_token(plaintext)
    token = ApiToken(
        name=form.name,
        token_hash=token_hash,
        token_prefix=token_prefix,
        created_by=user.username if user else "",
        expires_at=expires_at,
    )
    ctx.api_token_repo.save(token)

    audit(
        "api_token.created",
        actor=get_username(request),
        target=token.id,
        token_name=form.name,
        expires_at=as_utc(expires_at).isoformat() if expires_at else "never",
    )

    return render(
        request,
        "admin/api_tokens.html",
        {
            "tokens": ctx.api_token_repo.list_all(),
            "new_token": plaintext,
            "message": "",
            "now": utcnow(),
        },
        block_name="api_tokens_page",
    )


@router.delete("/admin/api-tokens/{token_id}", response_class=HTMLResponse)
def revoke_api_token(
    request: Request,
    token_id: str,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """DELETE /admin/api-tokens/{token_id} — revoke a token (HTMX fragment).

    URL change: was POST .../{token_id}/revoke. The plaintext token is
    never recoverable after revoke; this is the kill switch.
    """
    repo = ctx.api_token_repo
    token = repo.get_by_id(token_id)
    token_name = token.name if token else "Unknown"
    repo.delete(token_id)

    audit(
        "api_token.revoked",
        actor=get_username(request),
        target=token_id,
        token_name=token_name,
    )

    return render(
        request,
        "admin/api_tokens.html",
        {
            "tokens": repo.list_all(),
            "new_token": "",
            "message": f"Token '{token_name}' revoked",
            "now": utcnow(),
        },
        block_name="api_tokens_page",
    )
