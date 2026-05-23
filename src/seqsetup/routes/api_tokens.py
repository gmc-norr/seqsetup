"""Admin routes for API token management.

Migrated to Starlette ``Route(...)`` registration. The list/form FT
component (``ApiTokensPage``) is still rendered via the transitional
``ft_response`` / ``ft_page_response`` helpers; a later phase converts
those components to Jinja2.
"""

from datetime import datetime, timedelta

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

from ..components.api_tokens import ApiTokensPage
from ..context import AppContext
from ..models.api_token import ApiToken
from ..services.audit_log import audit
from ..templating import ft_page_response, ft_response
from .utils import get_username, require_admin, sanitize_string


# Default token lifetime in days. An admin can request a different value
# via the create form (0 = never expires, capped at 730d / ~2y).
_DEFAULT_EXPIRY_DAYS = 90
_MAX_EXPIRY_DAYS = 730


def register(app, ctx: AppContext) -> None:
    """Register API token management routes."""
    if not hasattr(app, "routes") or not isinstance(app.routes, list):
        raise TypeError(
            f"api_tokens.register requires a Starlette-style app with a mutable "
            f"routes list, got {type(app).__name__}"
        )

    def admin_api_tokens(request: Request) -> Response:
        """GET /admin/api-tokens — full page."""
        if err := require_admin(request):
            return err
        return ft_page_response(
            request,
            ApiTokensPage(ctx.api_token_repo.list_all()),
            page_title="API Tokens",
            active_route="/admin/api-tokens",
        )

    async def create_api_token(request: Request) -> Response:
        """POST /admin/api-tokens/create — create a token; returns HTMX fragment.

        ``expiry_days`` accepts an integer string. Empty falls back to the
        default lifetime; 0 means "never expires" (recorded but discouraged);
        values >MAX are clamped down.
        """
        if err := require_admin(request):
            return err

        form = await request.form()
        name = sanitize_string(form.get("name", ""), 256)
        expiry_days = form.get("expiry_days", "")

        if not name:
            return ft_response(
                ApiTokensPage(
                    ctx.api_token_repo.list_all(),
                    message="Token name is required",
                )
            )

        try:
            requested = int(expiry_days) if expiry_days else _DEFAULT_EXPIRY_DAYS
        except ValueError:
            requested = _DEFAULT_EXPIRY_DAYS
        days = max(0, min(_MAX_EXPIRY_DAYS, requested))
        expires_at = (datetime.now() + timedelta(days=days)) if days > 0 else None

        user = request.scope.get("auth")
        plaintext = ApiToken.generate_token()
        token_hash, token_prefix = ApiToken.hash_token(plaintext)
        token = ApiToken(
            name=name,
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
            token_name=name,
            expires_at=expires_at.isoformat() if expires_at else "never",
        )

        return ft_response(
            ApiTokensPage(ctx.api_token_repo.list_all(), new_token=plaintext)
        )

    def revoke_api_token(request: Request) -> Response:
        """POST /admin/api-tokens/{token_id}/revoke — delete a token."""
        if err := require_admin(request):
            return err

        token_id = request.path_params["token_id"]
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

        return ft_response(
            ApiTokensPage(repo.list_all(), message=f"Token '{token_name}' revoked")
        )

    app.routes.append(Route("/admin/api-tokens", admin_api_tokens, methods=["GET"]))
    app.routes.append(Route("/admin/api-tokens/create", create_api_token, methods=["POST"]))
    app.routes.append(Route("/admin/api-tokens/{token_id}/revoke", revoke_api_token, methods=["POST"]))
