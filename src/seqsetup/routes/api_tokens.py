"""Admin routes for API token management."""

from fasthtml.common import *
from starlette.responses import Response

from .utils import require_admin
from ..components.layout import AppShell
from ..components.api_tokens import ApiTokensPage
from ..models.api_token import ApiToken


def register(app, rt, get_api_token_repo):
    """Register API token management routes."""

    @app.get("/admin/api-tokens")
    def admin_api_tokens(req):
        """API token management page."""
        error = require_admin(req)
        if error:
            return error

        user = req.scope.get("auth")
        tokens = get_api_token_repo().list_all()

        return AppShell(
            user=user,
            active_route="/admin/api-tokens",
            content=ApiTokensPage(tokens),
            title="API Tokens",
        )

    @app.post("/admin/api-tokens/create")
    def create_api_token(req, name: str = ""):
        """Create a new API token."""
        error = require_admin(req)
        if error:
            return error

        user = req.scope.get("auth")
        name = name.strip()

        if not name:
            tokens = get_api_token_repo().list_all()
            return ApiTokensPage(tokens, message="Token name is required")

        # Generate token
        plaintext = ApiToken.generate_token()
        token_hash, token_prefix = ApiToken.hash_token(plaintext)
        token = ApiToken(
            name=name,
            token_hash=token_hash,
            token_prefix=token_prefix,
            created_by=user.username,
        )
        get_api_token_repo().save(token)

        tokens = get_api_token_repo().list_all()
        return ApiTokensPage(tokens, new_token=plaintext)

    @app.post("/admin/api-tokens/{token_id}/revoke")
    def revoke_api_token(req, token_id: str):
        """Revoke (delete) an API token."""
        error = require_admin(req)
        if error:
            return error

        repo = get_api_token_repo()
        token = repo.get_by_id(token_id)
        token_name = token.name if token else "Unknown"
        repo.delete(token_id)

        tokens = repo.list_all()
        return ApiTokensPage(tokens, message=f"Token '{token_name}' revoked")
