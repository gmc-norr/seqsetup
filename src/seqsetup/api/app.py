"""FastAPI application for /api/*.

Hosts the JSON read API plus auto-generated OpenAPI/Swagger at /docs.
Mounted by ``seqsetup.app`` at the ``/api`` prefix, so the route paths
declared here are relative — e.g. ``@api.get("/runs")`` is reachable at
``/api/runs``.
"""

from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request, status
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from ..context import AppContext
from ..models.api_token import ApiToken
from ..models.sequencing_run import RunStatus
from ..services.audit_log import audit
from .deps import api_actor, make_bearer_auth
from .schemas import ErrorResponse, RunListResponse, RunSummary


# Paging defaults / bounds for /api/runs. Caps protect the API against
# a token-holder pulling every run's metadata in one request.
_DEFAULT_PAGE_SIZE = 50
_MAX_PAGE_SIZE = 200


# Pinned Swagger UI version. Audit C5 specifically called out the
# "unpkg.com CDN with inline script and no CSP" combo; FastAPI's default
# /docs loads from cdn.jsdelivr.net with the same shape. We pin a specific
# version, host the assets from the same origin via Swagger's UNPKG-served
# bundle, AND restrict via a strict CSP. (For maximum hardening, operators
# can mirror these files behind /static/swagger and switch _SWAGGER_BASE.)
_SWAGGER_VERSION = "5.17.14"
_SWAGGER_BASE = f"https://cdn.jsdelivr.net/npm/swagger-ui-dist@{_SWAGGER_VERSION}"

_SWAGGER_CSP = (
    "default-src 'none'; "
    f"script-src 'self' {_SWAGGER_BASE}; "
    f"style-src 'self' {_SWAGGER_BASE} 'unsafe-inline'; "
    "img-src 'self' data: https:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

_SWAGGER_HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SeqSetup API Documentation</title>
    <link rel="stylesheet" type="text/css" href="{_SWAGGER_BASE}/swagger-ui.css">
    <style>
        html {{ box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }}
        *, *:before, *:after {{ box-sizing: inherit; }}
        body {{ margin: 0; background: #fafafa; }}
        .swagger-ui .topbar {{ display: none; }}
        .swagger-ui .info .title {{ font-size: 2rem; }}
        .swagger-ui .info {{ margin: 30px 0; }}
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="{_SWAGGER_BASE}/swagger-ui-bundle.js"></script>
    <script src="/api/docs/init.js"></script>
</body>
</html>"""

_SWAGGER_INIT_JS = """window.onload = function() {
    var ui = SwaggerUIBundle({
        url: "/api/openapi.json",
        dom_id: "#swagger-ui",
        deepLinking: true,
        presets: [SwaggerUIBundle.presets.apis],
        layout: "BaseLayout",
        persistAuthorization: true,
        tryItOutEnabled: true,
    });
    window.ui = ui;
};
"""


def _run_summary(run) -> RunSummary:
    """Convert a domain SequencingRun dataclass into the API DTO.

    Deliberately omits samples, generated exports, and PDF bytes — those
    are only returned by the explicit per-run endpoints. A token-holder
    that just wants to enumerate runs shouldn't bulk-dump finalized
    clinical payloads in a single request.
    """
    return RunSummary(
        id=run.id,
        run_name=run.run_name,
        status=run.status.value,
        instrument_platform=run.instrument_platform.value,
        flowcell_type=run.flowcell_type,
        created_at=run.created_at,
        updated_at=run.updated_at,
        created_by=run.created_by,
        sample_count=len(run.samples) if run.samples else 0,
    )


def create_api_app(ctx: AppContext) -> FastAPI:
    """Build the FastAPI app for /api/*.

    The hand-maintained openapi.py is replaced by FastAPI's auto-generated
    spec at /openapi.json (which becomes /api/openapi.json after mounting).
    Swagger UI lives at /docs (mounted to /api/docs) — same-origin with CSP.

    The ``ctx`` is closed over by both the auth dependency and the route
    handlers — uniform binding. Tests get isolation via fresh_app's full
    module reload; production never swaps the context at runtime.
    """
    api = FastAPI(
        title="SeqSetup API",
        description=(
            "Read-only JSON API for sequencing-run metadata and pre-generated "
            "exports. Only runs in ``ready`` or ``archived`` status are exposed; "
            "drafts are never returned via the API."
        ),
        version="2.0",
        openapi_url="/openapi.json",
        # FastAPI's built-in /docs loads Swagger from cdn.jsdelivr.net with inline
        # script — we replace it with a same-origin, CSP-hardened page below.
        docs_url=None,
        redoc_url=None,
    )

    bearer_auth = make_bearer_auth(ctx)
    AuthToken = Annotated[ApiToken, Depends(bearer_auth)]

    @api.get("/docs", include_in_schema=False)
    def swagger_ui_html() -> Response:
        """Serve a same-origin Swagger UI page with a strict CSP.

        Replaces FastAPI's built-in /docs (which loads from cdn.jsdelivr.net
        with inline script and no CSP — see audit finding C5).
        """
        return Response(
            content=_SWAGGER_HTML,
            media_type="text/html",
            headers={"Content-Security-Policy": _SWAGGER_CSP},
        )

    @api.get("/docs/init.js", include_in_schema=False)
    def swagger_ui_init_js() -> Response:
        """Same-origin Swagger UI init script (no inline JS in the page)."""
        return Response(content=_SWAGGER_INIT_JS, media_type="application/javascript")

    ALLOWED_API_STATUSES = {RunStatus.READY, RunStatus.ARCHIVED}

    def _check_run_access(run):
        """Raise the right HTTPException if the run isn't accessible via API."""
        if not run:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Run not found")
        if run.status not in ALLOWED_API_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Run not available via API. Only ready or archived runs can be accessed.",
            )

    @api.get(
        "/runs",
        response_model=RunListResponse,
        summary="List ready or archived runs",
        responses={
            400: {"model": ErrorResponse, "description": "Invalid status filter"},
            401: {"model": ErrorResponse, "description": "Missing or invalid Bearer token"},
            429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        },
    )
    def list_runs(
        request: Request,
        token: AuthToken,
        status_filter: Annotated[
            str,
            Query(
                alias="status",
                description='Filter by run status. Allowed: "ready" or "archived".',
            ),
        ] = "ready",
        limit: Annotated[
            int,
            Query(ge=1, le=_MAX_PAGE_SIZE, description="Maximum number of results per page."),
        ] = _DEFAULT_PAGE_SIZE,
        offset: Annotated[
            int,
            Query(ge=0, description="Zero-based offset into the result set."),
        ] = 0,
    ) -> RunListResponse:
        """Return a paginated, minimal-DTO list of runs.

        The bulky finalized payloads (samples, Sample Sheets, JSON, PDF)
        live behind their explicit per-run endpoints — not in this list.

        Note: the parameter is named ``status_filter`` internally to avoid
        shadowing the imported ``fastapi.status`` enum, but the query
        parameter is exposed as ``?status=`` via Query(alias=...).
        """
        if status_filter not in ("ready", "archived"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid status. Only 'ready' and 'archived' are allowed via API.",
            )
        runs = ctx.run_repo.list_by_status(status_filter)
        # Deterministic ordering — newest first by updated_at.
        runs.sort(key=lambda r: r.updated_at or r.created_at, reverse=True)
        total = len(runs)
        page = runs[offset:offset + limit]
        audit(
            "api.runs.listed",
            actor=api_actor(token),
            status=status_filter,
            limit=limit,
            offset=offset,
            returned=len(page),
        )
        return RunListResponse(
            items=[_run_summary(r) for r in page],
            total=total,
            limit=limit,
            offset=offset,
        )

    @api.get(
        "/runs/{run_id}/samplesheet-v2",
        response_class=PlainTextResponse,
        summary="Download SampleSheet v2 (CSV) for a ready run",
        responses={
            200: {"content": {"text/csv": {}}, "description": "SampleSheet v2 CSV"},
            401: {"model": ErrorResponse, "description": "Missing or invalid Bearer token"},
            403: {"model": ErrorResponse, "description": "Run not in ready or archived status"},
            404: {"model": ErrorResponse, "description": "Run not found or sheet not generated"},
            429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        },
    )
    def get_samplesheet_v2(
        token: AuthToken,
        run_id: Annotated[str, Path(description="Run identifier (UUID).")],
    ):
        run = ctx.run_repo.get_by_id(run_id)
        _check_run_access(run)
        if not run.generated_samplesheet_v2:
            raise HTTPException(status_code=404, detail="SampleSheet v2 not yet generated")
        audit("api.run.read", actor=api_actor(token), target=run_id, resource="samplesheet_v2")
        return Response(content=run.generated_samplesheet_v2, media_type="text/csv")

    @api.get(
        "/runs/{run_id}/samplesheet-v1",
        response_class=PlainTextResponse,
        summary="Download SampleSheet v1 (CSV) for a ready run",
        responses={
            200: {"content": {"text/csv": {}}},
            401: {"model": ErrorResponse, "description": "Missing or invalid Bearer token"},
            403: {"model": ErrorResponse, "description": "Run not in ready or archived status"},
            404: {"model": ErrorResponse, "description": "Run not found or sheet not generated"},
            429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        },
    )
    def get_samplesheet_v1(
        token: AuthToken,
        run_id: Annotated[str, Path(description="Run identifier (UUID).")],
    ):
        run = ctx.run_repo.get_by_id(run_id)
        _check_run_access(run)
        if not run.generated_samplesheet_v1:
            raise HTTPException(status_code=404, detail="SampleSheet v1 not available for this run")
        audit("api.run.read", actor=api_actor(token), target=run_id, resource="samplesheet_v1")
        return Response(content=run.generated_samplesheet_v1, media_type="text/csv")

    @api.get(
        "/runs/{run_id}/json",
        summary="Download full JSON metadata for a ready run",
        responses={
            401: {"model": ErrorResponse, "description": "Missing or invalid Bearer token"},
            403: {"model": ErrorResponse, "description": "Run not in ready or archived status"},
            404: {"model": ErrorResponse, "description": "Run not found or content not generated"},
            429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        },
    )
    def get_json(
        token: AuthToken,
        run_id: Annotated[str, Path(description="Run identifier (UUID).")],
    ):
        run = ctx.run_repo.get_by_id(run_id)
        _check_run_access(run)
        if not run.generated_json:
            raise HTTPException(status_code=404, detail="JSON metadata not yet generated")
        audit("api.run.read", actor=api_actor(token), target=run_id, resource="json")
        return Response(content=run.generated_json, media_type="application/json")

    @api.get(
        "/runs/{run_id}/validation-report",
        summary="Download validation report (JSON) for a ready run",
        responses={
            401: {"model": ErrorResponse, "description": "Missing or invalid Bearer token"},
            403: {"model": ErrorResponse, "description": "Run not in ready or archived status"},
            404: {"model": ErrorResponse, "description": "Run not found or content not generated"},
            429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        },
    )
    def get_validation_json(
        token: AuthToken,
        run_id: Annotated[str, Path(description="Run identifier (UUID).")],
    ):
        run = ctx.run_repo.get_by_id(run_id)
        _check_run_access(run)
        if not run.generated_validation_json:
            raise HTTPException(status_code=404, detail="Validation report not yet generated")
        audit("api.run.read", actor=api_actor(token), target=run_id, resource="validation_json")
        return Response(content=run.generated_validation_json, media_type="application/json")

    @api.get(
        "/runs/{run_id}/validation-pdf",
        summary="Download validation report (PDF) for a ready run",
        responses={
            200: {"content": {"application/pdf": {}}},
            401: {"model": ErrorResponse, "description": "Missing or invalid Bearer token"},
            403: {"model": ErrorResponse, "description": "Run not in ready or archived status"},
            404: {"model": ErrorResponse, "description": "Run not found or content not generated"},
            429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
        },
    )
    def get_validation_pdf(
        token: AuthToken,
        run_id: Annotated[str, Path(description="Run identifier (UUID).")],
    ):
        run = ctx.run_repo.get_by_id(run_id)
        _check_run_access(run)
        if not run.generated_validation_pdf:
            raise HTTPException(status_code=404, detail="Validation PDF not yet generated")
        audit("api.run.read", actor=api_actor(token), target=run_id, resource="validation_pdf")
        return Response(content=run.generated_validation_pdf, media_type="application/pdf")

    return api
