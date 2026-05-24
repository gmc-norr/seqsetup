"""Pydantic form validation failures → HTML fragment with HX-Reswap/HX-Retarget.

This test will become more meaningful as Phase 1+ routes start using
Pydantic forms. For now it exercises the global ``RequestValidationError``
handler against a synthetic invalid request to ``/login/submit``
(if that route is the first to gain a Pydantic form) OR a placeholder
test route added in this same file.
"""

import pytest
from starlette.testclient import TestClient


def test_pydantic_422_returns_html_fragment_with_hx_headers(logged_in_client, fresh_app):
    """When a Pydantic-validated form fails, HTMX clients get an HTML
    fragment + HX-Retarget. (Placeholder: any Phase-1+ route that gains
    a Pydantic form will exercise this in earnest.)

    Uses ``logged_in_client`` because AuthMiddleware redirects
    unauthenticated requests to /login for any non-public path.
    """
    app, _ctx, _db = fresh_app
    from fastapi import Form
    from pydantic import BaseModel, Field
    from typing import Annotated
    from starlette.responses import HTMLResponse

    class _TestForm(BaseModel):
        bounded: int = Field(ge=0, le=10)

    @app.post("/__test_pydantic_422", response_class=HTMLResponse)
    def _h(form: Annotated[_TestForm, Form()]):
        return "ok"

    response = logged_in_client.post(
        "/__test_pydantic_422",
        data={"bounded": "99"},
        headers={"Origin": "http://testserver", "HX-Request": "true"},
    )
    assert response.status_code == 422
    assert "text/html" in response.headers.get("content-type", "")
    assert response.headers.get("HX-Retarget") == "#form-errors"
    assert response.headers.get("HX-Reswap") == "innerHTML"
    # Body MUST NOT contain the offending value ("99") — security: no echo.
    assert "99" not in response.text
    assert "bounded" in response.text  # field name OK to include
