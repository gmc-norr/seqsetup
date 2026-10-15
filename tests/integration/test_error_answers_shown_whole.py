"""An error the server aims at an error slot carries HX-Reselect "unset", so
an hx-select on the element that asked cannot pick it empty (outside review
of f490536, F3: a sample row's settings box picks itself out of the row it
gets back, and its refusals once showed an empty banner)."""

import asyncio

from starlette.requests import Request

from seqsetup.data.instruments import SyncedInstrumentsUnusable
from seqsetup.exception_handlers import instruments_unusable_handler

from .test_group_a3 import ORIGIN, _indexed_draft

HTMX = {**ORIGIN, "HX-Request": "true"}


def _request(htmx: bool) -> Request:
    headers = [(b"hx-request", b"true")] if htmx else []
    return Request({"type": "http", "method": "POST", "path": "/runs/x",
                    "headers": headers, "query_string": b""})


class TestErrorAnswersAreShownWhole:
    """Every handler that aims an error at #error-banner or #form-errors
    tells htmx to use the whole answer."""

    def test_a_refused_setting(self, fresh_app, logged_in_client):
        _app, ctx, _db = fresh_app
        run = _indexed_draft(ctx, "reselect-refused")

        resp = logged_in_client.post(
            f"/runs/{run.id}/samples/{run.samples[0].id}/settings",
            data={"barcode_mismatches_index1": "5"}, headers=HTMX)

        assert resp.status_code == 400
        assert (resp.headers["HX-Retarget"], resp.headers["HX-Reselect"]) == (
            "#error-banner", "unset")

    def test_a_form_validation_error(self, fresh_app, logged_in_client):
        app, _ctx, _db = fresh_app
        from typing import Annotated

        from fastapi import Form
        from pydantic import BaseModel, Field
        from starlette.responses import HTMLResponse

        class _Form(BaseModel):
            bounded: int = Field(ge=0, le=10)

        @app.post("/__test_reselect_422", response_class=HTMLResponse)
        def _h(form: Annotated[_Form, Form()]):
            return "ok"

        resp = logged_in_client.post("/__test_reselect_422", data={"bounded": "99"},
                                     headers=HTMX)

        assert resp.status_code == 422
        assert (resp.headers["HX-Retarget"], resp.headers["HX-Reselect"]) == (
            "#form-errors", "unset")

    def test_unusable_instruments(self):
        resp = asyncio.run(instruments_unusable_handler(
            _request(htmx=True), SyncedInstrumentsUnusable("The records cannot be used.")))

        assert resp.status_code == 503
        assert (resp.headers["HX-Retarget"], resp.headers["HX-Reselect"]) == (
            "#error-banner", "unset")

    def test_a_page_request_gets_a_page_without_it(self):
        resp = asyncio.run(instruments_unusable_handler(
            _request(htmx=False), SyncedInstrumentsUnusable("The records cannot be used.")))

        assert resp.status_code == 503
        assert "HX-Reselect" not in resp.headers
