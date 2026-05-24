"""Server emits ``HX-Trigger: {"toast": {...}}`` → Alpine renders the toast.

Server-side test: the HTTP header is present and parses as JSON with
the expected shape. (Client-side rendering is covered by the browser
smoke test.)
"""

import json

from fastapi.responses import HTMLResponse


def test_toast_hxtrigger_header_emitted(logged_in_client, fresh_app):
    """Install a temporary route that emits a toast trigger and assert
    the response header round-trips.

    Uses ``logged_in_client`` because AuthMiddleware redirects
    unauthenticated requests away from /__test_toast.
    """
    app, _ctx, _db = fresh_app

    @app.get("/__test_toast", response_class=HTMLResponse)
    def _h():
        return HTMLResponse(
            content="ok",
            headers={"HX-Trigger": json.dumps({"toast": {"kind": "success", "message": "Saved"}})},
        )

    response = logged_in_client.get("/__test_toast")
    trigger = response.headers.get("HX-Trigger", "")
    assert trigger
    payload = json.loads(trigger)
    assert "toast" in payload
    assert payload["toast"]["kind"] == "success"
    assert payload["toast"]["message"] == "Saved"
