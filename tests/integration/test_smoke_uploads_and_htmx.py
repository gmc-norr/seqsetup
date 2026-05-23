"""Smoke tests for multipart upload + HTMX response headers + cookie attributes.

These three surfaces are where a framework migration (FastHTML → FastAPI)
diverges most. Without explicit assertions, a migration can pass the rest
of the smoke suite while the UI is silently broken.
"""

import re

import pytest


def _origin() -> dict:
    return {"Origin": "http://testserver"}


class TestIndexKitUpload:
    """The single multipart UploadFile route in the app.

    A migration that drops UploadFile handling or mis-encodes multipart
    would silently break admin operations. One smoke test against the
    happy path + the binary-content reject path catches both.
    """

    def _minimal_kit_yaml(self) -> bytes:
        return (
            b"name: SmokeTestKit\n"
            b"version: '1.0'\n"
            b"index_mode: unique_dual\n"
            b"index_pairs:\n"
            b"  - id: SK-P1\n"
            b"    name: P1\n"
            b"    index1:\n"
            b"      name: i7-A01\n"
            b"      sequence: ATTACTCG\n"
            b"    index2:\n"
            b"      name: i5-A01\n"
            b"      sequence: TATAGCCT\n"
        )

    def test_upload_minimal_kit_succeeds(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        before = len(ctx.index_kit_repo.list_all())

        response = logged_in_client.post(
            "/indexes/upload",
            data={
                "index_mode": "unique_dual",
                "kit_name": "SmokeTestKit",
                "kit_version": "1.0",
            },
            files={"index_file": ("smoke.yaml", self._minimal_kit_yaml(), "text/yaml")},
            headers=_origin(),
        )
        assert response.status_code == 200, response.text[:300]
        # The kit was saved.
        assert len(ctx.index_kit_repo.list_all()) == before + 1
        # HTMX redirect header — drives the UI back to the kits page.
        assert response.headers.get("HX-Redirect") == "/indexes", (
            f"Expected HX-Redirect to /indexes; got headers={dict(response.headers)}"
        )

    def test_upload_binary_content_rejected(self, logged_in_client):
        """A PDF mis-uploaded as a kit file is rejected with the binary message."""
        response = logged_in_client.post(
            "/indexes/upload",
            data={"index_mode": "unique_dual"},
            files={"index_file": ("oops.pdf", b"%PDF-1.4 fake content", "application/pdf")},
            headers=_origin(),
        )
        # Returns an error fragment (HTMX-friendly), not 5xx.
        assert response.status_code == 200
        assert "binary" in response.text.lower()


class TestHtmxResponseHeaders:
    """The HTMX flow relies on response markers (HX-Redirect on save-and-go,
    hx-swap-oob on partial updates, etc.). A framework migration can drop
    these silently — pin them with explicit assertions."""

    def test_instrument_update_returns_swappable_fragment(self, logged_in_client):
        # Create a draft run.
        response = logged_in_client.get("/runs/new", follow_redirects=False)
        run_id = response.headers["location"].split("run_id=", 1)[1]

        # Update instrument — response should be a fragment ready for hx-swap.
        response = logged_in_client.post(
            f"/runs/{run_id}/instrument",
            data={"instrument_platform": "MiSeq i100 Series"},
            headers={**_origin(), "HX-Request": "true"},
        )
        assert response.status_code == 200
        # The endpoint returns the FlowcellSelectWizard fragment which the UI
        # swaps into #flowcell-select. The fragment must contain the select
        # element for the swap to make sense.
        body = response.text
        assert "flowcell" in body.lower(), f"Fragment missing flowcell select: {body[:300]}"

    def test_unknown_instrument_returns_400_not_silent_keep(self, logged_in_client):
        """B1 fix: unknown platform must 400, not silently keep the old value."""
        response = logged_in_client.get("/runs/new", follow_redirects=False)
        run_id = response.headers["location"].split("run_id=", 1)[1]

        response = logged_in_client.post(
            f"/runs/{run_id}/instrument",
            data={"instrument_platform": "Imaginary Sequencer 9000"},
            headers=_origin(),
        )
        assert response.status_code == 400
        assert "imaginary" in response.text.lower() or "unknown" in response.text.lower()


class TestSessionCookieAttributes:
    """SameSite=Strict + (when SEQSETUP_HTTPS_ONLY=1) Secure are the
    load-bearing CSRF defenses. Pin them in tests so a framework migration
    can't silently downgrade them."""

    def test_session_cookie_has_samesite_strict(self, client, admin_user_seeded):
        response = client.post(
            "/login/submit",
            data=admin_user_seeded,
            headers=_origin(),
            follow_redirects=False,
        )
        assert response.status_code == 303
        set_cookie = response.headers.get("set-cookie", "")
        # Starlette's SessionMiddleware uses "session" as the cookie name.
        assert "session=" in set_cookie, f"No session cookie set: {set_cookie!r}"
        assert re.search(r"samesite=strict", set_cookie, re.IGNORECASE), (
            f"Session cookie must have SameSite=Strict; got {set_cookie!r}"
        )
        # HttpOnly defends against XSS — must be set.
        assert re.search(r"httponly", set_cookie, re.IGNORECASE), (
            f"Session cookie must have HttpOnly; got {set_cookie!r}"
        )
