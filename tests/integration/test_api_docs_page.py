"""The API's schema says how to authenticate, and the docs say what the
Swagger page really needs (outside review of f490536, finding F14).

Measured on main: a browser navigation carries the session cookie and never
an Authorization header, so a signed-in user opening /api/docs got 401 --
and so did /api/docs/init.js, which the page's own <script> fetches, and
/api/openapi.json, which Swagger fetches. A Bearer client gets 200 on all
three but cannot be a browser navigation. On top of that the schema
declared no security scheme, so even a working Swagger UI would show no
Authorize button, and the page loads Swagger itself from a CDN, so an
offline lab gets a blank page whatever else is fixed.

README.md and docs/api-reference/runs.rst advertised the page as simply
"hosted at /api/docs".
"""

from pathlib import Path

import pytest

from seqsetup.models.api_token import ApiToken

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def bearer(fresh_app):
    _app, ctx, _db = fresh_app
    plaintext = ApiToken.generate_token()
    token_hash, prefix = ApiToken.hash_token(plaintext)
    ctx.api_token_repo.save(ApiToken(name="f14", token_hash=token_hash, token_prefix=prefix))
    return {"Authorization": f"Bearer {plaintext}"}


class TestTheSchemaSaysHowToAuthenticate:
    """Without a declared scheme, a generated client and Swagger's Authorize
    button have nothing to go on."""

    def test_it_declares_bearer_authentication(self, logged_in_client, bearer):
        schema = logged_in_client.get("/api/openapi.json", headers=bearer).json()
        schemes = schema.get("components", {}).get("securitySchemes", {})
        assert any(s.get("type") == "http" and s.get("scheme", "").lower() == "bearer"
                   for s in schemes.values()), f"securitySchemes={schemes!r}"

    def test_every_route_in_the_schema_requires_it(self, logged_in_client, bearer):
        """The requirement must name a scheme the schema declares -- a
        requirement for an undeclared name says nothing (review P3-2)."""
        schema = logged_in_client.get("/api/openapi.json", headers=bearer).json()
        required = schema.get("security")
        assert required, f"no top-level security: {required!r}"
        declared = set(schema.get("components", {}).get("securitySchemes", {}))
        named = {name for entry in required for name in entry}
        assert named and named <= declared, (
            f"the schema requires {named}, which it does not declare ({declared})")
        for path, operations in schema.get("paths", {}).items():
            for method, operation in operations.items():
                assert operation.get("security") != [], (
                    f"{method.upper()} {path} opts out of the requirement")

    def test_the_schema_says_where_its_paths_live(self, logged_in_client, bearer):
        """This app is mounted at /api, so its paths are "/runs" and the
        like. Without a servers entry a tool pointed at the schema calls
        them at the host root (review P1-1)."""
        schema = logged_in_client.get("/api/openapi.json", headers=bearer).json()
        assert schema.get("servers") == [{"url": "/api"}], schema.get("servers")
        assert "/runs" in schema.get("paths", {}), sorted(schema.get("paths", {}))
        # And the root-level path really is not the API.
        assert logged_in_client.get("/runs", headers=bearer).status_code != 200

    def test_run_data_still_needs_a_token(self, logged_in_client):
        """The guard that must survive: a web session alone reads no run data."""
        assert logged_in_client.get("/api/runs").status_code == 401


class TestTheDocsSayWhatThePageNeeds:

    @pytest.mark.parametrize("path", ["README.md", "docs/api-reference/runs.rst",
                                      "docs/development/contributing.rst"])
    def test_it_does_not_simply_advertise_the_page(self, path):
        """The window is the paragraph the mention sits in, not 1200
        characters of unrelated text: the first cut of this test passed
        against main's own README, where "token" came from a Technology
        Stack row far away (review P3-1)."""
        text = (ROOT / path).read_text()
        assert "/api/docs" in text, f"{path} no longer mentions /api/docs at all"
        where = text.index("/api/docs")
        around = text[max(0, where - 200):where + 400]
        assert "token" in around.lower(), (
            f"{path} points at /api/docs without saying, nearby, that it needs a "
            f"Bearer token, which a browser navigation cannot send:\n{around}")

    @pytest.mark.parametrize("path", ["README.md", "docs/api-reference/runs.rst",
                                      "docs/development/contributing.rst"])
    def test_it_says_a_browser_cannot_open_it(self, path):
        text = (ROOT / path).read_text()
        where = text.index("/api/docs")
        around = text[max(0, where - 200):where + 400]
        assert "browser" in around.lower(), (
            f"{path} does not say a browser cannot open it:\n{around}")

    def test_the_reference_says_the_page_needs_the_internet(self):
        text = (ROOT / "docs" / "api-reference" / "runs.rst").read_text()
        where = text.index("/api/docs")
        around = text[max(0, where - 300):where + 900]
        assert "internet" in around.lower() or "CDN" in around, (
            f"runs.rst does not say the page loads Swagger from a CDN:\n{around}")
