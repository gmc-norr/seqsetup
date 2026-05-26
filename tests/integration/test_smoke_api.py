"""Smoke tests for the JSON API.

Covers: Bearer-token auth, the ready-or-archived-only restriction, and the
HTMX-vs-API CSRF exemption (API routes are not cookie-driven).
"""

import pytest

from seqsetup.models.api_token import ApiToken
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    RunStatus,
    SequencingRun,
)


def _seed_api_token(ctx, name: str = "test-token") -> str:
    """Create a token, store the hash, return the plaintext for use in tests."""
    plaintext = ApiToken.generate_token()
    token_hash, token_prefix = ApiToken.hash_token(plaintext)
    token = ApiToken(
        name=name,
        token_hash=token_hash,
        token_prefix=token_prefix,
        created_by="admin-test",
    )
    ctx.api_token_repo.save(token)
    return plaintext


def _seed_ready_run(ctx, run_id: str = "api-ready-run", status: RunStatus = RunStatus.READY) -> str:
    """A run in READY or ARCHIVED state with a pre-generated samplesheet_v2."""
    run = SequencingRun(
        id=run_id,
        run_name="API Test Run",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
        status=status,
        generated_samplesheet_v2="[Header]\nFileFormatVersion,2\n\n[Reads]\nRead1Cycles,151\n",
        generated_json='{"run_name": "API Test Run"}',
    )
    run.add_sample(Sample(
        sample_id="S1",
        index_pair=IndexPair(
            id="p1", name="p1",
            index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
            index2=Index(name="i5", sequence="TATAGCCT", index_type=IndexType.I5),
        ),
    ))
    ctx.run_repo.save(run)
    return run_id


class TestApiAuth:
    def test_api_without_token_returns_401(self, client):
        response = client.get("/api/runs")
        assert response.status_code == 401

    def test_api_with_invalid_bearer_returns_401(self, client):
        response = client.get(
            "/api/runs",
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert response.status_code == 401

    def test_api_with_valid_token_returns_200(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        plaintext = _seed_api_token(ctx)
        response = client.get(
            "/api/runs",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        assert response.status_code == 200


class TestApiReadyOnly:
    def test_api_list_defaults_to_ready_only(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        plaintext = _seed_api_token(ctx)
        _seed_ready_run(ctx, "ready-1", status=RunStatus.READY)
        _seed_ready_run(ctx, "draft-1", status=RunStatus.DRAFT)

        response = client.get(
            "/api/runs",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        assert response.status_code == 200
        body = response.json()
        # New paginated envelope shape.
        assert "items" in body and "total" in body
        ids = [r["id"] for r in body["items"]]
        assert "ready-1" in ids
        # Drafts must never appear via the API.
        assert "draft-1" not in ids

    def test_api_list_returns_minimal_summary_not_full_run(self, client, fresh_app):
        """The list endpoint must NOT include samples, generated exports,
        or PDF payloads — those are behind explicit per-run endpoints."""
        _app, ctx, _db = fresh_app
        plaintext = _seed_api_token(ctx)
        _seed_ready_run(ctx, "ready-2", status=RunStatus.READY)

        response = client.get(
            "/api/runs",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        body = response.json()
        item = body["items"][0]
        # Required summary fields present.
        for key in ("id", "run_name", "status", "instrument_platform", "sample_count"):
            assert key in item
        # Bulky/sensitive payloads MUST NOT appear in the list response.
        for key in ("samples", "generated_samplesheet_v2", "generated_samplesheet_v1",
                    "generated_json", "generated_validation_pdf"):
            assert key not in item, f"{key} leaked into /api/runs response"

    def test_api_list_pagination_returns_requested_page(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        plaintext = _seed_api_token(ctx)
        for i in range(5):
            _seed_ready_run(ctx, f"ready-{i}", status=RunStatus.READY)

        response = client.get(
            "/api/runs?limit=2&offset=0",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        body = response.json()
        assert len(body["items"]) == 2
        assert body["total"] == 5
        assert body["limit"] == 2

    def test_api_list_rejects_out_of_range_limit(self, client, fresh_app):
        """FastAPI Query bounds return 422 — loud rejection beats silent clamp."""
        _app, ctx, _db = fresh_app
        plaintext = _seed_api_token(ctx)

        response = client.get(
            "/api/runs?limit=9999",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        assert response.status_code == 422

    def test_api_rejects_explicit_draft_status(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        plaintext = _seed_api_token(ctx)

        response = client.get(
            "/api/runs?status=draft",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        assert response.status_code == 400

    def test_api_get_draft_run_403(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        plaintext = _seed_api_token(ctx)
        _seed_ready_run(ctx, "draft-2", status=RunStatus.DRAFT)

        response = client.get(
            "/api/runs/draft-2/samplesheet-v2",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        # Drafts must surface as 403 specifically — 404 would leak less but
        # also masks misconfiguration. The contract is "you cannot access
        # this draft" not "this run does not exist".
        assert response.status_code == 403

    def test_api_get_archived_run_works(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        plaintext = _seed_api_token(ctx)
        _seed_ready_run(ctx, "archived-1", status=RunStatus.ARCHIVED)

        response = client.get(
            "/api/runs/archived-1/samplesheet-v2",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        assert response.status_code == 200
        assert "[Header]" in response.text


class TestSwaggerGated:
    """``/api/docs`` and ``/api/openapi.json`` are Bearer-token gated.

    Unauthenticated visitors should see the same 401 they get for every
    other API surface — disclosing the endpoint schema anonymously is
    unnecessary for a clinical-tenant deployment. The contract pinned
    below is "must require a token", not "must be public" (which was the
    earlier wording the audit flagged)."""

    def test_openapi_json_requires_token(self, client):
        response = client.get("/api/openapi.json")
        assert response.status_code == 401

    def test_openapi_json_reachable_with_token(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        plaintext = _seed_api_token(ctx)
        response = client.get(
            "/api/openapi.json",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        assert response.status_code == 200
        spec = response.json()
        assert spec["info"]["title"] == "SeqSetup API"
        assert "/runs" in spec["paths"]

    def test_docs_page_requires_token(self, client):
        response = client.get("/api/docs")
        assert response.status_code == 401

    def test_docs_page_has_csp_header_and_no_inline_script(self, client, fresh_app):
        """Audit C5: the Swagger UI page must have a CSP and no inline script."""
        _app, ctx, _db = fresh_app
        plaintext = _seed_api_token(ctx)
        response = client.get(
            "/api/docs",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        assert response.status_code == 200
        csp = response.headers.get("content-security-policy", "")
        assert csp, "Swagger UI page must set Content-Security-Policy"
        # Strict policy elements we care about:
        assert "default-src 'none'" in csp
        # No inline script in the page body — init code is at /api/docs/init.js
        body = response.text
        # Each <script> tag must have a src attribute (no inline body).
        import re
        for tag in re.findall(r"<script\b[^>]*>(.*?)</script>", body, re.DOTALL):
            assert tag.strip() == "", f"Inline script content found in /api/docs: {tag[:120]!r}"


class TestTokenExpiry:
    """A token past its expires_at must not authenticate."""

    def test_expired_token_returns_401(self, client, fresh_app):
        from datetime import datetime, timedelta
        from seqsetup.models.api_token import ApiToken

        _app, ctx, _db = fresh_app
        plaintext = ApiToken.generate_token()
        token_hash, prefix = ApiToken.hash_token(plaintext)
        expired = ApiToken(
            name="expired-token",
            token_hash=token_hash,
            token_prefix=prefix,
            created_by="test",
            expires_at=datetime.now() - timedelta(days=1),
        )
        ctx.api_token_repo.save(expired)

        response = client.get(
            "/api/runs",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        assert response.status_code == 401, (
            f"Expired token must 401; got {response.status_code} body={response.text[:200]}"
        )


class TestApiCsrfExempt:
    """API routes use Bearer tokens (not cookies) and should be exempt from
    the Origin/Host CSRF check — clients are non-browser (curl, scripts)
    that legitimately omit Origin.
    """

    def test_api_post_without_origin_not_rejected_for_csrf(self, client, fresh_app):
        _app, ctx, _db = fresh_app
        plaintext = _seed_api_token(ctx)

        # The API surface is mostly GET; POST endpoints are minimal. We use
        # a hypothetical POST to a known API path and check the failure mode
        # is auth- or 404-shaped, not 403 from CSRF.
        # If a POST API endpoint doesn't exist, the response should be 404 or
        # 405 (method not allowed) — definitely NOT a 403 from CSRF.
        response = client.post(
            "/api/runs",
            headers={"Authorization": f"Bearer {plaintext}"},
        )
        # 404/405 acceptable (endpoint doesn't accept POST), 403 from CSRF is NOT.
        assert response.status_code != 403
