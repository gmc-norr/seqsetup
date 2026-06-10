"""Integration test: the bulk-sample route refuses to push a run past the
per-run sample cap, returning a clean error banner rather than a 500.

The model layer (SequencingRun.add_sample) is the load-bearing backstop, but a
near-cap run plus a small paste that tips the total over must surface a
user-facing message, not an unhandled exception.
"""


def _origin() -> dict:
    return {"Origin": "http://testserver"}


def _new_draft_run(client) -> str:
    resp = client.post("/runs/new", follow_redirects=False, headers=_origin())
    assert resp.status_code in (302, 303), resp.text[:300]
    return resp.headers["location"].split("run_id=", 1)[1]


class TestBulkSampleCapRoute:
    def test_bulk_paste_over_cap_returns_banner_not_500(self, logged_in_client, monkeypatch):
        from seqsetup.models import sequencing_run

        monkeypatch.setattr(sequencing_run, "MAX_SAMPLES_PER_RUN", 2)
        run_id = _new_draft_run(logged_in_client)

        # Three sample rows into a cap-2 run. (The paste parser's own cap is
        # bound at import time, so this specifically exercises the route's
        # total-count guard against the live model cap.)
        paste = "A,WGS\nB,WGS\nC,WGS"
        resp = logged_in_client.post(
            f"/runs/{run_id}/samples/bulk",
            data={"paste_data": paste},
            headers={**_origin(), "HX-Request": "true"},
        )
        assert resp.status_code == 200, resp.text[:300]
        assert "maximum" in resp.text.lower()
