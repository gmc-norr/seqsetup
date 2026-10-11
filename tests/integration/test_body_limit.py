"""Each request body is capped (group 3b, review of N-23). Starlette bounds a
form field (1 MB) and the number of fields (1000), not a whole request, so an
anonymous login could still send 1000 fields of 1 MB. Every route takes at
most 2 MB; the paste preview, which reads a file of up to 10 MB, takes 11 MB;
its Add form, which may send 20 MB back, takes 21 MB. A larger body gets 413."""

MB = 1024 * 1024
_ORIGIN = {"Origin": "http://testserver"}


def _create_run(client) -> str:
    response = client.post("/runs/new", follow_redirects=False, headers=_ORIGIN)
    assert response.status_code == 303, response.text[:300]
    return response.headers["location"].split("run_id=", 1)[1].split("&", 1)[0]


class TestTheLoginRequestIsCapped:
    """POST /login/submit needs no login: 2 MB, whatever the fields."""

    def test_a_body_over_2_mb_is_refused(self, client):
        # Three fields, each under Starlette's 1 MB field limit.
        pads = {f"pad{i}": "a" * (900 * 1024) for i in range(3)}
        response = client.post("/login/submit", data={**pads, "username": "a", "password": "b"},
                               headers=_ORIGIN, follow_redirects=False)
        assert response.status_code == 413

    def test_a_body_sent_in_chunks_is_stopped_while_read(self, client):
        """No Content-Length up front: the cap counts while the form is read,
        and the 413 still gets the security headers."""
        def chunks():
            yield b"username=a&password=b&pad="
            for _ in range(48):
                yield b"a" * (64 * 1024)  # 3 MB in all

        response = client.post(
            "/login/submit", content=chunks(), follow_redirects=False,
            headers={**_ORIGIN, "Content-Type": "application/x-www-form-urlencoded"})
        assert response.status_code == 413
        assert response.headers["x-content-type-options"] == "nosniff"

    def test_a_body_under_2_mb_is_read(self, client, admin_user_seeded):
        pads = {f"pad{i}": "a" * (900 * 1024) for i in range(2)}
        response = client.post("/login/submit", data={**pads, **admin_user_seeded},
                               headers=_ORIGIN, follow_redirects=False)
        assert response.status_code == 303


class TestOtherRoutesAreCappedAt2Mb:
    """Every route the paste routes do not name, logged in or not."""

    def test_a_run_form_over_2_mb_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        pads = {f"pad{i}": "a" * (900 * 1024) for i in range(3)}
        response = logged_in_client.post(f"/runs/{run_id}/name", data={**pads, "run_name": "R1"},
                                         headers=_ORIGIN)
        assert response.status_code == 413
        assert ctx.run_repo.get_by_id(run_id).run_name != "R1"


class TestARefusedRequestChangesNothing:
    """A 413 means nothing happened. Starlette's cap acts when the body is
    read or the response starts, so a route that never reads its body would
    run, and save, before its answer became 413; a body whose Content-Length
    is over the cap is refused before any route runs."""

    def test_an_oversized_post_to_a_route_that_reads_no_body_saves_nothing(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        added = logged_in_client.post(f"/runs/{run_id}/samples", headers=_ORIGIN,
                                      data={"sample_id": "S001", "test_id": "WGS", "test_version": "1"})
        assert added.status_code == 200
        run = ctx.run_repo.get_by_id(run_id)
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/{run.samples[0].id}/clear-index",
            content=b"pad=" + b"a" * (3 * MB),
            headers={**_ORIGIN, "Content-Type": "application/x-www-form-urlencoded"})
        assert response.status_code == 413
        assert ctx.run_repo.get_by_id(run_id).updated_at == run.updated_at
        assert "max 2 MB" in response.text


class TestThePasteRoutesTakeTheirFiles:
    """POST /runs/{id}/samples/preview (11 MB) and /samples/bulk (21 MB)."""

    def test_preview_reaches_its_own_10_mb_file_check(self, logged_in_client):
        run_id = _create_run(logged_in_client)
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/preview",
            files={"sample_file": ("big.csv", b"x" * (10 * MB + 1), "text/csv"),
                   "lanes": (None, "1")},
            headers=_ORIGIN,
        )
        assert response.status_code == 400
        assert "File too large (max 10 MB)" in response.text

    def test_preview_refuses_a_body_over_11_mb(self, logged_in_client):
        run_id = _create_run(logged_in_client)
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/preview",
            files={"sample_file": ("big.csv", b"x" * (11 * MB + 1), "text/csv"),
                   "lanes": (None, "1")},
            headers=_ORIGIN,
        )
        assert response.status_code == 413

    def test_add_refuses_a_body_over_21_mb(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _create_run(logged_in_client)
        # Two fields, each under the Add route's 20 MB field limit.
        response = logged_in_client.post(
            f"/runs/{run_id}/samples/bulk",
            files={"paste_data": (None, "S1\n" + " " * (15 * MB)),
                   "pad": (None, " " * (7 * MB)), "lanes": (None, "1")},
            headers=_ORIGIN,
        )
        assert response.status_code == 413
        assert ctx.run_repo.get_by_id(run_id).samples == []


class TestTheProxyExampleLetsTheBodiesThrough:
    """The nginx example in docs/getting-started/deployment.rst. nginx refuses
    bodies over 1 MB unless told otherwise; the example lets through what the
    app takes, and the larger size only on the paste routes."""

    def _example(self) -> str:
        from pathlib import Path

        guide = Path(__file__).resolve().parents[2] / "docs" / "getting-started" / "deployment.rst"
        return guide.read_text()

    def test_the_server_size_covers_the_default_cap(self):
        import re

        from seqsetup.body_limit import DEFAULT_MAX_BODY_BYTES

        sizes = re.findall(r"^       client_max_body_size (\d+)m;", self._example(), re.M)
        assert len(sizes) == 1
        assert int(sizes[0]) * MB >= DEFAULT_MAX_BODY_BYTES

    def test_the_paste_location_covers_the_paste_caps(self):
        import re

        from seqsetup.routes.samples import ADD_MAX_BODY_BYTES, PREVIEW_MAX_BODY_BYTES

        found = re.findall(r"^       location ~ (\S+) \{\n           client_max_body_size (\d+)m;",
                           self._example(), re.M)
        assert len(found) == 1
        pattern, size = found[0]
        for path in ("/runs/abc/samples/preview", "/runs/abc/samples/bulk"):
            assert re.search(pattern, path), path
        assert not re.search(pattern, "/login/submit")
        assert int(size) * MB >= max(ADD_MAX_BODY_BYTES, PREVIEW_MAX_BODY_BYTES)
