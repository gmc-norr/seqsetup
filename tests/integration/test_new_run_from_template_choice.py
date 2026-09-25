"""The New Run page offers "Start from a template".

Templates could only be used from the Templates page. The New Run page
now lists them; choosing one makes the run from the template and deletes
the blank run the page had just made — only while it is still an empty
draft, the same rule as that page's Cancel.
"""

from seqsetup.models.sample import Sample

ORIGIN = {"Origin": "http://testserver"}


def _new_blank_run(client) -> str:
    r = client.post("/runs/new", headers=ORIGIN, follow_redirects=False)
    assert r.status_code == 303, r.text[:300]
    return r.headers["location"].split("run_id=", 1)[1]


def _make_template(client, ctx, name) -> str:
    source = _new_blank_run(client)
    client.post(
        f"/runs/{source}/save-as-template",
        data={"name": name, "description": "", "scaffold_sample_ids": "[]"},
        headers=ORIGIN, follow_redirects=False,
    )
    return next(t.id for t in ctx.run_template_repo.list_all() if t.name == name)


def _choose(client, template_id, blank_id):
    return client.post(
        "/runs/new/from-template",
        data={"template_id": template_id, "discard_run_id": blank_id},
        headers=ORIGIN, follow_redirects=False,
    )


class TestNewRunPageOffersTemplates:
    """The choice shows on a new run's setup page when templates exist."""

    def test_shown_on_a_new_run(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _make_template(logged_in_client, ctx, "Tmpl offered")
        blank = _new_blank_run(logged_in_client)
        page = logged_in_client.get(f"/runs/new/step/1?new=1&run_id={blank}").text
        assert 'action="/runs/new/from-template"' in page
        assert "Tmpl offered" in page
        assert f'name="discard_run_id" value="{blank}"' in page

    def test_not_shown_when_editing_setup_later(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _make_template(logged_in_client, ctx, "Tmpl hidden")
        blank = _new_blank_run(logged_in_client)
        page = logged_in_client.get(f"/runs/new/step/1?run_id={blank}").text
        assert 'action="/runs/new/from-template"' not in page


class TestChooseTemplate:
    """POST /runs/new/from-template makes the run and removes the blank one."""

    def test_makes_run_and_deletes_the_blank(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        template_id = _make_template(logged_in_client, ctx, "Tmpl chosen")
        blank = _new_blank_run(logged_in_client)
        r = _choose(logged_in_client, template_id, blank)
        assert r.status_code == 303
        new_id = r.headers["location"].rsplit("/", 1)[1]
        assert ctx.run_repo.get_by_id(new_id).run_name == "Tmpl chosen"
        assert ctx.run_repo.get_by_id(blank) is None

    def test_blank_with_samples_is_kept(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        template_id = _make_template(logged_in_client, ctx, "Tmpl keep")
        blank = _new_blank_run(logged_in_client)
        run = ctx.run_repo.get_by_id(blank)
        run.add_sample(Sample(id="k1", sample_id="KEEP-1", lanes=[1]))
        ctx.run_repo.save(run)
        assert _choose(logged_in_client, template_id, blank).status_code == 303
        assert ctx.run_repo.get_by_id(blank) is not None

    def test_unknown_template_keeps_the_blank(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        blank = _new_blank_run(logged_in_client)
        assert _choose(logged_in_client, "no-such-template", blank).status_code == 404
        assert ctx.run_repo.get_by_id(blank) is not None

    def test_no_template_chosen_keeps_the_blank(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        blank = _new_blank_run(logged_in_client)
        assert _choose(logged_in_client, "", blank).status_code == 404
        assert ctx.run_repo.get_by_id(blank) is not None
