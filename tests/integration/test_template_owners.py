"""Only a template's maker or an admin may rename or delete it (spec
2026-09-28 group 2a, N-27 = F19 + F20). Anyone may still use one.

The admin fixture is "admin-test"; the standard one is "operator"."""

from seqsetup.models.run_template import RunTemplate

ORIGIN = {"Origin": "http://testserver"}
HX = {**ORIGIN, "HX-Request": "true"}
NOT_YOURS = "You can only change templates you made. Ask the person who made it, or an admin."


def _template(ctx, created_by, name="Tmpl"):
    # 10B is offered on the default NovaSeq X; a template without a flowcell
    # cannot start a run (run_builder.assert_references_available).
    template = RunTemplate(name=name, created_by=created_by, updated_by=created_by,
                           flowcell_type="10B")
    ctx.run_template_repo.save(template)
    return template.id


def _rename(client, tid, name="Renamed"):
    return client.post(f"/templates/{tid}", data={"name": name, "description": ""},
                       headers=ORIGIN, follow_redirects=False)


class TestSomeoneElsesTemplate:
    def test_standard_user_cannot_delete_it(self, logged_in_standard_client, fresh_app):
        _app, ctx, _db = fresh_app
        tid = _template(ctx, "admin-test")
        resp = logged_in_standard_client.delete(f"/templates/{tid}", headers=HX)
        assert resp.status_code == 403
        assert NOT_YOURS in resp.text
        assert ctx.run_template_repo.get_by_id(tid) is not None

    def test_standard_user_cannot_rename_it(self, logged_in_standard_client, fresh_app):
        _app, ctx, _db = fresh_app
        tid = _template(ctx, "admin-test", name="Original")
        resp = _rename(logged_in_standard_client, tid, "Hijacked")
        assert resp.status_code == 403
        assert NOT_YOURS in resp.text
        assert ctx.run_template_repo.get_by_id(tid).name == "Original"

    def test_a_template_with_no_maker_is_admin_only(
            self, logged_in_client, logged_in_standard_client, fresh_app):
        _app, ctx, _db = fresh_app
        tid = _template(ctx, "")
        assert logged_in_standard_client.delete(f"/templates/{tid}", headers=HX).status_code == 403
        assert logged_in_client.delete(f"/templates/{tid}", headers=HX).status_code == 200
        assert ctx.run_template_repo.get_by_id(tid) is None

    def test_anyone_may_still_start_a_run_from_it(self, logged_in_standard_client, fresh_app):
        _app, ctx, _db = fresh_app
        tid = _template(ctx, "admin-test")
        resp = logged_in_standard_client.post(f"/runs/new/from-template/{tid}",
                                              headers=ORIGIN, follow_redirects=False)
        assert resp.status_code == 303


class TestTheMakerOrAnAdmin:
    def test_maker_deletes_own(self, logged_in_standard_client, fresh_app):
        _app, ctx, _db = fresh_app
        tid = _template(ctx, "operator")
        assert logged_in_standard_client.delete(f"/templates/{tid}", headers=HX).status_code == 200
        assert ctx.run_template_repo.get_by_id(tid) is None

    def test_maker_renames_own(self, logged_in_standard_client, fresh_app):
        _app, ctx, _db = fresh_app
        tid = _template(ctx, "operator")
        assert _rename(logged_in_standard_client, tid).status_code == 303
        assert ctx.run_template_repo.get_by_id(tid).name == "Renamed"

    def test_admin_deletes_anyones(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        tid = _template(ctx, "operator")
        assert logged_in_client.delete(f"/templates/{tid}", headers=HX).status_code == 200

    def test_admin_renames_anyones(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        tid = _template(ctx, "operator")
        assert _rename(logged_in_client, tid).status_code == 303
        assert ctx.run_template_repo.get_by_id(tid).name == "Renamed"

    def test_missing_template_is_still_404(self, logged_in_standard_client):
        assert logged_in_standard_client.delete("/templates/nope", headers=HX).status_code == 404
        assert _rename(logged_in_standard_client, "nope").status_code == 404


class TestListPage:
    def test_delete_shows_only_to_the_maker_and_to_admins(
            self, logged_in_client, logged_in_standard_client, fresh_app):
        _app, ctx, _db = fresh_app
        admins = _template(ctx, "admin-test", name="Admins")
        own = _template(ctx, "operator", name="Operators")
        standard_page = logged_in_standard_client.get("/templates").text
        assert f'hx-delete="/templates/{own}"' in standard_page
        assert f'hx-delete="/templates/{admins}"' not in standard_page
        admin_page = logged_in_client.get("/templates").text
        assert f'hx-delete="/templates/{own}"' in admin_page
        assert f'hx-delete="/templates/{admins}"' in admin_page
