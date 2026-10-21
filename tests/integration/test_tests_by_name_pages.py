"""The pages offer and take a test by its TestName: several tests may share
a TestType and a version (the user's word, 2026-10-21;
docs/design/2026-10-21-tests-by-name-design.md)."""

import html

from .test_group_a4 import _sample
from .test_paste_preview import ORIGIN, _run

NAMES = ("WGSRareDisease_1", "WGSRareDiseaseResearch_1")


def _lab_tests(ctx):
    # Imported here: a module-level TestProfile would be collected by pytest.
    from seqsetup.models.test_profile import TestProfile
    for name in NAMES:
        ctx.test_profile_repo.save(TestProfile(test_type="WGS", test_name=name, version="1.0.0",
                                               source_file=f"{name}.yaml"))


def _options(page, select_id):
    return page.split(f'id="{select_id}"', 1)[1].split("</select>", 1)[0]


class TestEveryPickListOffersEachName:

    def test_the_paste_the_bulk_panel_and_the_check_fix_box(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _lab_tests(ctx)
        run_id = _run(ctx, samples=[_sample("S1")])

        page = html.unescape(logged_in_client.get(f"/runs/{run_id}").text)

        for select_id in ("default_test_id", "bulk-test-id-input", "fix-test-id"):
            options = _options(page, select_id)
            for name in NAMES:
                assert f'<option value="{name}">{name} (WGS)</option>' in options, (select_id, options)
            assert '<option value="WGS">' not in options, (select_id, options)
        assert page.count("Synced: WGSRareDiseaseResearch_1 1.0.0 · WGSRareDisease_1 1.0.0") == 3

    def test_a_name_that_is_its_type_is_shown_once(self, logged_in_client, fresh_app):
        from .test_group_a4 import _tests
        _app, ctx, _db = fresh_app
        _tests(ctx, ("WGS", "1.0.0"))
        run_id = _run(ctx, samples=[_sample("S1")])

        page = html.unescape(logged_in_client.get(f"/runs/{run_id}").text)

        assert '<option value="WGS">WGS</option>' in _options(page, "default_test_id")


class TestAPasteTakesATestName:

    def _preview(self, client, run_id, text, default_test=""):
        return client.post(f"/runs/{run_id}/samples/preview", headers=ORIGIN, data={
            "paste_data": text, "lanes": ["1"], "default_test_id": default_test,
            "default_test_version": "1"})

    def test_a_default_test_that_is_a_name_is_taken(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _lab_tests(ctx)
        run_id = _run(ctx)

        resp = self._preview(logged_in_client, run_id, "sample_id\nS1\n", "WGSRareDisease_1")

        assert resp.status_code == 200, resp.text
        assert "No test called" not in html.unescape(resp.text)

    def test_a_default_test_that_is_only_a_type_is_refused(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _lab_tests(ctx)
        run_id = _run(ctx)

        resp = self._preview(logged_in_client, run_id, "sample_id\nS1\n", "WGS")

        assert resp.status_code == 400
        assert 'No test called "WGS".' in html.unescape(resp.text)

    def test_the_preview_knows_each_name_and_not_the_type(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _lab_tests(ctx)
        run_id = _run(ctx)

        page = html.unescape(self._preview(
            logged_in_client, run_id,
            "sample_id,test_id\nS1,WGSRareDisease_1\nS2,WGSRareDiseaseResearch_1\nS3,WGS\n").text)

        assert page.count("No test called") == 1 and 'No test called "WGS".' in page, page


class TestTheProfilesPageListsTestsByName:

    def test_in_name_order_whatever_their_types(self, logged_in_client, fresh_app):
        # Imported here: a module-level TestProfile would be collected by pytest.
        from seqsetup.models.test_profile import TestProfile
        _app, ctx, _db = fresh_app
        ctx.test_profile_repo.save(TestProfile(test_type="ZZZ", test_name="Alpha_1", version="1.0.0"))
        ctx.test_profile_repo.save(TestProfile(test_type="AAA", test_name="Beta_1", version="1.0.0"))

        page = logged_in_client.get("/profiles").text

        assert page.index("Alpha_1 (v1.0.0)") < page.index("Beta_1 (v1.0.0)"), page
