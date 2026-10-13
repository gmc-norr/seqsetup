"""Admin > LIMS Integration has no api-key box, and saving the page removes
a key an older deployment stored.

The key box wrote the secret into the settings document, where it sat in
every database backup and was preferred over SEQSETUP_LIMS_API_KEY whenever
that was unset. The box is gone; the page says when an old stored key is
still there and that saving removes it; saving removes it.
"""

ORIGIN = {"Origin": "http://testserver"}
STORED = "STORED-KEY-FROM-AN-OLD-DEPLOYMENT"


def _settings_doc(ctx) -> dict:
    """The raw sample-api settings document, as MongoDB holds it."""
    doc = ctx.sample_api_config_repo.collection.find_one({"_id": "sample_api_config"})
    return (doc or {}).get("config", {})


def _store_a_legacy_key(ctx) -> None:
    """Write the document an older SeqSetup would have left behind."""
    ctx.sample_api_config_repo.collection.replace_one(
        {"_id": "sample_api_config"},
        {"_id": "sample_api_config",
         "config": {"base_url": "https://lims.example.org/api", "api_key": STORED,
                    "enabled": False, "field_mappings": {}}},
        upsert=True,
    )


class TestThePageHasNoKeyBox:
    def test_the_form_has_no_api_key_input(self, logged_in_client, fresh_app):
        page = logged_in_client.get("/admin/sample-api").text
        assert 'name="api_key"' not in page

    def test_the_page_names_the_environment_variable(self, logged_in_client, fresh_app):
        page = logged_in_client.get("/admin/sample-api").text
        assert "SEQSETUP_LIMS_API_KEY" in page

    def test_a_posted_key_is_never_stored(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        response = logged_in_client.post(
            "/admin/settings/sample-api",
            data={"base_url": "https://lims.example.org/api", "api_key": "TYPED-KEY"},
            headers=ORIGIN)
        assert response.status_code == 200
        assert "api_key" not in _settings_doc(ctx)
        assert "TYPED-KEY" not in str(_settings_doc(ctx))


class TestAnOldStoredKey:
    def test_the_page_says_a_stored_key_is_there_and_that_saving_removes_it(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _store_a_legacy_key(ctx)

        page = logged_in_client.get("/admin/sample-api").text

        assert "older version of SeqSetup stored an api-key" in page
        assert "Saving this page removes it" in page

    def test_the_page_never_shows_the_stored_key_itself(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _store_a_legacy_key(ctx)
        assert STORED not in logged_in_client.get("/admin/sample-api").text

    def test_saving_removes_it(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _store_a_legacy_key(ctx)

        response = logged_in_client.post(
            "/admin/settings/sample-api",
            data={"base_url": "https://lims.example.org/api"}, headers=ORIGIN)

        assert response.status_code == 200
        assert "api_key" not in _settings_doc(ctx)

    def test_the_page_stops_saying_so_once_it_is_gone(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _store_a_legacy_key(ctx)
        logged_in_client.post("/admin/settings/sample-api",
                              data={"base_url": "https://lims.example.org/api"},
                              headers=ORIGIN)

        page = logged_in_client.get("/admin/sample-api").text

        assert "older version of SeqSetup stored an api-key" not in page

    def test_the_page_says_nothing_when_no_key_was_ever_stored(
            self, logged_in_client, fresh_app):
        page = logged_in_client.get("/admin/sample-api").text
        assert "older version of SeqSetup stored an api-key" not in page
