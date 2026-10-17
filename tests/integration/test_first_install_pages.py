"""What an admin sees on a fresh install, before anything is synced.

A practice deploy (2026-10-17) followed docs/getting-started/installation.rst
on a server whose umask is 007: the containers could not read the checkout,
and the pages either sent the admin to a menu item that does not exist or
said a file was in use that SeqSetup had not been able to read.
"""

from seqsetup.data import instruments


class TestTheProfilesPageNamesTheMenuItem:
    """With nothing synced, the page says where profiles come from, by the
    name the Admin menu gives it."""

    def test_the_empty_page_names_config_sync(self, logged_in_client):
        page = logged_in_client.get("/profiles").text
        assert "No test profiles available. Sync profiles from Admin &gt; Config Sync." in page
        assert "No application profiles available. Sync profiles from Admin &gt; Config Sync." in page

    def test_it_names_no_menu_item_that_does_not_exist(self, logged_in_client):
        assert "Admin &gt; Profiles" not in logged_in_client.get("/profiles").text


CLOSED = ("SeqSetup may not look in /app/config (Permission denied), so "
          "instruments.yaml was not read and no local instruments are loaded")


class TestTheInstrumentsPageSaysWhatWasRead:
    """With no synced instruments, the page says whether the local file was
    read, instead of always saying it is in use."""

    def test_a_file_that_was_not_read_is_said_plainly(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(instruments, "_local_file_problem", CLOSED)
        page = logged_in_client.get("/admin/instruments").text
        assert "No instruments are available" in page
        assert CLOSED in page
        assert "Using local configuration file" not in page

    def test_the_page_says_how_to_put_it_right(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(instruments, "_local_file_problem", CLOSED)
        page = logged_in_client.get("/admin/instruments").text
        assert 'href="/admin/config-sync"' in page
        assert "Installation" in page

    def test_a_file_that_was_read_keeps_the_note(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(instruments, "_local_file_problem", None)
        page = logged_in_client.get("/admin/instruments").text
        assert "Using local configuration file" in page
        assert "No instruments are available" not in page

    def test_the_reason_is_escaped(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(instruments, "_local_file_problem", "SeqSetup may not look in /a<b>")
        page = logged_in_client.get("/admin/instruments").text
        assert "/a&lt;b&gt;" in page and "/a<b>" not in page
