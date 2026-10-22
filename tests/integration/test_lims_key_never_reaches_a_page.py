"""No page shows the LIMS api-key, whatever is wrong with it.

A key ending in a line break made http.client refuse the header with
ValueError("Invalid header value b'<the key>\\n'"), and the run page's Load
Worklists showed that text -- key and all -- to any standard user, the admin
page showed it to the admin, and it went to Admin > Logs and the container log
(review INGEST-1 / SEC-1). The client now refuses to send such a key in its
own words.
"""

import socket

import pytest

from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services import sample_api as sample_api_module

from .conftest import hold_edit_lock

KEY = "s3cr3t-LIMS-key-0123456789"
RUN = "lims-key-run"
ORIGIN = {"Origin": "http://testserver"}


@pytest.fixture
def a_key_ending_in_a_newline(fresh_app, monkeypatch):
    _app, ctx, _db = fresh_app
    monkeypatch.setenv("SEQSETUP_LIMS_API_KEY", KEY + "\n")
    monkeypatch.setenv("SEQSETUP_LIMS_MIN_INTERVAL_MS", "0")
    monkeypatch.setattr(sample_api_module.socket, "getaddrinfo", lambda *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))])

    def connect(*args, **kwargs):
        raise AssertionError("nothing may connect anywhere")

    monkeypatch.setattr(sample_api_module.socket, "create_connection", connect)
    ctx.sample_api_config_repo.save(SampleApiConfig(
        base_url="https://lims.example.org/api", enabled=True))
    ctx.run_repo.save(SequencingRun(
        id=RUN, run_name="LIMS key", instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10)))
    hold_edit_lock(ctx, RUN, username="operator")
    return ctx


class TestTheRunPage:

    def test_load_worklists_says_what_is_wrong_without_the_key(
        self, logged_in_standard_client, a_key_ending_in_a_newline
    ):
        answer = logged_in_standard_client.get(f"/runs/{RUN}/samples/worklists")

        assert KEY not in answer.text, answer.text[:400]
        assert "control character" in answer.text

    def test_previewing_a_worksheet(self, logged_in_standard_client, a_key_ending_in_a_newline):
        answer = logged_in_standard_client.get(
            f"/runs/{RUN}/samples/preview-worklist",
            params={"worklist_id": "W1", "lanes": ["1"]})

        assert KEY not in answer.text, answer.text[:400]


class TestTheAdminPage:

    def test_the_connection_test_says_what_is_wrong_without_the_key(
        self, logged_in_client, a_key_ending_in_a_newline
    ):
        answer = logged_in_client.post(
            "/admin/settings/sample-api",
            data={"base_url": "https://lims.example.org/api", "enabled": "on"},
            headers=ORIGIN)

        assert KEY not in answer.text, answer.text[:400]


class TestTheLog:

    def test_admin_logs_never_hold_the_key(
        self, logged_in_client, logged_in_standard_client, a_key_ending_in_a_newline
    ):
        from seqsetup.services.log_capture import clear_captured_logs, get_captured_logs

        clear_captured_logs()
        logged_in_standard_client.get(f"/runs/{RUN}/samples/worklists")

        kept = "\n".join(e.message for e in get_captured_logs(limit=2000))
        assert KEY not in kept, kept[:600]
        assert KEY not in logged_in_client.get("/admin/logs").text
