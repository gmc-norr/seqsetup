"""audit() stores each event through the sink: same fields as the log line,
bounded in time, never raising."""

import json
import logging
import time

import pymongo
import pytest

from seqsetup.services import audit_log
from seqsetup.services.audit_log import audit


class _ListSink:
    def __init__(self):
        self.events = []

    def append(self, event):
        self.events.append(event)


class _BrokenSink:
    def append(self, event):
        raise RuntimeError("database down")


class _DeadServerSink:
    """Writes to a MongoDB address where nothing listens; the client's own
    timeouts are 30 s, like the app's socketTimeoutMS."""

    def __init__(self):
        client = pymongo.MongoClient(
            "mongodb://127.0.0.1:1/", serverSelectionTimeoutMS=30000,
            connectTimeoutMS=30000, socketTimeoutMS=30000,
        )
        self.client = client
        self.coll = client["t"]["audit_events"]

    def append(self, event):
        self.coll.insert_one(event.to_dict())


@pytest.fixture
def sink(monkeypatch):
    s = _ListSink()
    monkeypatch.setattr(audit_log, "_audit_sink", s)
    return s


class TestAuditSink:
    """The stored event matches the logged line."""

    def test_event_is_stored_with_the_logged_fields(self, sink, caplog):
        caplog.set_level(logging.INFO, logger="seqsetup.audit")
        audit("run.status.changed", actor="alice", target="run-1",
              outcome="success", to_status="ready")
        line = json.loads(
            [r.message for r in caplog.records if r.name == "seqsetup.audit"][-1])
        (stored,) = sink.events
        assert stored.event == line["event"] == "run.status.changed"
        assert stored.actor == line["actor"] == "alice"
        assert stored.target == line["target"] == "run-1"
        assert stored.outcome == line["outcome"] == "success"
        assert stored.details == line["details"] == {"to_status": "ready"}

    def test_stored_event_has_no_address_secrets(self, sink):
        audit("lims.url_blocked", actor="lims_client",
              target="//svc:PASSWORD@lims.invalid/api?api_token=TOKEN",
              reason="see https://svc:PASSWORD@lims.invalid/api?api_token=TOKEN")
        stored = json.dumps(sink.events[0].to_dict())
        assert "PASSWORD" not in stored and "TOKEN" not in stored
        assert sink.events[0].target == "//lims.invalid/api"

    def test_unserializable_details_are_marked(self, sink):
        class Weird:
            def __str__(self):
                raise RuntimeError("no")
        audit("x.y", actor="a", target="t", bad=Weird())
        assert sink.events[0].details == {"details_serialization_failed": True}
        assert sink.events[0].event == "x.y"

    def test_no_sink_is_fine(self, monkeypatch):
        monkeypatch.setattr(audit_log, "_audit_sink", None)
        audit("x.y", actor="a")

    def test_set_audit_sink_sets_and_clears(self, monkeypatch):
        monkeypatch.setattr(audit_log, "_audit_sink", None)
        s = _ListSink()
        audit_log.set_audit_sink(s)
        audit("x.y")
        audit_log.set_audit_sink(None)
        audit("x.z")
        assert [e.event for e in s.events] == ["x.y"]


class TestAuditSinkFailure:
    """A failed write never reaches the caller, and is not silent."""

    def test_failing_sink_does_not_raise_and_logs_an_error(self, monkeypatch, caplog):
        monkeypatch.setattr(audit_log, "_audit_sink", _BrokenSink())
        caplog.set_level(logging.ERROR, logger="seqsetup.services.audit_log")
        audit("login.success", actor="alice")
        errors = [r for r in caplog.records
                  if r.name == "seqsetup.services.audit_log" and r.levelno == logging.ERROR]
        assert len(errors) == 1
        assert "login.success" in errors[0].getMessage()

    def test_failure_message_keeps_the_cleaned_event(self, monkeypatch, caplog):
        """During a database outage the ERROR is the only copy that reaches
        /admin/logs, so it carries who did what to what — cleaned."""
        monkeypatch.setattr(audit_log, "_audit_sink", _BrokenSink())
        caplog.set_level(logging.ERROR, logger="seqsetup.services.audit_log")
        audit("run.status.changed", actor="alice", target="run-7",
              url="svc:PASSWORD@lims.example.com?api_token=TOKEN")
        (error,) = [r for r in caplog.records
                    if r.name == "seqsetup.services.audit_log" and r.levelno == logging.ERROR]
        message = error.getMessage()
        assert '"actor": "alice"' in message and '"target": "run-7"' in message
        assert "PASSWORD" not in message and "TOKEN" not in message

    def test_write_to_a_dead_server_is_bounded(self, monkeypatch, caplog):
        assert audit_log.AUDIT_WRITE_TIMEOUT_S == 2.0
        dead = _DeadServerSink()
        monkeypatch.setattr(audit_log, "_audit_sink", dead)
        caplog.set_level(logging.ERROR, logger="seqsetup.services.audit_log")
        start = time.monotonic()
        try:
            audit("login.success", actor="alice")
        finally:
            elapsed = time.monotonic() - start
            dead.client.close()
        assert elapsed < 5, f"audit() waited {elapsed:.1f}s"
        assert any(r.levelno == logging.ERROR for r in caplog.records
                   if r.name == "seqsetup.services.audit_log")
