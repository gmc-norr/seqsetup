"""Tests for the audit logging helper."""

import json
import logging

from seqsetup.services.audit_log import audit


class TestAuditEmits:
    """Each audit call must produce a single structured JSON line on the
    seqsetup.audit logger with the expected schema."""

    def _capture(self, caplog):
        # Wire caplog up to the audit logger explicitly — it has no handlers
        # by default in tests, and propagation may or may not reach root.
        caplog.set_level(logging.INFO, logger="seqsetup.audit")
        return caplog

    def test_minimal_event_has_required_fields(self, caplog):
        self._capture(caplog)
        audit("login.success", actor="alice")
        records = [r for r in caplog.records if r.name == "seqsetup.audit"]
        assert len(records) == 1
        payload = json.loads(records[0].message)
        assert payload["event"] == "login.success"
        assert payload["actor"] == "alice"
        assert payload["outcome"] == "success"
        assert payload["target"] == ""
        assert "ts" in payload
        assert isinstance(payload["ts"], int)
        # No "details" key when no kwargs supplied.
        assert "details" not in payload

    def test_outcome_failure_recorded(self, caplog):
        self._capture(caplog)
        audit("login.failure", actor="alice", outcome="failure", reason="bad_password")
        payload = json.loads(caplog.records[-1].message)
        assert payload["outcome"] == "failure"
        assert payload["details"] == {"reason": "bad_password"}

    def test_target_and_details(self, caplog):
        self._capture(caplog)
        audit(
            "run.status.changed",
            actor="alice",
            target="run-abc",
            from_status="draft",
            to_status="ready",
        )
        payload = json.loads(caplog.records[-1].message)
        assert payload["target"] == "run-abc"
        assert payload["details"]["from_status"] == "draft"
        assert payload["details"]["to_status"] == "ready"

    def test_payload_is_deterministic_json(self, caplog):
        """Keys are sorted so log lines compare equal across runs — useful for
        regression diffing and SIEM normalisation."""
        self._capture(caplog)
        audit("x.y", actor="a", target="t", b=2, a=1)
        line = caplog.records[-1].message
        assert line.index('"a"') < line.index('"b"')
