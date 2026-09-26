"""Secrets never reach the audit line or the stored event (N-21).

Two levels:
- ``redact_url`` cleans a value that IS a web address (a configured LIMS,
  GitHub or LDAP URL), with or without a scheme;
- ``redact_url_secrets`` cleans only unambiguous addresses (``://`` or
  ``//``) inside free text, so names that merely contain ``@``, ``:`` or
  ``#`` are kept exactly.
"""

import json
import logging

import pytest

from seqsetup.services import audit_log
from seqsetup.services.audit_log import audit, redact_url, redact_url_secrets

REMOVED = "[address removed]"


@pytest.mark.parametrize("value,expected", [
    # scheme-relative: reaches lims.url_blocked today (measured)
    ("//svc:PASSWORD@lims.invalid/api?api_token=TOKEN", "//lims.invalid/api"),
    ("svc:PASSWORD@lims.invalid/api?api_token=TOKEN", "lims.invalid/api"),
    ("https://svc:PASSWORD@lims.invalid/api?api_token=TOKEN", "https://lims.invalid/api"),
    ("ghp_TOKEN@github.com/org/repo", "github.com/org/repo"),
    ("TOKEN@lims.example.com", "lims.example.com"),
    ("lims.example.com/api?api_token=TOKEN", "lims.example.com/api"),
    ("lims.example.com?api_token=TOKEN", "lims.example.com"),
    ("lims.example.com:8443?api_token=TOKEN", "lims.example.com:8443"),
    ("svc@lims.example.com?api_token=TOKEN", "lims.example.com"),
    ("https://lims.example.com:8443/api#access_token=TOKEN", "https://lims.example.com:8443/api"),
    ("ldaps://cn=bind,dc=x:SECRET@ldap.example.com:636", "ldaps://ldap.example.com:636"),
    ("https://[::1]:8443/api?k=TOKEN", "https://[::1]:8443/api"),
    ("https://svc:PA SS@lims.invalid/api?api_token=TOKEN", "https://lims.invalid/api"),
    # the host keeps its case; nothing to remove means nothing changes
    ("https://GitHub.com/Org/Repo.git", "https://GitHub.com/Org/Repo.git"),
    ("github.com/org/repo", "github.com/org/repo"),
    ("  ", "  "),
    ("", ""),
    # fail closed
    ("http://[::1/api?api_token=TOKEN", REMOVED),
    ("https://svc:p@ss/w@host/api", REMOVED),
    ("https://svc:2024#rest@host/api", REMOVED),
    ("https://svc:PASSWORD@", REMOVED),
    ("https://host:PORT/api", REMOVED),
])
def test_redact_url(value, expected):
    assert redact_url(value) == expected


@pytest.mark.parametrize("text,expected", [
    ("blocked //svc:PASSWORD@lims.invalid/api?api_token=TOKEN now",
     "blocked //lims.invalid/api now"),
    ("see https://svc:PASSWORD@lims.invalid/api?api_token=TOKEN",
     "see https://lims.invalid/api"),
    ("at 'https://u:PASSWORD@h/x?t=TOKEN'.", "at 'https://h/x'."),
    ("two https://a:P1@h1/x?t=T1 and ldap://b:P2@h2", "two https://h1/x and ldap://h2"),
    ("http://[::1]", "http://[::1]"),
    ("https://GitHub.com/Org", "https://GitHub.com/Org"),
    # not addresses: left exactly as they are
    ("IDT UDI:v1@2024", "IDT UDI:v1@2024"),
    ("UDI/Set#A", "UDI/Set#A"),
    ("LIMS svc:prod@lab", "LIMS svc:prod@lab"),
    ("(alice@lab/NovaSeq)", "(alice@lab/NovaSeq)"),
    ("alice@example.com", "alice@example.com"),
    ("why? because.", "why? because."),
    ("a // b", "a // b"),
    ("run-2026-09-26_A", "run-2026-09-26_A"),
    ("Refusing to call LIMS at 'lims.internal' (127.0.0.1): address is loopback",
     "Refusing to call LIMS at 'lims.internal' (127.0.0.1): address is loopback"),
    ("", ""),
])
def test_redact_url_secrets(text, expected):
    assert redact_url_secrets(text) == expected


@pytest.fixture
def outputs(monkeypatch):
    """The logged JSON line and the stored event of the last audit() call.

    The line is read by a handler on the ``seqsetup.audit`` logger itself, so
    it is exactly what audit() wrote. Once any test has started the app, the
    log viewer's ScrubbingFilter sits on pytest's shared root handlers and
    rewrites records that reach them (``"api_key": ""`` becomes ``"***"``),
    so reading ``caplog`` would make these tests depend on test order.
    """
    lines = []
    stored = []

    class _Lines(logging.Handler):
        def emit(self, record):
            lines.append(record.getMessage())

    class _Sink:
        def append(self, event):
            stored.append(event)

    monkeypatch.setattr(audit_log, "_audit_sink", _Sink())
    handler = _Lines(level=logging.INFO)
    logger = logging.getLogger("seqsetup.audit")
    logger.addHandler(handler)

    def last():
        return json.loads(lines[-1]), stored[-1].to_dict()
    yield last
    logger.removeHandler(handler)


def _both(outputs):
    line, doc = outputs()
    return json.dumps(line), json.dumps(doc)


class TestAuditCleansTarget:
    """The target is free text: unambiguous addresses are cleaned, names kept."""

    def test_address_in_target_is_cleaned(self, outputs):
        audit("x.y", target="https://svc:PASSWORD@lims.invalid/api?api_token=TOKEN")
        line, doc = outputs()
        assert line["target"] == doc["target"] == "https://lims.invalid/api"

    def test_name_in_target_is_kept(self, outputs):
        audit("index_kit.deleted", target="IDT UDI:v1@2024")
        line, doc = outputs()
        assert line["target"] == doc["target"] == "IDT UDI:v1@2024"


class TestAuditCleansDetails:
    """Details are cleaned by key and by content, in the line and the store."""

    @pytest.mark.parametrize("key", ["url", "base_url", "repo_url", "server_url", "urls"])
    def test_address_keys_are_cleaned_strictly(self, outputs, key):
        audit("x.y", **{key: "svc:PASSWORD@lims.example.com?api_token=TOKEN"})
        line, doc = outputs()
        assert line["details"][key] == doc["details"][key] == "lims.example.com"

    def test_address_key_holding_a_list(self, outputs):
        audit("x.y", urls=["TOKEN@a.example.com", "https://u:PASSWORD@b.example.com/x"])
        line, doc = outputs()
        assert line["details"]["urls"] == ["a.example.com", "https://b.example.com/x"]
        assert doc["details"]["urls"] == line["details"]["urls"]

    @pytest.mark.parametrize("key", ["api_key", "password", "bind_password", "secret", "API_KEY"])
    def test_secret_keys_are_masked(self, outputs, key):
        audit("x.y", **{key: "SECRETVALUE"})
        line, doc = outputs()
        assert line["details"][key] == doc["details"][key] == "***"

    def test_non_secret_values_under_similar_keys_are_kept(self, outputs):
        audit("user.updated", password_changed=True, api_key="")
        line, doc = outputs()
        assert line["details"] == doc["details"] == {"password_changed": True, "api_key": ""}

    def test_key_value_secrets_inside_text_are_masked(self, outputs):
        audit("x.y", reason="login failed api_key=SECRETVALUE for svc")
        line_text, doc_text = _both(outputs)
        assert "SECRETVALUE" not in line_text and "SECRETVALUE" not in doc_text

    def test_names_in_details_are_kept(self, outputs):
        audit("index_kit.uploaded", kit_name="IDT UDI:v1@2024", note="UDI/Set#A")
        line, doc = outputs()
        assert line["details"] == doc["details"] == {
            "kit_name": "IDT UDI:v1@2024", "note": "UDI/Set#A"}

    def test_nested_details(self, outputs):
        audit("config_sync.updated",
              nested={"urls": ["//svc:PASSWORD@lims.invalid/api?api_token=TOKEN"],
                      "inner": {"repo_url": "ghp_TOKEN@github.com/org/repo"}})
        line, doc = outputs()
        assert line["details"]["nested"] == doc["details"]["nested"] == {
            "urls": ["//lims.invalid/api"], "inner": {"repo_url": "github.com/org/repo"}}


class TestAuditCleansConvertedValues:
    """Values audit() turns into text (sets, bytes, errors) are cleaned too."""

    ADDR = "https://svc:PASSWORD@lims.invalid/api?api_token=TOKEN"

    @pytest.mark.parametrize("value", [
        {ADDR},
        ADDR.encode(),
        ValueError(f"cannot reach {ADDR}"),
    ], ids=["set", "bytes", "exception"])
    def test_converted_value(self, outputs, value):
        audit("x.y", reason=value)
        line_text, doc_text = _both(outputs)
        for text in (line_text, doc_text):
            assert "PASSWORD" not in text and "TOKEN" not in text

    def test_circular_details_do_not_raise(self, outputs):
        loop = {}
        loop["self"] = loop
        audit("x.y", actor="a", target="t", bad=loop)
        line, doc = outputs()
        assert line["details_serialization_failed"] is True
        assert doc["details"] == {"details_serialization_failed": True}
