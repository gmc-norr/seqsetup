"""Audit logging for security-sensitive operations.

Writes structured JSON lines through a dedicated ``seqsetup.audit`` logger
so an operator can route them separately from application logs (file
handler, SIEM forwarder, etc).

Once ``set_audit_sink`` is called at startup, every event is also stored
permanently (``audit_events``, shown on /admin/audit): best effort, at most
``AUDIT_WRITE_TIMEOUT_S`` per write, never raising.

Callers MUST NOT pass secrets (passwords, hashes, plaintext API tokens,
LDAP bind passwords). As a backstop, every web address in ``target`` and in
string ``details`` loses its user/password part, query string and fragment
before the event is written (``redact_url_secrets``, security audit N-21).
Nothing else is scrubbed — keep the contract at the call site.

Event naming convention: ``"<area>.<verb>"`` — e.g., ``"login.success"``,
``"login.failure"``, ``"run.status.changed"``, ``"validation.approved"``.
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import pymongo

from ..models.audit_event import AuditEvent
from .log_capture import _SENSITIVE_KEY_NAMES, scrub_log_message


_audit_logger = logging.getLogger("seqsetup.audit")
# audit() writes at INFO. Without its own level this logger inherits the root
# default, WARNING, and every audit event is dropped before any handler sees
# it. Set here, where the logger is made, so no entry point can forget it.
_audit_logger.setLevel(logging.INFO)

# The longest one audit() call waits for the database. Past it the event
# counts as not saved (an ERROR is logged) and the request goes on.
AUDIT_WRITE_TIMEOUT_S = 2.0

# Where audit() also stores each event (an AuditEventRepository). Set at
# startup by set_audit_sink; None means events are only logged.
_audit_sink = None


def set_audit_sink(sink) -> None:
    """Store every later audit event through ``sink`` (anything with an
    ``append(AuditEvent)`` method); None stops storing."""
    global _audit_sink
    _audit_sink = sink


# Quote and sentence characters that may surround an address in text.
# Not '[' / ']': they belong to an IPv6 host.
_EDGE_CHARS = "'\"()<>{},;.!"
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_ADDRESS_REMOVED = "[address removed]"
# A details key whose value is a web address: url, urls, base_url, repo_url,
# server_url, ... Its value is cleaned with redact_url, scheme or not.
_ADDRESS_KEY_RE = re.compile(r"(?:.*_)?urls?")


def redact_url(value: str) -> str:
    """Clean a value that IS a web address (a configured LIMS, GitHub or LDAP
    URL): keep scheme, host (as typed), port and path; drop the
    user/password part, the query string and the fragment. The scheme is
    optional. An address that cannot be parsed cleanly becomes
    ``[address removed]``; one with nothing to remove is returned as is.
    Anything that is not text is returned as is (call sites pass it to
    audit() directly, outside audit()'s own never-raise guard)."""
    if not isinstance(value, str) or not value.strip():
        return value
    return _clean_address(value.strip())


def redact_url_secrets(text: str) -> str:
    """Clean every unambiguous web address inside free text — a piece that
    contains ``://`` or starts with ``//`` — the way ``redact_url`` does.

    Nothing else counts as an address here, so a name that merely contains
    ``@``, ``:`` or ``#`` (a kit ``IDT UDI:v1@2024``, an e-mail address) is
    kept exactly. Values known to be addresses go through ``redact_url``
    (audit() does that for details keys named like ``*url``)."""
    out = []
    for piece in re.split(r"(\s+)", text):
        core = piece.strip(_EDGE_CHARS)
        if "://" in core or (core.startswith("//") and len(core) > 2):
            start = piece.find(core)
            out.append(piece[:start] + _clean_address(core) + piece[start + len(core):])
        else:
            out.append(piece)
    return "".join(out)


def _clean_address(token: str) -> str:
    has_scheme = _SCHEME_RE.match(token) is not None
    relative = token.startswith("//")
    try:
        # Without a scheme or "//", urlsplit would read the host as a path.
        parts = urlsplit(token if has_scheme or relative else "//" + token)
        host = parts.hostname
        parts.port  # raises ValueError on a port that is not a number
        user = parts.username
    except ValueError:
        return _ADDRESS_REMOVED
    if not host:
        return _ADDRESS_REMOVED
    # An '@' that did not end up closing a user part means a '#', '/' or '?'
    # inside the password split the address early: the parse is not safe.
    if "@" in token and user is None:
        return _ADDRESS_REMOVED
    prefix = f"{parts.scheme}://" if has_scheme else ("//" if relative else "")
    # host[:port] exactly as typed, so a clean address comes back unchanged.
    cleaned = prefix + parts.netloc.rpartition("@")[2] + parts.path
    if any(c in cleaned for c in "@?#") or any(c.isspace() for c in cleaned):
        return _ADDRESS_REMOVED
    return cleaned


def _clean_value(value, key: str = ""):
    """Clean one value of an event, walking dicts and lists.

    - a non-empty text under a secret-looking key (``api_key``, ``password``,
      ... — the log viewer's list) becomes ``***``;
    - a text under an address key (``url``, ``*_url``) goes through
      ``redact_url``;
    - any other text goes through ``redact_url_secrets`` and the log viewer's
      ``scrub_log_message`` (``api_key=...`` inside a sentence).
    """
    if isinstance(value, dict):
        return {k: _clean_value(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean_value(v, key) for v in value]
    if not isinstance(value, str):
        return value
    name = key.lower()
    if name in _SENSITIVE_KEY_NAMES and value:
        return "***"
    if _ADDRESS_KEY_RE.fullmatch(name):
        return redact_url(value)
    return scrub_log_message(redact_url_secrets(value))


def audit(
    event: str,
    actor: str = "",
    target: str = "",
    outcome: str = "success",
    **details: Any,
) -> None:
    """Emit a single audit event.

    Args:
        event: short dotted event name (e.g. "run.status.changed")
        actor: identity that performed the action (username, "api-token:<id>", or "" for unauthenticated)
        target: identifier of the affected object (run_id, user_id, etc.)
        outcome: "success", "failure", or "denied"
        **details: small dict of non-sensitive contextual fields

    ``target`` and ``details`` are cleaned first (see ``_clean_value``). The
    event is then stored through the sink set by ``set_audit_sink``, if any
    — see ``_store``.

    Best-effort: a json serialization failure (e.g. caller passed bytes or
    a non-isoformat datetime) logs a warning to the application logger and
    returns. It must NEVER raise into the caller — a request handler must
    not 500 because of an audit-log call.
    """
    now = datetime.now(timezone.utc)
    record: dict[str, Any] = {
        "ts": int(now.timestamp()),
        "event": event,
        "actor": actor,
        "target": target,
        "outcome": outcome,
    }
    if details:
        record["details"] = details
    try:
        # Turn everything into JSON types first, then clean: a set, bytes or
        # an exception becomes text in _json_fallback, and that text must be
        # cleaned too.
        clean = json.loads(json.dumps(record, default=_json_fallback))
        clean["target"] = _clean_value(clean["target"])
        if "details" in clean:
            clean["details"] = _clean_value(clean["details"])
        line = json.dumps(clean, sort_keys=True)
    except Exception:
        # Fall back to a minimal record and log the serialization failure.
        # This keeps the audit trail informative (event/actor/target survive)
        # without killing the request that triggered the audit.
        logging.getLogger(__name__).warning(
            "audit() serialization failed for event=%r — emitting minimal record",
            event,
            exc_info=True,
        )
        try:
            line = json.dumps({
                "ts": record["ts"],
                "event": event,
                "actor": actor,
                "target": _clean_value(target) if isinstance(target, str) else "",
                "outcome": outcome,
                "details_serialization_failed": True,
            }, sort_keys=True)
        except Exception:
            # Absolutely last resort — never raise.
            return
    try:
        _audit_logger.info(line)
    except Exception:
        pass
    _store(line, now)


def _store(line: str, when: datetime) -> None:
    """Save one event (its cleaned JSON line) through the sink. Written
    before audit() returns and bounded by AUDIT_WRITE_TIMEOUT_S: when the
    user sees a response, the event is stored or an ERROR was logged. Never
    raises. The ERROR carries the cleaned line, so who did what to what
    still reaches /admin/logs during a database outage."""
    sink = _audit_sink
    if sink is None:
        return
    try:
        record = json.loads(line)
        details = record.get("details") or {}
        if record.get("details_serialization_failed"):
            details = {"details_serialization_failed": True}
        entry = AuditEvent(
            timestamp=when,
            event=record.get("event", ""),
            actor=record.get("actor", ""),
            target=record.get("target", ""),
            outcome=record.get("outcome", ""),
            details=details,
        )
        with pymongo.timeout(AUDIT_WRITE_TIMEOUT_S):
            sink.append(entry)
    except Exception:
        logging.getLogger(__name__).error(
            "Audit event could not be saved to the audit trail: %s",
            line,
            exc_info=True,
        )


def _json_fallback(obj):
    """Last-chance JSON encoder hook.

    Handles datetime/date/bytes/set, then falls back to ``str()``. Anything
    that can't be stringified falls into the outer try/except in ``audit``.
    """
    from datetime import date, datetime
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, (bytes, bytearray)):
        return obj.decode("utf-8", errors="replace")
    if isinstance(obj, (set, frozenset)):
        return sorted(obj)
    return str(obj)
