"""Audit logging for security-sensitive operations.

Writes structured JSON lines through a dedicated ``seqsetup.audit`` logger
so an operator can route them separately from application logs (file
handler, SIEM forwarder, etc).

Callers MUST NOT pass secrets (passwords, hashes, plaintext API tokens,
LDAP bind passwords). This module emits values opaquely and does not
attempt to scrub — keep the contract at the call site.

Event naming convention: ``"<area>.<verb>"`` — e.g., ``"login.success"``,
``"login.failure"``, ``"run.status.changed"``, ``"validation.approved"``.
"""

import json
import logging
import time
from typing import Any


_audit_logger = logging.getLogger("seqsetup.audit")
# audit() writes at INFO. Without its own level this logger inherits the root
# default, WARNING, and every audit event is dropped before any handler sees
# it. Set here, where the logger is made, so no entry point can forget it.
_audit_logger.setLevel(logging.INFO)


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

    Best-effort: a json serialization failure (e.g. caller passed bytes or
    a non-isoformat datetime) logs a warning to the application logger and
    returns. It must NEVER raise into the caller — a request handler must
    not 500 because of an audit-log call.
    """
    record: dict[str, Any] = {
        "ts": int(time.time()),
        "event": event,
        "actor": actor,
        "target": target,
        "outcome": outcome,
    }
    if details:
        record["details"] = details
    try:
        _audit_logger.info(json.dumps(record, sort_keys=True, default=_json_fallback))
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
            _audit_logger.info(json.dumps({
                "ts": int(time.time()),
                "event": event,
                "actor": actor,
                "target": target,
                "outcome": outcome,
                "details_serialization_failed": True,
            }, sort_keys=True))
        except Exception:
            # Absolutely last resort — never raise.
            pass


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
