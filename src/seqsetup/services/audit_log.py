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
    _audit_logger.info(json.dumps(record, sort_keys=True))
