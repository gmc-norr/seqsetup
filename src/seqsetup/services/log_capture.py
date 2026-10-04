"""In-memory log capture for admin log viewer."""

import logging
import re
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Optional


# Substrings that, if seen in a log message as the key of a key=value or
# "key": "value" pattern, indicate the value is a secret and must be scrubbed
# before being stored in the operator-visible log buffer.
_SENSITIVE_KEY_NAMES = (
    "bind_password",
    "api_key",
    "api-key",
    "password",
    "password_hash",
    "token_hash",
    "secret",
    "session_secret",
    "authorization",
)

# Compile once. Matches "<key>: '<value>'", "<key>=<value>", "<key>: <value>",
# and JSON-ish "<key>": "<value>". Captures the key separator and quoted value
# so the replacement preserves the surrounding shape.
def _build_scrub_pattern() -> re.Pattern:
    keys = "|".join(re.escape(k) for k in _SENSITIVE_KEY_NAMES)
    # Match: optional " or ', key, optional " or ', then = or : with optional space,
    # then either quoted value or unquoted value up to comma/whitespace.
    return re.compile(
        rf"""(?ix)
        ([\"\']?(?:{keys})[\"\']?\s*[:=]\s*)   # group 1: key and separator
        (?:
            \"((?:[^\"\\]|\\.)*)\"            # group 2: double-quoted value
          | '((?:[^'\\]|\\.)*)'               # group 3: single-quoted value
          | ([^\s,;}})\]]+)                   # group 4: unquoted value
        )
        """
    )


_SCRUB_PATTERN = _build_scrub_pattern()
# Bcrypt hash: starts with $2 followed by a/b/y, $cost$, then 53-char base64ish.
_BCRYPT_PATTERN = re.compile(r"\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}")


def scrub_log_message(message: str) -> str:
    """Replace likely-secret values in a log message with ``***``.

    Defense-in-depth — callers should never log secrets in the first place,
    but a future careless ``logger.debug(config.to_dict())`` must not expose
    bind passwords or API keys in the admin log viewer."""
    def _replace(match: re.Match) -> str:
        prefix = match.group(1)
        if match.group(2) is not None:
            return f'{prefix}"***"'
        if match.group(3) is not None:
            return f"{prefix}'***'"
        return f"{prefix}***"

    scrubbed = _SCRUB_PATTERN.sub(_replace, message)
    scrubbed = _BCRYPT_PATTERN.sub("$2b$**$***", scrubbed)
    return scrubbed


@dataclass
class LogEntry:
    """A captured log entry."""

    timestamp: datetime
    level: str
    logger_name: str
    message: str
    module: str = ""
    funcName: str = ""
    lineno: int = 0

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level,
            "logger_name": self.logger_name,
            "message": self.message,
            "module": self.module,
            "funcName": self.funcName,
            "lineno": self.lineno,
        }


class LogCaptureHandler(logging.Handler):
    """A logging handler that captures logs to an in-memory buffer.

    Stores the most recent N log entries in a thread-safe ring buffer.
    """

    def __init__(self, max_entries: int = 1000):
        super().__init__()
        self.max_entries = max_entries
        self._buffer: deque[LogEntry] = deque(maxlen=max_entries)
        self._lock = Lock()

    def emit(self, record: logging.LogRecord) -> None:
        """Capture a log record (with sensitive-value scrub applied)."""
        try:
            entry = LogEntry(
                timestamp=datetime.fromtimestamp(record.created, timezone.utc).replace(tzinfo=None),
                level=record.levelname,
                logger_name=record.name,
                message=scrub_log_message(self.format(record)),
                module=record.module,
                funcName=record.funcName,
                lineno=record.lineno,
            )
            with self._lock:
                self._buffer.append(entry)
        except Exception:
            self.handleError(record)

    def get_entries(
        self,
        level: Optional[str] = None,
        logger_name: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 100,
    ) -> list[LogEntry]:
        """Get log entries with optional filtering.

        Args:
            level: Filter by log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            logger_name: Filter by logger name prefix
            search: Search for text in message
            limit: Maximum number of entries to return

        Returns:
            List of matching log entries (most recent first)
        """
        with self._lock:
            entries = list(self._buffer)

        # Filter by level
        if level:
            level_upper = level.upper()
            entries = [e for e in entries if e.level == level_upper]

        # Filter by logger name prefix
        if logger_name:
            entries = [e for e in entries if e.logger_name.startswith(logger_name)]

        # Search in message
        if search:
            search_lower = search.lower()
            entries = [e for e in entries if search_lower in e.message.lower()]

        # Return most recent first, limited
        return list(reversed(entries))[:limit]

    def get_stats(self) -> dict:
        """Get log statistics."""
        with self._lock:
            entries = list(self._buffer)

        total = len(entries)
        by_level = {}
        for entry in entries:
            by_level[entry.level] = by_level.get(entry.level, 0) + 1

        return {
            "total": total,
            "max_entries": self.max_entries,
            "by_level": by_level,
        }

    def clear(self) -> None:
        """Clear all captured logs."""
        with self._lock:
            self._buffer.clear()


# Global log capture handler instance
_log_capture_handler: Optional[LogCaptureHandler] = None


def _not_audit_record(record: logging.LogRecord) -> bool:
    """Audit events are kept on the Audit trail page (/admin/audit), not in
    this clearable, 2000-entry buffer."""
    return record.name != "seqsetup.audit" and not record.name.startswith("seqsetup.audit.")


def get_log_capture_handler() -> LogCaptureHandler:
    """Get or create the global log capture handler."""
    global _log_capture_handler
    if _log_capture_handler is None:
        _log_capture_handler = LogCaptureHandler(max_entries=2000)
        _log_capture_handler.setLevel(logging.DEBUG)
        _log_capture_handler.setFormatter(
            logging.Formatter("%(message)s")
        )
        _log_capture_handler.addFilter(_not_audit_record)
    return _log_capture_handler


class ScrubbingFilter(logging.Filter):
    """Logging filter that pre-formats every record and scrubs likely secrets
    before a handler emits it.

    IMPORTANT — attach this to HANDLERS, not loggers. Python only consults a
    logger's own filters for records logged *directly* to that logger; records
    that PROPAGATE UP from child loggers (every module here uses
    ``logging.getLogger(__name__)`` → ``seqsetup.services.*``,
    ``seqsetup.audit``) reach ancestor *handlers* without re-running the
    ancestor logger's filters. A filter on the ``seqsetup`` logger therefore
    would NOT scrub those propagated records on an operator's root file/syslog
    handler. ``attach_scrubbing_filter_to_handler`` / ``setup_log_capture``
    install this on the handlers so it fires for propagated records too.

    The filter rewrites ``record.msg`` to the fully-formatted-then-scrubbed
    string and clears ``record.args`` so downstream handlers' ``format()``
    calls don't re-interpolate the original arguments (which could
    re-introduce the secret). It is idempotent — running twice on the same
    record (e.g. via filters on multiple handlers) re-scrubs an
    already-scrubbed string with no change.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            full = record.getMessage()
        except Exception:
            # Don't drop the record on a formatting bug; let the original
            # handler render it as-is (the in-memory viewer also still has
            # its emit-time scrub as a second line of defense).
            return True
        record.msg = scrub_log_message(full)
        record.args = ()
        return True


_SCRUBBING_FILTER: Optional[ScrubbingFilter] = None


def _get_scrubbing_filter() -> ScrubbingFilter:
    global _SCRUBBING_FILTER
    if _SCRUBBING_FILTER is None:
        _SCRUBBING_FILTER = ScrubbingFilter()
    return _SCRUBBING_FILTER


def attach_scrubbing_filter_to_handler(handler: logging.Handler) -> ScrubbingFilter:
    """Attach the global scrubbing filter to a HANDLER (idempotent).

    Handler-level filters run for every record the handler processes,
    including those propagated up from child loggers — which is why this,
    not a logger-level filter, is the mechanism that actually protects
    external file/stdout/syslog handlers. Operators who add their own root
    handler after startup should call this on it.
    """
    flt = _get_scrubbing_filter()
    if flt not in handler.filters:
        handler.addFilter(flt)
    return flt


def install_scrubbing_filter(logger_names: Optional[list[str]] = None) -> ScrubbingFilter:
    """Attach the scrubbing filter to handlers so secrets are redacted before
    they reach disk/syslog.

    Covers the handlers we control (the in-memory capture handler) plus any
    handlers already attached to the root logger at startup (the common case:
    an operator configured stdout/file logging via ``logging.basicConfig`` or
    the container runtime before importing the app). Also keeps a copy on the
    named loggers for records logged directly to them. Idempotent.

    NOTE: a logger-level filter does NOT fire for records propagated from
    child loggers; the handler-level attachment below is what makes the
    redaction effective for ``seqsetup.services.*`` / ``seqsetup.audit``.
    """
    flt = _get_scrubbing_filter()
    # Handler-level: the load-bearing attachment (covers propagated records).
    attach_scrubbing_filter_to_handler(get_log_capture_handler())
    for handler in list(logging.getLogger().handlers):
        attach_scrubbing_filter_to_handler(handler)
    # Logger-level: harmless extra coverage for records logged directly to
    # these loggers (not their children).
    targets = logger_names if logger_names is not None else ["seqsetup"]
    for name in targets:
        logger = logging.getLogger(name)
        if flt not in logger.filters:
            logger.addFilter(flt)
    return flt


def setup_log_capture(logger_names: Optional[list[str]] = None) -> LogCaptureHandler:
    """Set up log capture for specified loggers.

    Args:
        logger_names: List of logger names to capture. If None, captures root logger.

    Returns:
        The log capture handler
    """
    handler = get_log_capture_handler()

    if logger_names is None:
        # Capture from root logger
        logging.root.addHandler(handler)
    else:
        for name in logger_names:
            logger = logging.getLogger(name)
            logger.addHandler(handler)

    # Always also install the scrubbing filter so stdout / file handlers
    # see the same redacted message the in-memory viewer does. This filter
    # mutates the record in place — it must run before any handler emits.
    install_scrubbing_filter(logger_names)

    return handler


def get_captured_logs(
    level: Optional[str] = None,
    logger_name: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 100,
) -> list[LogEntry]:
    """Get captured log entries.

    Convenience function that uses the global handler.
    """
    handler = get_log_capture_handler()
    return handler.get_entries(level, logger_name, search, limit)


def get_log_stats() -> dict:
    """Get log statistics from the global handler."""
    handler = get_log_capture_handler()
    return handler.get_stats()


def clear_captured_logs() -> None:
    """Clear all captured logs."""
    handler = get_log_capture_handler()
    handler.clear()
