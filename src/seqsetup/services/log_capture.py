"""In-memory log capture for admin log viewer."""

import logging
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Optional


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
        """Capture a log record."""
        try:
            entry = LogEntry(
                timestamp=datetime.fromtimestamp(record.created),
                level=record.levelname,
                logger_name=record.name,
                message=self.format(record),
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


def get_log_capture_handler() -> LogCaptureHandler:
    """Get or create the global log capture handler."""
    global _log_capture_handler
    if _log_capture_handler is None:
        _log_capture_handler = LogCaptureHandler(max_entries=2000)
        _log_capture_handler.setLevel(logging.DEBUG)
        _log_capture_handler.setFormatter(
            logging.Formatter("%(message)s")
        )
    return _log_capture_handler


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
