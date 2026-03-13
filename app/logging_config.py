"""Structured JSON logging configuration for GCP Cloud Logging."""

import json
import logging
import sys
from datetime import datetime
from typing import Any, Optional


class CloudLoggingFormatter(logging.Formatter):
    """Format logs as JSON for GCP Cloud Logging with structured fields."""

    def format(self, record: logging.LogRecord) -> str:
        """Format record as JSON with scan_id and trace context."""
        log_obj = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "source": {
                "file": record.filename,
                "function": record.funcName,
                "line": record.lineno,
            },
        }

        # Add scan_id from context if available
        if hasattr(record, "scan_id") and record.scan_id:  # type: ignore
            log_obj["scan_id"] = record.scan_id  # type: ignore

        # Add trace context for Cloud Trace integration
        if hasattr(record, "trace_id") and record.trace_id:  # type: ignore
            log_obj["trace_id"] = record.trace_id  # type: ignore

        # Include exception traceback if present
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        # Include custom fields
        for key, value in record.__dict__.items():
            if key not in [
                "name",
                "msg",
                "args",
                "created",
                "filename",
                "funcName",
                "levelname",
                "levelno",
                "lineno",
                "module",
                "msecs",
                "message",
                "pathname",
                "process",
                "processName",
                "relativeCreated",
                "thread",
                "threadName",
                "exc_info",
                "exc_text",
                "stack_info",
                "scan_id",
                "trace_id",
            ]:
                try:
                    # Only include JSON-serializable values
                    json.dumps(value)
                    log_obj[key] = value
                except (TypeError, ValueError):
                    log_obj[key] = str(value)

        return json.dumps(log_obj)


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure structured JSON logging."""
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add JSON formatter to stdout
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(CloudLoggingFormatter())
    root_logger.addHandler(handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a named logger instance."""
    return logging.getLogger(name)


class LogContext:
    """Context manager for adding scan_id and trace_id to logs."""

    def __init__(
        self, logger: logging.Logger, scan_id: str, trace_id: Optional[str] = None
    ):
        self.logger = logger
        self.scan_id = scan_id
        self.trace_id = trace_id
        self._filters = []

    def __enter__(self) -> "LogContext":
        """Add context to all handlers."""

        class ContextFilter(logging.Filter):
            """Filter to inject scan_id and trace_id into log records."""

            def __init__(self, scan_id: str, trace_id: Optional[str]):
                super().__init__()
                self.scan_id = scan_id
                self.trace_id = trace_id

            def filter(self, record: logging.LogRecord) -> bool:
                record.scan_id = self.scan_id  # type: ignore
                record.trace_id = self.trace_id  # type: ignore
                return True

        # Create single filter instance with context
        filter_obj = ContextFilter(self.scan_id, self.trace_id)

        # Add filter to all handlers
        for handler in self.logger.handlers:
            handler.addFilter(filter_obj)
            self._filters.append((handler, filter_obj))

        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Remove context filters."""
        for handler, filter_obj in self._filters:
            handler.removeFilter(filter_obj)
        self._filters.clear()
