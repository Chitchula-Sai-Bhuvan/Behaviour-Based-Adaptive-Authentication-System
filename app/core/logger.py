"""
core/logger.py
──────────────
Structured, production-ready logging setup.

All application loggers route through the root logger configured here.
In production, swap the StreamHandler for a file handler or a log
aggregator handler (Datadog, CloudWatch, Loki, etc.).

Log levels:
  DEBUG   — detailed trace (development only)
  INFO    — normal operations (login, MFA, evaluations)
  WARNING — unexpected but non-critical (Redis unavailable, unknown device)
  ERROR   — failures requiring investigation (DB write failure, etc.)
  CRITICAL — service-level failures
"""

import logging
import json
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """
    Format every log record as a single-line JSON object.
    This makes logs machine-parseable for SIEM ingestion.
    """

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Attach any extra fields passed via the `extra` kwarg
        for key, value in record.__dict__.items():
            if key not in (
                "args", "asctime", "created", "exc_info", "exc_text",
                "filename", "funcName", "id", "levelname", "levelno",
                "lineno", "module", "msecs", "message", "msg", "name",
                "pathname", "process", "processName", "relativeCreated",
                "stack_info", "thread", "threadName",
            ):
                log_obj[key] = value
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)


def configure_logging(debug: bool = False) -> None:
    """
    Call once at application startup (in main.py lifespan).
    Sets the root logger level and attaches a JSON-formatted console handler.
    """
    level = logging.DEBUG if debug else logging.INFO
    root = logging.getLogger()
    root.setLevel(level)

    # Remove any handlers already attached (e.g. from uvicorn)
    root.handlers.clear()

    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    root.addHandler(handler)

    # Quieten noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Convenience wrapper — call this in every module instead of logging.getLogger."""
    return logging.getLogger(name)
