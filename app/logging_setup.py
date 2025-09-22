from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict

import structlog
from structlog.processors import TimeStamper
from opentelemetry import trace


def _add_trace_context(logger: Any, method_name: str, event_dict: Dict[str, Any]) -> Dict[str, Any]:
    span = trace.get_current_span()
    ctx = span.get_span_context()
    if ctx and ctx.is_valid:
        event_dict["trace_id"] = format(ctx.trace_id, "032x")
        event_dict["span_id"] = format(ctx.span_id, "016x")
    return event_dict


def setup_logging(level: str | int = "INFO") -> None:
    lvl = logging.getLevelName(level) if isinstance(level, str) else level
    timestamper = TimeStamper(fmt="iso", utc=True)

    processors = [
        structlog.processors.add_log_level,
        timestamper,
        _add_trace_context,
        structlog.processors.dict_tracebacks,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(serializer=None),
    ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(lvl if isinstance(lvl, int) else logging.INFO),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Silence noisy loggers optionally
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str):
    return structlog.get_logger(name)

