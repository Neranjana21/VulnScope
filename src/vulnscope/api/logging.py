"""Structured, allowlisted logging (T6, rule 6, PD-03, PD-10).

``log_event`` emits one JSON line per event and drops every field that is not in
``ALLOWED_FIELDS``: tokens, key hashes, headers, bodies, DSNs and foreign ids cannot be logged by
construction. Exceptions are never formatted here (callers pass the class name only).
"""
from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

LOGGER_NAME = "vulnscope.api"

ALLOWED_EVENTS = frozenset({
    "auth_failed", "role_denied", "cross_org_miss", "unhandled_exception",
    "app_role_check_failed", "revoke_unrecorded", "revoke_repair_failed", "scan_gate_error",
    "ledger_write_failed", "idempotency_conflict", "startup", "reconcile_done",
})
ALLOWED_FIELDS = frozenset({
    "event", "request_id", "route", "reason", "role", "api_key_id", "exc_class", "count",
    "suppressed", "engagement_id",
})
_MAX_VALUE = 128


def _clean(value: Any) -> Any:
    if isinstance(value, bool | int):
        return value
    text = str(value)
    text = "".join(ch for ch in text if ch.isprintable())
    return text[:_MAX_VALUE]


def log_event(event: str, **fields: Any) -> None:
    if event not in ALLOWED_EVENTS:
        raise ValueError("unknown log event")
    record: dict[str, Any] = {"event": event}
    for key, value in fields.items():
        if key in ALLOWED_FIELDS and key != "event" and value is not None:
            record[key] = _clean(value)
    logging.getLogger(LOGGER_NAME).warning(json.dumps(record, sort_keys=True))


class Coalescer:
    """At most ``per_second`` allowed calls per one-second bucket; the rest are counted."""

    def __init__(self, per_second: int = 10,
                 monotonic: Callable[[], float] | None = None) -> None:
        import time

        self._per = per_second
        self._mono = monotonic or time.monotonic
        self._bucket = int(self._mono())
        self._n = 0
        self._suppressed = 0

    def allow(self) -> bool:
        b = int(self._mono())
        if b != self._bucket:
            self._bucket, self._n = b, 0
        if self._n < self._per:
            self._n += 1
            return True
        self._suppressed += 1
        return False

    def take_suppressed(self) -> int:
        n, self._suppressed = self._suppressed, 0
        return n


class ScrubFilter(logging.Filter):
    """Drops exception and stack text and format arguments from foreign records (uvicorn,
    sqlalchemy): third-party exception text can carry statement parameters."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        record.args = ()
        return True
