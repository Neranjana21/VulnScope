"""Shared building blocks for every schema in this package: the
``schema_version`` literal, a UUIDv7 helper, and an ISO8601-UTC datetime
type that rejects naive datetimes (docs/io-contracts.md "Conventions":
"naive datetimes are rejected", reason code ``WINDOW_NAIVE_DATETIME``).
"""
from __future__ import annotations

import secrets
import time
from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict

SchemaVersion1 = Literal[1]


def _reject_naive_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError(
            "naive datetime is not allowed; timestamps must be timezone-aware "
            "UTC (WINDOW_NAIVE_DATETIME)"
        )
    return value


UtcDateTime = Annotated[datetime, AfterValidator(_reject_naive_datetime)]


class StrictModel(BaseModel):
    """Base for every request/response schema: unknown fields are
    rejected (``UNKNOWN_FIELD``, docs/io-contracts.md)."""

    model_config = ConfigDict(extra="forbid")


def uuid7() -> str:
    """Generate a UUIDv7 string (RFC 9562): a 48-bit big-endian Unix-ms
    timestamp, the version/variant bits, and 74 bits of randomness.

    No third-party dependency is pulled in for this -- Python 3.12 has no
    builtin ``uuid.uuid7()`` (that lands in 3.14).
    """
    unix_ms = int(time.time() * 1000)
    rand = secrets.token_bytes(10)
    rand_a = int.from_bytes(rand[0:2], "big") & 0x0FFF  # 12 bits
    rand_b = int.from_bytes(rand[2:10], "big") & 0x3FFFFFFFFFFFFFFF  # 62 bits

    value = (unix_ms & 0xFFFFFFFFFFFF) << 80
    value |= 0x7 << 76  # version nibble = 0b0111
    value |= rand_a << 64
    value |= 0b10 << 62  # variant bits (RFC 4122)
    value |= rand_b

    hex_str = f"{value:032x}"
    return f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"
