"""Canonical JSON v1, the hash chain input format, and the total payload sanitizer.

Pure module: standard library only (``tests/unit/test_module_boundaries.py``). The wire format is
pinned by the golden vectors in ``tests/fixtures/ledger_golden`` (ADR-0003: changing it needs a new
ledger version, ADR-0005 records the byte-level choices).

Two paths, deliberately separate:

* STRICT (``canonical_json``, ``normalize_payload``, ``compute_record_hash``): rejects anything that
  is not plain JSON data (floats, bytes, subclasses, cycles, oversize). Used for hashing and for
  ``verify``. Budgets are checked BEFORE a structure is walked or copied.
* TOTAL (``sanitize_payload``): never raises for ANY input, lossy, bounded. ``append`` of every
  backend runs it first, so hostile target data can never make a decision unrecordable (rule 8),
  and a header-shaped secret is redacted before it is stored (rule 6). All data from a target is
  hostile (rule 9): no user-defined method is ever called, only exact type tests.

Depth: the payload root container counts as depth 1, so 16 nested containers are accepted and 17
are rejected (``MAX_DEPTH``). Header pairs: a two-item list or tuple ``[name, value]`` whose name
is on ``BLOCKED_KEYS`` (exact, case-insensitive) has its value redacted like a dict key would be,
at any depth; pairs with other names are preserved.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import islice
from typing import Final, cast

from vulnscope.ledger.errors import CanonicalizationError
from vulnscope.ledger.types import LedgerEntry

type JsonValue = None | bool | int | str | list[JsonValue] | dict[str, JsonValue]

LEDGER_SCHEMA_VERSION: Final = 1
MAX_PAYLOAD_BYTES: Final = 65_536
MAX_DEPTH: Final = 16
MAX_SEQ: Final = 2_147_483_646  # int4 column, chain_heads starts at -1
MAX_INT: Final = 2**53 - 1

_MAX_NODES: Final = 10_000
_MAX_STR: Final = 8_192
_DOC_SLACK: Final = 4_096  # entry documents and checkpoint messages wrap a payload

GENESIS_PREFIX: Final = b"vulnscope-ledger-v1:"

_CHAIN_RE: Final = re.compile(r"(engagement|intake):[A-Za-z0-9_.-]{1,200}")
_KIND_RE: Final = re.compile(r"[a-z][a-z0-9_.]{0,63}")
_ACTOR_RE: Final = re.compile(r"[A-Za-z0-9_.:-]{1,255}")
_HEX64_RE: Final = re.compile(r"[0-9a-f]{64}")
_TS_RE: Final = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{6})Z"
)


# ------------------------------------------------------------------------------ grammar
def _grammar_ok(rx: re.Pattern[str], s: object, max_len: int) -> bool:
    """``fullmatch`` only (a ``$`` anchor would accept a trailing newline), ASCII only."""
    return type(s) is str and len(s) <= max_len and s.isascii() and rx.fullmatch(s) is not None


def is_hash(s: object) -> bool:
    """True for exactly 64 lowercase hex characters."""
    return _grammar_ok(_HEX64_RE, s, 64)


def validate_chain_id(s: str) -> None:
    if not _grammar_ok(_CHAIN_RE, s, 211):
        raise CanonicalizationError("invalid chain_id")


def validate_kind(s: str) -> None:
    if not _grammar_ok(_KIND_RE, s, 64):
        raise CanonicalizationError("invalid kind")


def validate_actor(s: str) -> None:
    if not _grammar_ok(_ACTOR_RE, s, 255):
        raise CanonicalizationError("invalid actor")


def _validate_hash(s: object) -> None:
    if not is_hash(s):
        raise CanonicalizationError("invalid hash")


def _validate_seq(seq: object) -> None:
    if type(seq) is not int or seq < 0 or seq > MAX_SEQ:
        raise CanonicalizationError("invalid seq")


# ------------------------------------------------------------------------------ timestamps
def format_ts(ts: datetime) -> str:
    """``YYYY-MM-DDTHH:MM:SSZ`` plus always six fractional digits, UTC. Naive datetimes raise (D6).

    Formatted by hand from integer fields (``strftime`` does not zero-pad years < 1000 on glibc).
    """
    if not isinstance(ts, datetime) or ts.tzinfo is None or ts.utcoffset() is None:
        raise CanonicalizationError("timestamp must be a timezone-aware datetime")
    try:
        u = ts.astimezone(UTC)
    except (OverflowError, ValueError):
        raise CanonicalizationError("timestamp out of range") from None
    return (
        f"{u.year:04d}-{u.month:02d}-{u.day:02d}T{u.hour:02d}:{u.minute:02d}:{u.second:02d}"
        f".{u.microsecond:06d}Z"
    )


def parse_ts(text: str) -> datetime:
    """Inverse of ``format_ts``; accepts ONLY that exact shape (no offsets, no short forms)."""
    if type(text) is not str or len(text) != 27 or not text.isascii():
        raise CanonicalizationError("invalid timestamp")
    m = _TS_RE.fullmatch(text)
    if m is None:
        raise CanonicalizationError("invalid timestamp")
    year, month, day, hour, minute, second, micro = (int(g) for g in m.groups())
    try:
        return datetime(year, month, day, hour, minute, second, micro, tzinfo=UTC)
    except ValueError:
        raise CanonicalizationError("invalid timestamp") from None


def genesis_hash(chain_id: str) -> str:
    validate_chain_id(chain_id)
    return hashlib.sha256(GENESIS_PREFIX + chain_id.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------------------ strict path
class _SanitizedPayload(dict[str, JsonValue]):
    """Provenance marker: ONLY ``sanitize_payload`` builds one. Data from a target cannot construct
    a Python class, so ``type(x) is _SanitizedPayload`` means "already sanitized in-process"
    (ADR-0005: in-process code that can build one is already inside the trust boundary)."""

    __slots__ = ()


_DICT_TYPES: Final = (dict, _SanitizedPayload)
_SEQ_TYPES: Final = (list, tuple)
# (output container, source items, next index, depth) of one open container in ``_copy_strict``
type _StrictFrame = tuple[
    dict[str, JsonValue] | list[JsonValue], list[tuple[object, object]] | list[object], int, int
]


def _copy_strict(root: object, max_depth: int, max_chars: int) -> JsonValue:
    """Validate and deep-copy plain JSON data. Iterative. Depth, node count, string length and a
    running size budget are enforced BEFORE a container is walked or copied; exact types only (no
    subclass, no user-defined method is ever called). A cycle hits the depth cap at once."""
    nodes = 0
    chars = 0

    def leaf(x: object) -> JsonValue:
        nonlocal chars
        if x is None:
            return None
        t = type(x)
        if t is bool:
            return cast(bool, x)
        if t is int:
            if abs(cast(int, x)) > MAX_INT:
                raise CanonicalizationError("integer out of range")
            return cast(int, x)
        if t is str:
            s = cast(str, x)
            if len(s) > _MAX_STR:
                raise CanonicalizationError("string too long")
            chars += len(s)
            if chars > max_chars:
                raise CanonicalizationError("payload too large")
            return s
        raise CanonicalizationError("unsupported type")

    def open_container(
        x: object, depth: int
    ) -> tuple[dict[str, JsonValue] | list[JsonValue], list[tuple[object, object]] | list[object]]:
        nonlocal nodes
        if depth > max_depth:
            raise CanonicalizationError("nesting too deep")
        if type(x) in _DICT_TYPES:
            d = cast(dict[object, object], x)
            nodes += len(d)
            if nodes > _MAX_NODES:
                raise CanonicalizationError("too many nodes")
            return {}, list(d.items())
        s = cast(list[object], x)
        nodes += len(s)
        if nodes > _MAX_NODES:
            raise CanonicalizationError("too many nodes")
        return [], list(s)

    def is_container(x: object) -> bool:
        t = type(x)
        return t in _DICT_TYPES or t in _SEQ_TYPES

    if not is_container(root):
        return leaf(root)
    out_root, items0 = open_container(root, 1)
    stack: list[_StrictFrame] = [(out_root, items0, 0, 1)]
    while stack:
        out, items, idx, depth = stack.pop()
        while idx < len(items):
            item = items[idx]
            idx += 1
            if isinstance(out, dict):
                k, v = cast(tuple[object, object], item)
                if type(k) is not str or len(k) > _MAX_STR:
                    raise CanonicalizationError("invalid key")
                chars += len(k)
                if chars > max_chars:
                    raise CanonicalizationError("payload too large")
            else:
                k, v = None, item
            if is_container(v):
                child, child_items = open_container(v, depth + 1)
                stack.append((out, items, idx, depth))
                stack.append((child, child_items, 0, depth + 1))
                if isinstance(out, dict):
                    out[cast(str, k)] = child
                else:
                    out.append(child)
                break
            val = leaf(v)
            if isinstance(out, dict):
                out[cast(str, k)] = val
            else:
                out.append(val)
    return out_root


def dumps_validated(value: JsonValue) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (UnicodeEncodeError, ValueError, TypeError, RecursionError):
        raise CanonicalizationError("value cannot be serialised") from None


def canonical_json(value: object) -> bytes:
    """STRICT canonical JSON v1: sorted keys (code point order, NOT RFC 8785), compact separators,
    raw UTF-8, no floats. Raises ``CanonicalizationError`` for anything else."""
    copy = _copy_strict(value, MAX_DEPTH + 1, MAX_PAYLOAD_BYTES + _DOC_SLACK)
    data = dumps_validated(copy)
    if len(data) > MAX_PAYLOAD_BYTES + _DOC_SLACK:
        raise CanonicalizationError("value too large")
    return data


def normalize_payload(payload: Mapping[str, object]) -> dict[str, JsonValue]:
    """Validated deep copy of a payload (tuples become lists). Raises ``CanonicalizationError``."""
    if type(payload) not in _DICT_TYPES:
        raise CanonicalizationError("payload must be a dict")
    copy = _copy_strict(payload, MAX_DEPTH, MAX_PAYLOAD_BYTES)
    if len(dumps_validated(copy)) > MAX_PAYLOAD_BYTES:
        raise CanonicalizationError("payload too large")
    return cast(dict[str, JsonValue], copy)


# ------------------------------------------------------------------------------ entry hashing
def entry_document(
    *,
    schema_version: int,
    chain_id: str,
    seq: int,
    kind: str,
    actor: str,
    payload: Mapping[str, object],
    ts: datetime,
    prev_hash: str,
) -> dict[str, JsonValue]:
    """The object that is hashed (the contract's entry without ``record_hash``)."""
    if type(schema_version) is not int or schema_version != LEDGER_SCHEMA_VERSION:
        raise CanonicalizationError("unsupported schema_version")
    validate_chain_id(chain_id)
    validate_kind(kind)
    validate_actor(actor)
    _validate_seq(seq)
    _validate_hash(prev_hash)
    return {
        "actor": actor,
        "chain_id": chain_id,
        "kind": kind,
        "payload": normalize_payload(payload),
        "prev_hash": prev_hash,
        "schema_version": schema_version,
        "seq": seq,
        "ts": format_ts(ts),
    }


def compute_record_hash(
    *,
    schema_version: int,
    chain_id: str,
    seq: int,
    kind: str,
    actor: str,
    payload: Mapping[str, object],
    ts: datetime,
    prev_hash: str,
) -> str:
    """``hex(SHA-256(ASCII(prev_hash) + canonical_json(entry_document)))`` (ADR-0005 (b)): ``||`` is
    plain concatenation of the 64 hex ASCII bytes and the canonical bytes, no separator."""
    doc = entry_document(
        schema_version=schema_version,
        chain_id=chain_id,
        seq=seq,
        kind=kind,
        actor=actor,
        payload=payload,
        ts=ts,
        prev_hash=prev_hash,
    )
    return hashlib.sha256(prev_hash.encode("ascii") + dumps_validated(doc)).hexdigest()


def entry_record_hash(entry: LedgerEntry) -> str:
    """Recompute an entry's hash from its fields, ignoring ``entry.record_hash``."""
    return compute_record_hash(
        schema_version=entry.schema_version,
        chain_id=entry.chain_id,
        seq=entry.seq,
        kind=entry.kind,
        actor=entry.actor,
        payload=entry.payload,
        ts=entry.ts,
        prev_hash=entry.prev_hash,
    )


# ------------------------------------------------------------------------------ total sanitizer
BLOCKED_KEYS: Final = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "password",
        "passwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "credential",
        "client_secret",
    }
)
REDACTED: Final = "[redacted]"

SAN_MAX_DEPTH: Final = 8
SAN_MAX_ITEMS: Final = 64  # keys per dict, items per list (top level: see TOP_KEYS_MAX)
SAN_MAX_NODES: Final = 2_000
STR_CAP: Final = 2_048
KEY_CAP: Final = 128
OUTPUT_BUDGET: Final = 32 * 1024
RECORDS_RESERVE: Final = 4 * 1024
TOP_KEYS_MAX: Final = 64
_TOP_SNAPSHOT: Final = 1_024
_SCALAR_STR_MAX: Final = 256
_SCALAR_BUDGET: Final = 16 * 1024
_MAX_RECORDS: Final = 16
_PATH_CAP: Final = 128
_HASH_PREFIX: Final = 1 << 20
_NODE_COST: Final = 6

_CTRL_TABLE: Final = {i: f"\\x{i:02x}" for i in (*range(32), 127)}


def _escape(s: str) -> str:
    """C0 controls and DEL become literal ``\\xNN`` text, lone surrogates ``\\uXXXX`` text.
    The output contains neither, so escaping is idempotent."""
    if s.isascii():
        return s if s.isprintable() else s.translate(_CTRL_TABLE)
    t = s.translate(_CTRL_TABLE)
    try:
        t.encode("utf-8")
    except UnicodeEncodeError:
        return t.encode("utf-8", "backslashreplace").decode("utf-8")
    return t


def _clean_str(s: str) -> tuple[str, str | None]:
    """Escape then cap at ``STR_CAP`` characters INCLUDING the suffix (idempotent, R2.2 R1-1).
    The input is sliced first, so a 100 MB string costs O(cap)."""
    n = len(s)
    pre = s[:STR_CAP]
    esc = _escape(pre)
    if n <= STR_CAP and len(esc) <= STR_CAP:
        return esc, ("escaped" if esc != pre else None)
    suffix = f"...[truncated:{n}]"
    return esc[: STR_CAP - len(suffix)] + suffix, "truncated"


def _clean_key(k: object, index: int) -> str:
    if type(k) is not str:
        return f"[key:{index}]"
    return _escape(k[:KEY_CAP])[:KEY_CAP]


def _unique_key(base: str, used: set[str]) -> str:
    if base not in used:
        used.add(base)
        return base
    n = 1
    while True:
        suffix = f"~{n}"
        cand = base[: KEY_CAP - len(suffix)] + suffix
        if cand not in used:
            used.add(cand)
            return cand
        n += 1


def _is_blocked(k: object) -> bool:
    return type(k) is str and len(k) <= 32 and k.lower() in BLOCKED_KEYS


def _jbytes(text: str) -> int:
    """Bytes of the canonical JSON encoding of an (already escaped) string."""
    return len(text.encode("utf-8")) + text.count('"') + text.count("\\") + 2


def _is_scalar_value(v: object) -> bool:
    if v is None:
        return True
    t = type(v)
    return t is bool or t is int or (t is str and len(cast(str, v)) <= _SCALAR_STR_MAX)


class _Frame:
    __slots__ = ("items", "i", "out", "path", "depth", "redact", "used", "cid", "pair")

    def __init__(
        self,
        items: tuple[object, ...],
        out: dict[str, JsonValue] | list[JsonValue],
        path: str,
        depth: int,
        redact: bool,
        cid: int,
    ) -> None:
        self.items = items
        self.i = 0
        self.out = out
        self.path = path
        self.depth = depth
        self.redact = redact
        self.used: set[str] = set()
        self.cid = cid
        self.pair = False  # a [blocked-name, value] header pair: the value is redacted


class _Dropped:
    """Sentinel: the value was not emitted."""


_DROP: Final = _Dropped()


class _Sanitizer:
    """One run of the total sanitizer. Holds budgets and the alteration records."""

    def __init__(self) -> None:
        self.nodes = 0
        self.remaining = 0
        self.records: list[dict[str, JsonValue]] = []
        self.open_ids: set[int] = set()
        self.exhausted = False

    # -- records
    def rec(self, path: str, reason: str, **extra: JsonValue) -> None:
        if len(self.records) >= _MAX_RECORDS:
            return
        record: dict[str, JsonValue] = {"path": path[:_PATH_CAP], "reason": reason}
        record.update(extra)
        self.records.append(record)

    # -- budget
    def spend(self, cost: int) -> bool:
        if cost > self.remaining:
            return False
        self.remaining -= cost
        return True

    # -- leaves
    def str_leaf(self, s: str, path: str, redact: bool) -> str | _Dropped:
        if redact:
            if not self.spend(_jbytes(REDACTED) + _NODE_COST):
                return _DROP
            self.rec(path, "redacted")
            return REDACTED
        text, reason = _clean_str(s)
        cost = _jbytes(text) + _NODE_COST
        if cost > self.remaining:
            avail = self.remaining - _NODE_COST - 2
            if avail <= 0:
                return _DROP
            raw = text.encode("utf-8")
            limit = avail
            while True:
                text = raw[:limit].decode("utf-8", "ignore")
                cost = _jbytes(text) + _NODE_COST
                if cost <= self.remaining or limit <= 0:
                    break
                limit -= cost - self.remaining
            if cost > self.remaining:
                return _DROP
            reason = "clamped"
        self.remaining -= cost
        if reason is not None:
            extra: dict[str, JsonValue] = {"orig_len": len(s)}
            if len(s) > STR_CAP:
                prefix = s[:_HASH_PREFIX].encode("utf-8", "surrogatepass")
                name = "sha256" if len(s) <= _HASH_PREFIX else "sha256_prefix_1mib"
                extra[name] = hashlib.sha256(prefix).hexdigest()
            self.rec(path, reason, **extra)
        return text

    def marker(self, text: str, path: str) -> str | _Dropped:
        if not self.spend(_jbytes(text) + _NODE_COST):
            return _DROP
        self.rec(path, "marker")
        return text

    def scalar_or_marker(self, v: object, path: str, redact: bool) -> JsonValue | _Dropped:
        """Convert a non-container value. Exact type tests only."""
        if v is None or type(v) is bool:
            if not self.spend(_NODE_COST + 5):
                return _DROP
            return v
        t = type(v)
        if t is int:
            n = cast(int, v)
            if abs(n) > MAX_INT:
                return self.marker("[int_range]", path)
            if not self.spend(_NODE_COST + len(str(n))):
                return _DROP
            return n
        if t is str:
            return self.str_leaf(cast(str, v), path, redact)
        if t is float:
            return self.marker("[float]", path)
        return self.marker("[unsupported]", path)

    def make_key(self, k: object, index: int, used: set[str], parent: str) -> str:
        """Escape, cap and de-duplicate a dict key; any alteration is recorded."""
        base = _clean_key(k, index)
        reason: str | None = None
        if type(k) is not str:
            reason = "marker"
        elif base != k:
            reason = "truncated" if len(k) > KEY_CAP else "escaped"
        key = _unique_key(base, used)
        if reason is None and key != base:
            reason = "escaped"
        if reason is not None:
            self.rec(f"{parent}.{key}", reason)
        return key

    # -- containers
    def open_frame(
        self, v: object, path: str, redact: bool, depth: int, limit: int = SAN_MAX_ITEMS
    ) -> _Frame | str | _Dropped:
        t = type(v)
        if depth > SAN_MAX_DEPTH:
            return self.marker("[depth]", path)
        cid = id(v)
        if cid in self.open_ids:
            return self.marker("[cycle]", path)
        items: tuple[object, ...]
        total: int
        out: dict[str, JsonValue] | list[JsonValue]
        if t is dict or t is _SanitizedPayload:
            d = cast(dict[object, object], v)
            try:
                total = len(d)
                items = tuple(islice(d.items(), limit + 1))
            except RuntimeError:  # mutated by another thread mid-snapshot
                return self.marker("[unstable]", path)
            out = {}
        else:
            s = cast(list[object], v)
            try:
                total = len(s)
                items = tuple(s[: limit + 1])
            except RuntimeError:
                return self.marker("[unstable]", path)
            out = []
        if not self.spend(_NODE_COST):
            return _DROP
        if total > limit:
            items = items[:limit]
            self.rec(path, "dropped", count=total - limit)
        self.open_ids.add(cid)
        frame = _Frame(items, out, path, depth, redact, cid)
        frame.pair = (
            not isinstance(out, dict) and total == 2 and len(items) == 2 and _is_blocked(items[0])
        )
        return frame

    def convert_child(
        self, v: object, path: str, redact: bool, depth: int
    ) -> JsonValue | _Frame | _Dropped:
        self.nodes += 1
        if self.nodes > SAN_MAX_NODES:
            self.exhausted = True
            return _DROP
        t = type(v)
        if t is dict or t is list or t is tuple or t is _SanitizedPayload:
            return self.open_frame(v, path, redact, depth)
        return self.scalar_or_marker(v, path, redact)

    def run(self, first: _Frame) -> JsonValue:
        """Iterative traversal of one subtree (explicit stack: no recursion on hostile depth)."""
        stack: list[_Frame] = [first]
        while stack:
            f = stack[-1]
            if self.exhausted or f.i >= len(f.items):
                stack.pop()
                self.open_ids.discard(f.cid)
                continue
            item = f.items[f.i]
            index = f.i
            f.i += 1
            if isinstance(f.out, dict):
                k, v = cast(tuple[object, object], item)
                key = self.make_key(k, index, f.used, f.path)
                child_path = f"{f.path}.{key}"[:_PATH_CAP]
                if not self.spend(_jbytes(key)):
                    self.rec(f.path, "dropped", count=len(f.items) - index)
                    f.i = len(f.items)
                    continue
                redact = f.redact or _is_blocked(k)
            else:
                v = item
                key = ""
                child_path = f"{f.path}[{index}]"[:_PATH_CAP]
                redact = f.redact or (f.pair and index == 1)
            res = self.convert_child(v, child_path, redact, f.depth + 1)
            if isinstance(res, _Dropped):
                self.rec(f.path, "dropped", count=len(f.items) - index)
                f.i = len(f.items)
                continue
            if isinstance(res, _Frame):
                if isinstance(f.out, dict):
                    f.out[key] = res.out
                else:
                    f.out.append(res.out)
                stack.append(res)
                continue
            if isinstance(f.out, dict):
                f.out[key] = res
            else:
                f.out.append(res)
        return first.out

    # -- top level
    def top(self, source: dict[object, object], *, wrapped: bool) -> _SanitizedPayload:
        try:
            total = len(source)
            items = tuple(islice(source.items(), _TOP_SNAPSHOT))
        except RuntimeError:
            out = _SanitizedPayload()
            out["value" if wrapped else "payload"] = "[unstable]"
            self.rec("$", "marker")
            return self._finish(out)
        out = _SanitizedPayload()
        used: set[str] = set()
        keys_left = TOP_KEYS_MAX
        considered: list[tuple[int, object, object]] = []
        for index, (k, v) in enumerate(items):
            if not wrapped and type(k) is str and k in ("sanitized", "sanitization"):
                self.rec(f"$.{k}", "dropped")  # no spoofing of the alteration record
                continue
            considered.append((index, k, v))
        if total > len(items):
            self.rec("$", "dropped", count=total - len(items))
        scalars = [c for c in considered if _is_scalar_value(c[2])]
        others = [c for c in considered if not _is_scalar_value(c[2])]

        # pass 1: scalar values always get served first (rule_id, allowed, target, ...)
        self.remaining = _SCALAR_BUDGET
        for index, k, v in scalars:
            if keys_left <= 0:
                self.rec("$", "dropped", count=1)
                continue
            key = self.make_key(k, index, used, "$")
            if not self.spend(_jbytes(key)):
                self.rec("$", "dropped", count=1)
                continue
            self.nodes += 1
            res = self.scalar_or_marker(v, f"$.{key}"[:_PATH_CAP], _is_blocked(k))
            if isinstance(res, _Dropped):
                self.rec("$", "dropped", count=1)
                used.discard(key)
                continue
            out[key] = res
            keys_left -= 1
        scalar_used = _SCALAR_BUDGET - self.remaining

        # pass 2: every other value in caller order with its own share of the budget (R1-2)
        content = OUTPUT_BUDGET - RECORDS_RESERVE - scalar_used
        share = max(256, content // max(1, min(len(others), keys_left)))
        carry = 0
        for index, k, v in others:
            if keys_left <= 0 or self.exhausted:
                self.rec("$", "dropped", count=1)
                continue
            key = self.make_key(k, index, used, "$")
            allowance = share + carry
            self.remaining = allowance
            if not self.spend(_jbytes(key)):
                self.rec("$", "dropped", count=1)
                used.discard(key)
                continue
            res2 = self.convert_child(v, f"$.{key}"[:_PATH_CAP], _is_blocked(k), 2)
            if isinstance(res2, _Dropped):
                self.rec("$", "dropped", count=1)
                used.discard(key)
                carry = 0
                continue
            if isinstance(res2, _Frame):
                out[key] = self.run(res2)
            else:
                out[key] = res2
            carry = max(0, self.remaining)
            keys_left -= 1
        return self._finish(out)

    def _finish(self, out: _SanitizedPayload) -> _SanitizedPayload:
        if self.records:
            out["sanitized"] = True
            out["sanitization"] = cast(JsonValue, self.records)
        return out


def _fb_text(s: str, cap: int) -> str:
    """Escape for the fallback path. Independent of the main helpers on purpose."""
    t = s[:cap].translate(_CTRL_TABLE)
    try:
        t.encode("utf-8")
    except UnicodeEncodeError:
        t = t.encode("utf-8", "backslashreplace").decode("utf-8")
    return t[:cap]


def _fallback(obj: object) -> _SanitizedPayload:
    """Last resort: fixed marker plus the first 16 scalar top-level items copied exception-free."""
    out = _SanitizedPayload()
    try:
        if type(obj) is dict or type(obj) is _SanitizedPayload:
            src = cast(dict[object, object], obj)
            for k, v in islice(src.items(), 16):
                if type(k) is not str or k in ("sanitized", "sanitization"):
                    continue
                key = _fb_text(k, 64)
                if v is None or type(v) is bool:
                    out[key] = v
                elif type(v) is int:
                    out[key] = v if abs(v) <= MAX_INT else "[int_range]"
                elif type(v) is str:
                    out[key] = _fb_text(v, _SCALAR_STR_MAX)
    except Exception:  # noqa: BLE001 - the fallback must not fail; plain marker below
        out = _SanitizedPayload()
    out["sanitized"] = True
    out["sanitization"] = [{"reason": "fallback"}]
    return out


def _sanitize(obj: object) -> _SanitizedPayload:
    san = _Sanitizer()
    if type(obj) is dict or type(obj) is _SanitizedPayload:
        return san.top(cast(dict[object, object], obj), wrapped=False)
    san.rec("$", "marker")
    return san.top({"value": obj}, wrapped=True)


def sanitize_payload(obj: object) -> dict[str, JsonValue]:
    """TOTAL: never raises for any input (only ``BaseException`` such as ``KeyboardInterrupt`` or
    ``CancelledError`` passes through). Lossy and bounded; output always passes the strict path.

    Provenance by type: an instance this function already returned (and that still passes the
    strict check) is returned unchanged, so a payload sanitized by a caller equals what is stored.
    """
    try:
        if type(obj) is _SanitizedPayload:
            try:
                normalize_payload(obj)
            except CanonicalizationError:
                pass
            else:
                return obj
        out = _sanitize(obj)
        normalize_payload(out)  # final strict re-check
        return out
    except Exception:  # noqa: BLE001 - totality is the contract (rule 8)
        return _fallback(obj)


def prepare_payload(payload: object) -> dict[str, JsonValue]:
    """Sanitize then normalise: the plain-dict deep copy every backend stores and returns."""
    clean = sanitize_payload(payload)
    try:
        return normalize_payload(clean)
    except CanonicalizationError:
        return normalize_payload(_fallback(payload))


# ------------------------------------------------------------------------------ append input
@dataclass(frozen=True)
class PreparedEntry:
    """Validated, sanitized inputs of one ``append`` (identical for every backend)."""

    chain_id: str
    kind: str
    actor: str
    payload: dict[str, JsonValue]
    ts: datetime  # aware, UTC


def prepare_append(
    chain_id: str, kind: str, actor: str, payload: Mapping[str, object], ts: datetime
) -> PreparedEntry:
    """Validate identifiers (raises ``CanonicalizationError``) and sanitize the payload (never
    raises). Runs before any lock or connection is taken."""
    validate_chain_id(chain_id)
    validate_kind(kind)
    validate_actor(actor)
    format_ts(ts)  # naive or out-of-range timestamps raise
    return PreparedEntry(
        chain_id=chain_id,
        kind=kind,
        actor=actor,
        payload=prepare_payload(payload),
        ts=ts.astimezone(UTC),
    )
