# ruff: noqa: E501
"""Secret handling for the stress/integration DB tests (GR-STR-31). R1.

Two layers, because a repr that is "safe by construction" cannot protect values the tests do not
own (plain-str DSN fixtures in implementer files, exception messages, subprocess output):

1. ``Secret``: a ``str`` subclass whose ``repr``/``str``/``format`` are the fixed text
   ``Secret(<redacted>)``. It stays a real ``str`` for C-level consumers (``os.environ``,
   ``monkeypatch.setenv``, asyncpg/SQLAlchemy URL parsing), and ``reveal()`` returns the plain
   value for code that must build a connection. Derived strings (``+``, slicing) are plain str:
   the kit helpers re-wrap what they build.
2. ``scrub()``: a backstop applied by the plugin to EVERY test report before the terminal and the
   JUnit writer see it. It redacts URL userinfo by pattern (scheme://user:ANYTHING@), the exact
   known passwords and URLs, any run of >= 8 characters of a known secret (so pytest's repr
   elision, which can leave a fragment next to ``...``, is covered), and the text around an
   ellipsis that borders an ``@``. Fragments shorter than 8 characters are not guaranteed.
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterable
from urllib.parse import unquote, urlsplit

REDACTED = "***REDACTED***"
MIN_FRAGMENT = 8
_EXTRA: set[str] = set()


class Secret(str):
    """A string that never prints itself."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "Secret(<redacted>)"

    def __str__(self) -> str:
        return "Secret(<redacted>)"

    def __format__(self, spec: str) -> str:
        return "Secret(<redacted>)"


def reveal(value: str) -> str:
    """The plain value (a new, exact ``str``), for building connections and environments only."""
    return str.__str__(value) if type(value) is not str else value


def register_secret(value: str) -> None:
    """Make the backstop know a runtime-generated secret (e.g. a scratch role password)."""
    plain = reveal(value)
    if plain:
        _EXTRA.add(plain)


def _password_of(url: str) -> list[str]:
    try:
        pw = urlsplit(url).password
    except ValueError:
        return []
    return [p for p in (pw, unquote(pw) if pw else None) if p]


def _collect() -> tuple[set[str], set[str]]:
    passwords: set[str] = set(_EXTRA)
    urls: set[str] = set()
    for name, value in os.environ.items():
        if not value:
            continue
        if name.endswith("_DATABASE_URL"):
            urls.add(value)
            passwords.update(_password_of(value))
        elif name.endswith("PASSWORD"):
            passwords.add(value)
    return passwords, urls


def known_secrets() -> list[str]:
    """Passwords and whole URLs the process knows, read from the environment at call time."""
    passwords, urls = _collect()
    return sorted((s for s in passwords | urls if len(s) >= 4), key=len, reverse=True)


def known_passwords() -> list[str]:
    """Passwords only: fragment matching must never use a whole URL (it would eat host names)."""
    return sorted((s for s in _collect()[0] if len(s) >= 4), key=len, reverse=True)


_USERINFO_FULL = re.compile(r"(://[^\s:/@'\"<>]+:)[^\s@'\"/<>]*@")
_USERINFO_ELIDED = re.compile(r"(://[^\s:/@'\"<>]+:)[^\s@'\"/<>]*\.\.\.[^\s@'\"/<>]*@?")
_ELLIPSIS_BEFORE_AT = re.compile(r"(\.\.\.)[^\s@'\"/<>.]{1,128}@")
_BARE_USERINFO = re.compile(r"(?<![\w/])([A-Za-z0-9_]{3,}:)[^\s@'\"/:<>]{6,}@(?=127\.0\.0\.1|localhost|[\w-]+\.[\w.-]+[:/])")


def _scrub_fragments(text: str, secret: str) -> str:
    if len(secret) < MIN_FRAGMENT:
        return text
    windows = {secret[i : i + MIN_FRAGMENT] for i in range(len(secret) - MIN_FRAGMENT + 1)}
    rx = re.compile("|".join(re.escape(w) for w in sorted(windows)))
    out: list[str] = []
    pos = 0
    for m in rx.finditer(text):
        start = m.start()
        if start < pos:
            continue
        end = m.end()
        while end < len(text) and text[start : end + 1] in secret:
            end += 1
        out.append(text[pos:start])
        out.append(REDACTED)
        pos = end
    out.append(text[pos:])
    return "".join(out)


def scrub(text: str, extra: Iterable[str] = ()) -> str:
    """Return ``text`` with every secret, URL userinfo and >= 8-char secret fragment redacted."""
    if not text:
        return text
    secrets = known_secrets() + [reveal(e) for e in extra if e]
    for s in sorted(set(secrets), key=len, reverse=True):
        if s in text:
            text = text.replace(s, REDACTED)
    for s in known_passwords() + [reveal(e) for e in extra if e]:
        text = _scrub_fragments(text, s)
    text = _USERINFO_FULL.sub(rf"\1{REDACTED}@", text)
    text = _USERINFO_ELIDED.sub(rf"\1{REDACTED}...", text)
    text = _ELLIPSIS_BEFORE_AT.sub(rf"\1{REDACTED}@", text)
    text = _BARE_USERINFO.sub(rf"\1{REDACTED}", text)
    return text
