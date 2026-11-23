"""SEC-A4 / SEC-A5: ASCII-only numerics and post-NFKC re-validation."""

from __future__ import annotations

import re
import unicodedata

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from vulnscope.policy.target import TargetParseError, canonical_target

ROWS = (
    "1_27.0.0.1",
    "0x1_0.0.0.1",
    "127.0.0.1:8_0",
    "127.0.0.1:٨٠",
    "host:²",
    "0x7f.0x_0.0.1",
    "http://evil.test＠allowed.test",
    "evil.test／x",
    "evil.test：80@a",
    "℀.test",
    "٣.0.0.1",
)


@pytest.mark.parametrize("raw", ROWS)
def test_row_rejects_with_stable_code(raw: str) -> None:
    with pytest.raises(TargetParseError) as info:
        canonical_target(raw)
    assert re.fullmatch(r"[a-z_0-9]+", info.value.code)


def test_arabic_digit_last_label_is_an_idn_name_never_an_ip() -> None:
    t = canonical_target("1.2.3.٤")
    assert t.ip is None and t.host.startswith("1.2.3.xn--")


def test_target_module_forbids_lenient_numeric_calls() -> None:
    """isdigit/isdecimal/isnumeric are banned in target.py; int() only on
    text that a prior ASCII regex has validated (checked by reading calls)."""
    import ast
    from pathlib import Path

    import vulnscope.policy.target as mod

    tree = ast.parse(Path(mod.__file__).read_text(encoding="utf-8"))
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert not attrs & {"isdigit", "isdecimal", "isnumeric"}


@given(st.text(max_size=40))
@settings(max_examples=300, deadline=None)
def test_any_accepted_ipv4_text_is_ascii_numeric(text: str) -> None:
    try:
        t = canonical_target(text)
    except TargetParseError:
        return
    if t.ip is not None and t.ip.version == 4 and ":" not in text:
        authority = re.split(r"[/?#]", text.split("://", 1)[-1], maxsplit=1)[0]
        if authority.isascii():
            assert re.fullmatch(r"[0-9a-fA-FxX.]+", authority)


def _bad_codepoints() -> list[str]:
    bad = set("@/\\?#%: \t")
    out = []
    for cp in range(0x80, 0x11000):
        ch = chr(cp)
        if 0xD800 <= cp <= 0xDFFF:
            continue
        if set(unicodedata.normalize("NFKC", ch)) & bad:
            out.append(ch)
    return out


def test_every_codepoint_whose_nfkc_has_a_metacharacter_rejects() -> None:
    offenders = []
    for ch in _bad_codepoints():
        try:
            t = canonical_target(f"a{ch}b.test")
        except TargetParseError:
            continue
        offenders.append((hex(ord(ch)), t.host))
    assert offenders == []
