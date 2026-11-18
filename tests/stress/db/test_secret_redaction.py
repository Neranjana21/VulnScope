# ruff: noqa: E501
"""GR-STR-31: no secret may appear in test output (terminal, longrepr, JUnit XML). R1.

Pure tests, no database. The passwords below are random fakes generated per run and exported to
the child pytest through its environment, exactly like the real VULNSCOPE_*_DATABASE_URL values.
Covered shapes (the ones Phase R attempt 1 leaked, docs/gates/slice0-grants-phaseR-leak.md):
full URL in a fixture dataclass, full URL in a plain-str fixture, pytest's elision of a long repr
(fragment next to ``...``), a bare fragment, a secret in an exception message, in captured
stdout, and in a JUnit property. A control run WITHOUT the plugin proves the child really leaks,
so the green result is not vacuous.
"""
from __future__ import annotations

import os
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import stress_db_secrets as sec
import vulnscope_db_plugin as kit
from _pytest._io.saferepr import saferepr

MIN = sec.MIN_FRAGMENT


def _fake() -> tuple[str, str, str, str]:
    a, b = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    return (
        a,
        b,
        f"postgresql+asyncpg://vulnscope_migrator:{a}@127.0.0.1:5432/vulnscope",
        f"postgresql+asyncpg://vulnscope_app:{b}@127.0.0.1:5432/vulnscope",
    )


def leaks(text: str, pw: str) -> list[str]:
    """Every >= 8-character window of the password present in ``text`` (empty list = clean)."""
    return sorted({pw[i : i + MIN] for i in range(len(pw) - MIN + 1) if pw[i : i + MIN] in text})


def userinfo_survivors(text: str) -> list[str]:
    import re

    return re.findall(r"://[^\s:/@'\"]+:(?!\*\*\*REDACTED)[^\s@'\"/]{6,}@", text)


@pytest.fixture
def fakes(monkeypatch: pytest.MonkeyPatch) -> tuple[str, str, str, str]:
    a, b, url_a, url_b = _fake()
    monkeypatch.setenv("VULNSCOPE_MIGRATION_DATABASE_URL", url_a)
    monkeypatch.setenv("VULNSCOPE_TEST_APP_DATABASE_URL", url_b)
    return a, b, url_a, url_b


# ---------------------------------------------------------------- layer 1: the wrapper type
def test_secret_never_prints_itself_in_any_formatting() -> None:
    s = sec.Secret("hunter2-hunter2-hunter2")
    shown = [repr(s), str(s), f"{s}", format(s), repr([s]), repr({"k": s}), repr((s,))]
    assert all("hunter2" not in x for x in shown), shown
    assert sec.reveal(s) == "hunter2-hunter2-hunter2" and type(sec.reveal(s)) is str
    assert isinstance(s, str), "must stay a real str for monkeypatch.setenv / asyncpg / SQLAlchemy"


def test_kit_url_helpers_return_secrets_and_still_work(fakes: tuple[str, str, str, str]) -> None:
    a, _, url_a, _ = fakes
    d = kit.to_dsn(url_a)
    assert isinstance(d, sec.Secret) and sec.reveal(d).startswith("postgresql://")
    w = kit.with_user(kit.with_db(url_a, "vulnscope_stress_abcdef01"), "someone", "pw-123456789")
    assert isinstance(w, sec.Secret)
    assert "someone:pw-123456789@127.0.0.1:5432/vulnscope_stress_abcdef01" in sec.reveal(w)
    assert a not in repr(d) + repr(w)


def test_fixture_dataclasses_do_not_print_secrets(fakes: tuple[str, str, str, str]) -> None:
    a, b, url_a, url_b = fakes
    env = kit.StressEnv(
        admin_url=sec.Secret(url_a), app_url=sec.Secret(url_b),
        app_password=sec.Secret(b), admin_password=sec.Secret(a),
        admin_user="vulnscope_migrator", admin_is_superuser=True,
    )
    db = kit.ScratchDb(
        name="vulnscope_stress_abcdef01", admin_url=sec.Secret(url_a), app_url=sec.Secret(url_b),
        admin_dsn=kit.to_dsn(url_a), app_dsn=kit.to_dsn(url_b),
    )
    out = " ".join([repr(env), str(env), f"{env}", saferepr(env), repr(db), str(db), f"{db}", saferepr(db), repr([env, db])])
    assert leaks(out, a) == [] and leaks(out, b) == [], out
    assert userinfo_survivors(out) == []


# ---------------------------------------------------------------- layer 2: the scrubber on text shapes
def _elided_repr(pw: str) -> tuple[str, str]:
    """A long string whose pytest repr (maxsize 240) cuts THROUGH the password: fragment, not whole."""
    for k in range(60, 200):
        value = "p" * k + pw + "z" * 400
        shown = saferepr(value)
        if leaks(shown, pw) and pw not in shown:
            return value, shown
    raise AssertionError("could not build an elision control for the password")


def test_scrubber_covers_full_elided_and_fragment_shapes(fakes: tuple[str, str, str, str]) -> None:
    a, b, url_a, url_b = fakes
    el_a, shown_a = _elided_repr(a)
    el_b, shown_b = _elided_repr(b)
    assert leaks(shown_a, a) and leaks(shown_b, b), "control: the elided repr must contain a real fragment"
    long_url = url_a + "?pad=" + "x" * 400
    elided_url = saferepr(long_url)
    samples = {
        "full_url": f"cannot connect to {url_a} and {url_b}",
        "bare_password": f"password={a} other={b}",
        "fragment_middle": f"... {a[5:30]} ... {b[9:40]}",
        "fragment_prefix": f"{a[:18]}...",
        "fragment_suffix": f"...{b[-20:]}@127.0.0.1:5432/vulnscope'",
        "userinfo_head_then_ellipsis": f"'postgresql+asyncpg://vulnscope_app:{b[:12]}...{b[-5:]}@127.0.0.1'",
        "pytest_elided_value_a": shown_a,
        "pytest_elided_value_b": shown_b,
        "pytest_elided_url": elided_url,
        "dsn_without_scheme": f"vulnscope_migrator:{a}@127.0.0.1:5432",
        "dataclass_repr": f"ScratchDb(name='x', admin_url='{url_a}', app_url='{url_b}')",
    }
    for name, text in samples.items():
        out = sec.scrub(text)
        assert leaks(out, a) == [], (name, "admin password fragment survived")
        assert leaks(out, b) == [], (name, "app password fragment survived")
        assert userinfo_survivors(out) == [], (name, "URL userinfo survived")
    assert sec.REDACTED in sec.scrub(samples["full_url"])


def test_scrubber_does_not_destroy_ordinary_diagnostics(fakes: tuple[str, str, str, str]) -> None:
    text = "postgresql://127.0.0.1:5432/vulnscope_stress_ab12 ERROR permission denied for table ledger_entries (port 5432)"
    assert sec.scrub(text) == text


def test_report_backstop_scrubs_longrepr_sections_and_properties(fakes: tuple[str, str, str, str]) -> None:
    a, b, url_a, url_b = fakes
    rep: Any = pytest.TestReport(
        nodeid="t.py::t", location=("t.py", 1, "t"), keywords={}, outcome="failed",
        longrepr=f"E   AssertionError: {url_a}\nfixture = '{url_b}'", when="call",
        sections=[("Captured stdout call", f"{a} {b[3:40]}")], duration=0.0,
        user_properties=[("dsn", url_a)],
    )
    kit._scrub_report(rep)
    blob = str(rep.longrepr) + repr(rep.sections) + repr(rep.user_properties)
    assert leaks(blob, a) == [] and leaks(blob, b) == [] and userinfo_survivors(blob) == [], blob


# ---------------------------------------------------------------- layer 2, end to end (child pytest)
CHILD = '''
from dataclasses import dataclass
import pytest

A = {a!r}
B = {b!r}
URL_A = {url_a!r}
URL_B = {url_b!r}
ELIDED_A = {el_a!r}
ELIDED_B = {el_b!r}


@dataclass
class Env:  # a plain dataclass: the exact shape that leaked in Phase R attempt 1
    admin_url: str
    admin_password: str


@pytest.fixture
def stress_env():
    return Env(URL_A, A)


@pytest.fixture
def oracle_dsn():
    return "postgresql://vulnscope_migrator:%s@127.0.0.1:5432/vulnscope_stress_ab12cd34" % A


@pytest.fixture
def app_database_url():
    return URL_B


@pytest.fixture
def elided_a():
    return ELIDED_A


@pytest.fixture
def elided_b():
    return ELIDED_B


def test_dataclass_fixture(stress_env):
    assert stress_env.admin_url == "nope"


def test_plain_dsn_fixture(oracle_dsn):
    assert oracle_dsn == "nope"


def test_app_database_url_fixture(app_database_url):
    assert app_database_url == "nope"


def test_elided_fixtures(elided_a, elided_b):
    assert (elided_a, elided_b) == ("nope", "nope")


def test_fragment_operand():
    assert A[7:31] + B[2:25] == "nope"


def test_exception_message():
    raise RuntimeError("cannot connect to " + URL_A + " and " + URL_B)


def test_captured_stdout():
    print("dsn", URL_A, A, B[3:40])
    assert False


def test_junit_property(record_property):
    record_property("dsn", URL_B)
    assert False
'''


def _child_run(tmp: Path, a: str, b: str, url_a: str, url_b: str, *, with_plugin: bool) -> tuple[int, str, str]:
    el_a, _ = _elided_repr(a)
    el_b, _ = _elided_repr(b)
    (tmp / "test_child.py").write_text(
        CHILD.format(a=a, b=b, url_a=url_a, url_b=url_b, el_a=el_a, el_b=el_b), encoding="utf-8"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("VULNSCOPE_") and k != "POSTGRES_PASSWORD"}
    env.update(
        {
            "PYTHONPATH": str(kit.HERE),
            "VULNSCOPE_MIGRATION_DATABASE_URL": url_a,
            "VULNSCOPE_TEST_APP_DATABASE_URL": url_b,
        }
    )
    cmd = [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "--tb=long", "-rA", "-q",
           "--junitxml=out.xml", "test_child.py"]
    if with_plugin:
        cmd[3:3] = ["-p", "vulnscope_db_plugin"]
    p = subprocess.run(cmd, cwd=tmp, env=env, capture_output=True, text=True, timeout=180)
    xml = (tmp / "out.xml").read_text(encoding="utf-8") if (tmp / "out.xml").exists() else ""
    return p.returncode, p.stdout + p.stderr, xml


def test_control_without_the_backstop_the_child_run_does_leak(tmp_path: Path, fakes: tuple[str, str, str, str]) -> None:
    a, b, url_a, url_b = fakes
    rc, terminal, xml = _child_run(tmp_path, a, b, url_a, url_b, with_plugin=False)
    assert rc == 1 and "8 failed" in terminal, terminal[-300:]
    assert a in terminal and a in xml and b in terminal, "control must leak, otherwise the next test proves nothing"


def test_with_the_backstop_nothing_survives_in_terminal_or_junit(tmp_path: Path, fakes: tuple[str, str, str, str]) -> None:
    a, b, url_a, url_b = fakes
    rc, terminal, xml = _child_run(tmp_path, a, b, url_a, url_b, with_plugin=True)
    assert rc == 1 and "8 failed" in terminal, "the child must run and fail every test"
    for label, text in (("terminal", terminal), ("junit", xml)):
        assert leaks(text, a) == [], f"{label}: admin password fragment survived"
        assert leaks(text, b) == [], f"{label}: app password fragment survived"
        assert userinfo_survivors(text) == [], f"{label}: URL userinfo survived"
    assert sec.REDACTED in terminal and sec.REDACTED in xml, "nothing was redacted: the child did not exercise the scrubber"
    for name in ("test_dataclass_fixture", "test_plain_dsn_fixture", "test_app_database_url_fixture",
                 "test_elided_fixtures", "test_fragment_operand", "test_exception_message",
                 "test_captured_stdout", "test_junit_property"):
        assert name in terminal, f"{name} missing from the child output"
