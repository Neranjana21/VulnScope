"""Self-test of tests/stress/stress_dbguard.py (owner decision 2026-11-19, DB guards).

Pure and offline: fake URLs with a canary password, no connection is ever opened. Proves
(1) only 127.0.0.1:5432 + vulnscope_task<letters>_<8 hex> is accepted, (2) a refusal is a FAILURE
and its message never contains any part of the URL, (3) an unset variable is a skip, which becomes
a failure under VULNSCOPE_REQUIRE_INTEGRATION=1.
"""
from __future__ import annotations

import pytest
from stress_dbguard import (
    require_task_database_url,
    skip_or_fail,
    url_is_disposable_task_database,
)

CANARY = "CANARYPW9f3a1c"
HEX = "0123abcd"


def _url(db: str, *, host: str = "127.0.0.1", port: str = "5432", query: str = "") -> str:
    return f"postgresql+asyncpg://vulnscope_app:{CANARY}@{host}:{port}/{db}{query}"


GOOD = [
    _url(f"vulnscope_taskb_{HEX}"),
    _url(f"vulnscope_taskd_{HEX}"),
    _url(f"vulnscope_task_{HEX}"),
    _url(f"vulnscope_taskab_{HEX}", query="?sslmode=disable"),
    f"postgresql://u:{CANARY}@127.0.0.1:5432/vulnscope_taskb_{HEX}",
]
BAD = [
    _url("vulnscope"),
    _url(f"vulnscope_stress_{HEX}"),
    _url("postgres"),
    _url(f"vulnscope_taskb_{HEX.upper()}"),
    _url("vulnscope_taskb_0123abc"),
    _url("vulnscope_taskb_0123abcde"),
    _url(f"vulnscope_task1_{HEX}"),
    _url(f"vulnscope_taskB_{HEX}"),
    _url(f"vulnscope_taskb_{HEX}\n"),
    _url(f"vulnscope_taskb_{HEX} "),
    _url(f"vulnscope_taskb_{HEX}/extra"),
    _url(f"prefix_vulnscope_taskb_{HEX}"),
    _url(f"vulnscope_taskb_{HEX}", host="localhost"),
    _url(f"vulnscope_taskb_{HEX}", host="127.0.0.2"),
    _url(f"vulnscope_taskb_{HEX}", host="::1"),
    _url(f"vulnscope_taskb_{HEX}", port="5433"),
    f"postgresql://u:{CANARY}@127.0.0.1/vulnscope_taskb_{HEX}",
    _url(f"vulnscope_taskb_{HEX}", query="?host=evil.invalid"),
    _url(f"vulnscope_taskb_{HEX}", query="?HOST=evil.invalid"),
    _url(f"vulnscope_taskb_{HEX}", query="?hostaddr=192.0.2.1"),
    _url(f"vulnscope_taskb_{HEX}", query="?dbname=vulnscope"),
    _url(f"vulnscope_taskb_{HEX}", query="?port=5433"),
    f"postgresql://u:{CANARY}@127.0.0.1:5432,evil.invalid:5432/vulnscope_taskb_{HEX}",
    f"postgresql://127.0.0.1:5432@evil.invalid:5432/vulnscope_taskb_{HEX}",
    f"mysql://u:{CANARY}@127.0.0.1:5432/vulnscope_taskb_{HEX}",
    f"postgresql://u:{CANARY}@127.0.0.1:5432",
    "",
    "not a url",
    f"postgresql://u:{CANARY}@127.0.0.1:99999999999/vulnscope_taskb_{HEX}",
    f"postgresql://u:{CANARY}@[127.0.0.1:5432/vulnscope_taskb_{HEX}",
]


@pytest.mark.parametrize("url", GOOD)
def test_guard_accepts_only_disposable_task_databases(url: str) -> None:
    assert url_is_disposable_task_database(url) is True


@pytest.mark.parametrize("url", BAD)
def test_guard_refuses_everything_else(url: str) -> None:
    assert url_is_disposable_task_database(url) is False


@pytest.mark.parametrize("require", [None, "0", "1"])
@pytest.mark.parametrize("url", BAD[:12])
def test_refusal_is_a_failure_with_fixed_text_regardless_of_require_flag(
    monkeypatch: pytest.MonkeyPatch, url: str, require: str | None
) -> None:
    monkeypatch.setenv("VULNSCOPE_TEST_DATABASE_URL", url)
    if require is None:
        monkeypatch.delenv("VULNSCOPE_REQUIRE_INTEGRATION", raising=False)
    else:
        monkeypatch.setenv("VULNSCOPE_REQUIRE_INTEGRATION", require)
    with pytest.raises(pytest.fail.Exception) as info:
        require_task_database_url()
    text = str(info.value)
    assert CANARY not in text
    assert "127.0.0.1:5432" in text  # fixed text names the allowed target, not the offered one
    assert info.value.pytrace is False


def test_accepted_url_is_returned_unchanged_and_not_echoed(monkeypatch: pytest.MonkeyPatch) -> None:
    url = GOOD[0]
    monkeypatch.setenv("VULNSCOPE_TEST_DATABASE_URL", url)
    monkeypatch.delenv("VULNSCOPE_REQUIRE_INTEGRATION", raising=False)
    assert require_task_database_url() == url


def test_unset_is_a_skip_without_the_require_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VULNSCOPE_TEST_DATABASE_URL", raising=False)
    monkeypatch.delenv("VULNSCOPE_REQUIRE_INTEGRATION", raising=False)
    with pytest.raises(pytest.skip.Exception):
        require_task_database_url()


@pytest.mark.parametrize("value", ["", None])
def test_unset_or_empty_is_a_failure_under_require_flag(
    monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    if value is None:
        monkeypatch.delenv("VULNSCOPE_TEST_DATABASE_URL", raising=False)
    else:
        monkeypatch.setenv("VULNSCOPE_TEST_DATABASE_URL", value)
    monkeypatch.setenv("VULNSCOPE_REQUIRE_INTEGRATION", "1")
    with pytest.raises(pytest.fail.Exception):
        require_task_database_url()


@pytest.mark.parametrize("flag", [None, "0", "true", "yes", "2", " 1"])
def test_only_the_exact_value_1_turns_skips_into_failures(
    monkeypatch: pytest.MonkeyPatch, flag: str | None
) -> None:
    if flag is None:
        monkeypatch.delenv("VULNSCOPE_REQUIRE_INTEGRATION", raising=False)
    else:
        monkeypatch.setenv("VULNSCOPE_REQUIRE_INTEGRATION", flag)
    with pytest.raises(pytest.skip.Exception):
        skip_or_fail("fixed reason")


def test_skip_or_fail_fails_under_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULNSCOPE_REQUIRE_INTEGRATION", "1")
    with pytest.raises(pytest.fail.Exception):
        skip_or_fail("fixed reason")
