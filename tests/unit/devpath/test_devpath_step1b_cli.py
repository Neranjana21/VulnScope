"""The step1b command takes no target, and its refusals and failures print fixed keys only."""

from __future__ import annotations

import importlib
from typing import Any

import pytest
from devpath import LABEL

PASSWORD = "canary-pw-7f3a9c"


def command() -> Any:
    return importlib.import_module("devpath.step1b")


def test_the_only_option_is_the_output_directory() -> None:
    parser = command().build_parser()
    options = {name for action in parser._actions for name in action.option_strings}
    assert options == {"-h", "--help", "--out"}
    assert [a.dest for a in parser._actions if not a.option_strings] == []
    assert parser.get_default("out") == ".reports/step1b"  # git-ignored


@pytest.mark.parametrize(
    "argv",
    [
        ["http://" + PASSWORD],
        ["--target", PASSWORD],
        ["--port", "5432"],
        ["--host=" + PASSWORD],
        ["--url=" + PASSWORD],
        ["--ou", PASSWORD],
    ],
)
def test_target_like_arguments_are_rejected_without_being_echoed(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert command().main(argv) == 2
    out = capsys.readouterr()
    assert (out.out, out.err) == ("usage_error=true\n", "")


@pytest.mark.parametrize(
    ("env", "code"),
    [
        ({}, "lab_not_enabled"),
        ({"VULNSCOPE_ENABLE_LAB": "1", "VULNSCOPE_LAB_CIDR": "127.0.0.0/8"}, "lab_cidr_set"),
        ({"VULNSCOPE_ENABLE_LAB": "1"}, "database_not_task"),
    ],
)
def test_config_refusals_happen_before_anything_else(
    env: dict[str, str],
    code: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv("VULNSCOPE_ENABLE_LAB", raising=False)
    monkeypatch.delenv("VULNSCOPE_LAB_CIDR", raising=False)
    monkeypatch.setenv(
        "VULNSCOPE_DATABASE_URL", f"postgresql+asyncpg://a:{PASSWORD}@127.0.0.1:5432/vulnscope"
    )
    for name, value in env.items():
        monkeypatch.setenv(name, value)

    def untouched(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("used despite a refusal")

    for attribute in ("get_async_engine", "seed_engagement", "run_check"):
        monkeypatch.setattr(command(), attribute, untouched)
    assert command().main([]) == 2
    out = capsys.readouterr()
    assert (out.out, out.err) == (f"{LABEL}\nrefused={code}\n", "")


def test_unexpected_errors_print_only_the_class_name(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def explode() -> None:
        raise RuntimeError(PASSWORD)

    monkeypatch.setattr(command(), "Settings", explode)
    assert command().main([]) == 1
    out = capsys.readouterr()
    assert (out.out, out.err) == (f"{LABEL}\nerror=RuntimeError\n", "")
