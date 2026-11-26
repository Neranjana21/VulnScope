"""The demo command takes no target, and its failures print nothing but a fixed key."""

from __future__ import annotations

import importlib
from typing import Any

import pytest
from devpath import LABEL

PASSWORD = "canary-pw-7f3a9c"


def demo() -> Any:
    return importlib.import_module("devpath.step1")


def test_the_only_option_is_the_output_directory() -> None:
    parser = demo().build_parser()
    options = {name for action in parser._actions for name in action.option_strings}
    assert options == {"-h", "--help", "--out"}
    assert [a.dest for a in parser._actions if not a.option_strings] == []
    assert parser.get_default("out") == ".reports/step1"  # git-ignored


@pytest.mark.parametrize(
    "argv",
    [["http://" + PASSWORD], ["--target", PASSWORD], ["--port", "5432"], ["--host=" + PASSWORD]],
)
def test_target_like_arguments_are_rejected_without_being_echoed(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert demo().main(argv) == 2
    out = capsys.readouterr()
    assert out.out == "usage_error=true\n"
    assert out.err == ""


def test_config_refusal_prints_only_the_code(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("VULNSCOPE_ENABLE_LAB", raising=False)
    monkeypatch.delenv("VULNSCOPE_LAB_CIDR", raising=False)
    monkeypatch.setenv(
        "VULNSCOPE_DATABASE_URL", f"postgresql+asyncpg://a:{PASSWORD}@127.0.0.1:5432/vulnscope"
    )

    def no_stub(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a stub was started despite a refusal")

    monkeypatch.setattr(demo(), "RunningStub", no_stub)
    assert demo().main([]) == 2
    out = capsys.readouterr()
    assert out.out == f"{LABEL}\nrefused=lab_not_enabled\n"
    assert out.err == ""


def test_unexpected_errors_print_only_the_class_name(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def explode() -> None:
        raise RuntimeError(PASSWORD)

    monkeypatch.setattr(demo(), "Settings", explode)
    assert demo().main([]) == 1
    out = capsys.readouterr()
    assert out.out == f"{LABEL}\nerror=RuntimeError\n"
    assert out.err == ""
