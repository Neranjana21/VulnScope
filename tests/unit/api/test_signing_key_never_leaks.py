"""The ledger signing key setting is a PATH only: key material (the file content) must never appear
in repr/str of Settings, in any log record (all loggers at DEBUG), or in any HTTP response body or
header. Boolean-probe rule: the comparison is computed into a boolean first; the assertion message
carries no operand value. Each surface is proven live by a deliberately leaking mutant."""
from __future__ import annotations

import logging
import os
import secrets
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vulnscope.api.main import create_app
from vulnscope.config import Settings

DSN = "postgresql+asyncpg://u:pw@127.0.0.1:1/x"


def leaked(canary: str, texts: list[str]) -> bool:
    return any(canary in t for t in texts)


@pytest.fixture
def key_file(tmp_path: Path) -> Iterator[tuple[Path, str]]:
    canary = "SIGNKEY-CANARY-" + secrets.token_hex(16)
    p = tmp_path / "signing.key"
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(canary)
    assert (p.stat().st_mode & 0o777) == 0o600
    yield p, canary


def surfaces(settings: Settings, caplog: pytest.LogCaptureFixture, *,
             mutant: str = "") -> list[str]:
    out: list[str] = [repr(settings), str(settings)]
    canary_path = settings.ledger_signing_key_file
    assert canary_path is not None
    app = create_app(settings)
    if mutant == "header":
        @app.middleware("http")
        async def leak(request, call_next):  # type: ignore[no-untyped-def]
            resp = await call_next(request)
            resp.headers["x-debug"] = canary_path.read_text()
            return resp
    c = TestClient(app, raise_server_exceptions=False)
    with caplog.at_level(logging.DEBUG, logger=""):
        if mutant == "log":
            logging.getLogger("vulnscope.api").warning(canary_path.read_text())
        calls = [c.get("/healthz"), c.get("/nope"), c.delete("/healthz"),
                 c.get("/v1/engagements/x", headers={"Authorization": "Bearer " + "a" * 40}),
                 c.post("/v1/engagements", content=b"x" * 300_000)]
        try:
            with TestClient(create_app(settings)):
                pass
        except Exception as exc:  # noqa: BLE001 - startup refusal text is a surface too
            out.append(f"{type(exc).__name__}: {exc}")
    for r in calls:
        out.append(r.text)
        out.append(str(dict(r.headers)))
    out.extend(f"{x.getMessage()}|{x.exc_text}|{x.args}|{x.__dict__}" for x in caplog.records)
    return out


def test_real_surfaces_never_contain_key_material(key_file: tuple[Path, str],
                                                  caplog: pytest.LogCaptureFixture) -> None:
    path, canary = key_file
    s = Settings(database_url=DSN, ledger_signing_key_file=path)
    found = leaked(canary, surfaces(s, caplog))
    if found:
        pytest.fail("leak")
    assert s.ledger_signing_key_file == path  # the PATH is what the setting holds


def test_probe_detects_a_leaking_repr(key_file: tuple[Path, str],
                                      caplog: pytest.LogCaptureFixture) -> None:
    path, canary = key_file

    class LeakySettings(Settings):
        def __repr__(self) -> str:
            return f"LeakySettings({path.read_text()})"

    s = LeakySettings(database_url=DSN, ledger_signing_key_file=path)
    assert leaked(canary, surfaces(s, caplog)) is True


@pytest.mark.parametrize("mutant", ["log", "header"])
def test_probe_detects_leaking_log_and_header(key_file: tuple[Path, str],
                                              caplog: pytest.LogCaptureFixture,
                                              mutant: str) -> None:
    path, canary = key_file
    s = Settings(database_url=DSN, ledger_signing_key_file=path)
    assert leaked(canary, surfaces(s, caplog, mutant=mutant)) is True
