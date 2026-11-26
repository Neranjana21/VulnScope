"""An invalid VULNSCOPE_API_* admission setting stops startup before an engine or wiring exists."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from vulnscope.api import main
from vulnscope.config import AdmissionConfigError, Settings


def test_invalid_admission_env_stops_startup_before_any_wiring(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VULNSCOPE_API_AUTH_RESERVED", "0")
    built: list[str] = []

    def no_engine(*_: object, **__: object) -> None:
        built.append("engine")
        raise AssertionError("engine must not be built")

    monkeypatch.setattr(main, "get_async_engine", no_engine)
    app = main.create_app(Settings(database_url="postgresql+asyncpg://u:p@127.0.0.1:1/x"))
    with pytest.raises(AdmissionConfigError):
        with TestClient(app):
            pass
    assert built == []
