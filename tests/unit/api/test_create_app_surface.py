"""PD-23, PD-03 item 1, PD-04 item 7: the default app refuses to start without wiring; the
public surface hides docs; settings are validated at startup; Settings never prints the DSN."""
from __future__ import annotations

import math

import pytest
from fastapi.testclient import TestClient

from vulnscope.api.main import create_app
from vulnscope.api.startup import ConfigError, validate_settings
from vulnscope.api.wiring import WiringNotAvailable
from vulnscope.config import Settings

DSN = "postgresql+asyncpg://u:CANARYpw@127.0.0.1:1/x"


def test_default_create_app_refuses_to_start() -> None:
    app = create_app(Settings(database_url=DSN))
    with pytest.raises(WiringNotAvailable):
        with TestClient(app):
            pass


def test_create_app_without_settings_does_not_touch_the_database_at_construction() -> None:
    app = create_app()
    assert app.debug is False


def test_unset_database_url_refuses_to_start() -> None:
    app = create_app(Settings(database_url=None))
    with pytest.raises(ConfigError):
        with TestClient(app):
            pass


def test_docs_are_not_exposed_and_health_is_open() -> None:
    c = TestClient(create_app(Settings(database_url=DSN)), raise_server_exceptions=True)
    for path in ("/docs", "/redoc", "/openapi.json", "/v1/engagements/"):
        r = c.get(path)
        assert r.status_code == 404 and r.json()["code"] == "NOT_FOUND", path
    r = c.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_unauthenticated_requests_do_no_database_work() -> None:
    c = TestClient(create_app(Settings(database_url=DSN)), raise_server_exceptions=True)
    # No wiring is installed (no lifespan): an authenticated route must fail closed, not crash.
    r = c.get("/v1/engagements/abc")
    assert r.status_code in (401, 503)
    assert r.json()["code"] in ("UNAUTHENTICATED", "UNAVAILABLE")


def test_settings_repr_hides_the_dsn() -> None:
    assert "CANARYpw" not in repr(Settings(database_url=DSN))
    assert "CANARYpw" not in str(Settings(database_url=DSN))


@pytest.mark.parametrize("kw", [
    {"max_rps_per_host": math.nan}, {"max_rps_per_host": math.inf}, {"max_rps_per_host": 0.0},
    {"max_rps_per_host": -1.0}, {"max_window_days": 0}, {"max_window_days": 3651},
    {"database_url": None},
])
def test_validate_settings_rejects(kw: dict) -> None:
    base = {"database_url": DSN}
    base.update(kw)
    with pytest.raises(ConfigError):
        validate_settings(Settings(**base))


def test_validate_settings_accepts_defaults() -> None:
    validate_settings(Settings(database_url=DSN))
