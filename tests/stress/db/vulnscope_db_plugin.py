# ruff: noqa: E501
"""R1 pytest plugin + helper kit for tests/stress/db (docs/gates/slice0-grants-stress-pins.md GR-STR-21).

Registered by tests/stress/db/conftest.py (or ``-p vulnscope_db_plugin`` with
``PYTHONPATH=tests/stress/db``). Provides, by fixture name only:
  stress_env, scratch_manager, scratch_db_factory, migrated_scratch, shared_db_lock,
  oracle_dsn
and hooks: zero-skip under VULNSCOPE_REQUIRE_INTEGRATION=1, inventory enforcement under
VULNSCOPE_INVENTORY_ENFORCE=1.

Safety: every connection goes through ``assert_lab_url``: host exactly 127.0.0.1, port 5432,
database exactly ``vulnscope`` (shared dev DB, marker-checked) or ``vulnscope_stress_<hex>``.
Nothing here ever targets another host. Tests are synchronous; async work runs in a worker
thread with its own event loop so it can never disturb pytest-asyncio's loop.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import importlib
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, TypeVar
from urllib.parse import urlsplit, urlunsplit

import pytest
from stress_db_secrets import Secret as Secret
from stress_db_secrets import register_secret, reveal, scrub

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
INVENTORY_FILE = HERE / "integration_inventory.txt"

HOST = "127.0.0.1"
PORT = 5432
SHARED_DB = "vulnscope"
MARKER = "dev-disposable"
SCRATCH_DB_RE = re.compile(r"^vulnscope_stress_[0-9a-f]{8,32}$")
SCRATCH_ROLE_RE = re.compile(r"^vulnscope_stress_[0-9a-f]{8}$")
ADMIN_ENV = "VULNSCOPE_MIGRATION_DATABASE_URL"
APP_ENV = "VULNSCOPE_TEST_APP_DATABASE_URL"
SESSION_LOCK_KEY = 0x5653545245535331
SHARED_LOCK_KEY = 0x56554C4E53434F50
T = TypeVar("T")


def require_integration() -> bool:
    return os.environ.get("VULNSCOPE_REQUIRE_INTEGRATION") == "1"


# --------------------------------------------------------------------------- url guards
class UnsafeTarget(RuntimeError):
    pass


def assert_lab_url(url: str, *, allow_shared: bool = True, allow_scratch: bool = True) -> None:
    p = urlsplit(reveal(url))
    if p.hostname != HOST or p.port != PORT:
        raise UnsafeTarget(f"refusing non-lab target host={p.hostname!r} port={p.port!r}")
    name = p.path.lstrip("/")
    if allow_shared and name == SHARED_DB:
        return
    if allow_scratch and SCRATCH_DB_RE.fullmatch(name):
        return
    raise UnsafeTarget(f"refusing database name {name!r}")


def to_dsn(url: str) -> Secret:
    return Secret(reveal(url).replace("postgresql+asyncpg://", "postgresql://", 1))


def with_db(url: str, dbname: str) -> Secret:
    p = urlsplit(reveal(url))
    return Secret(urlunsplit(p._replace(path="/" + dbname)))


def with_user(url: str, user: str, password: str) -> Secret:
    p = urlsplit(reveal(url))
    return Secret(urlunsplit(p._replace(netloc=f"{user}:{reveal(password)}@{p.hostname}:{p.port}")))


def lazy(module: str) -> ModuleType:
    """Import a not-yet-existing production module INSIDE a test body (GR-STR-20)."""
    return importlib.import_module(module)


# --------------------------------------------------------------------------- async bridge
def run(coro: Awaitable[T]) -> T:
    async def _wrap() -> T:
        return await coro

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, _wrap()).result()


def with_conn(dsn: str, fn: Callable[[Any], Awaitable[T]], *, timeout: float = 30) -> T:
    import asyncpg

    assert_lab_url(dsn)
    plain = reveal(dsn)

    async def _go() -> T:
        conn = await asyncpg.connect(plain, timeout=timeout)
        try:
            return await fn(conn)
        finally:
            await conn.close()

    return run(_go())


def fetch(dsn: str, sql: str, *args: Any) -> list[Any]:
    return with_conn(dsn, lambda c: c.fetch(sql, *args))


def fetchval(dsn: str, sql: str, *args: Any) -> Any:
    return with_conn(dsn, lambda c: c.fetchval(sql, *args))


def execute(dsn: str, *statements: str) -> None:
    async def _go(c: Any) -> None:
        for s in statements:
            await c.execute(s)

    with_conn(dsn, _go)


def run_sync_helper(sa_url: str, fn: Callable[[Any], T]) -> T:
    """Call ``fn(sync_connection)`` (the shape migration_grants/role_checks take) inside a
    transaction that is committed on success."""
    from sqlalchemy.ext.asyncio import create_async_engine

    assert_lab_url(sa_url)
    plain = reveal(sa_url)

    async def _go() -> T:
        engine = create_async_engine(plain)
        try:
            async with engine.begin() as conn:
                return await conn.run_sync(fn)
        finally:
            await engine.dispose()

    return run(_go())


# --------------------------------------------------------------------------- advisory lock
class LockUnavailable(RuntimeError):
    pass


class AdvisoryLock:
    """Session-level pg_try_advisory_lock held by a dedicated thread/connection, polled."""

    def __init__(self, dsn: str, key: int, timeout: float) -> None:
        assert_lab_url(dsn)
        self.dsn, self.key, self.timeout = Secret(reveal(dsn)), key, timeout
        self._ready = threading.Event()
        self._release = threading.Event()
        self._err: BaseException | None = None
        self._thread: threading.Thread | None = None

    async def _main(self) -> None:
        import asyncpg

        conn = None
        try:
            conn = await asyncpg.connect(reveal(self.dsn), timeout=15)
            deadline = time.monotonic() + self.timeout
            while not await conn.fetchval("SELECT pg_try_advisory_lock($1)", self.key):
                if time.monotonic() > deadline:
                    raise LockUnavailable(
                        f"shared database is in use by another test session (advisory lock "
                        f"{self.key:#x} not acquired within {self.timeout}s)"
                    )
                await asyncio.sleep(0.25)
            self._ready.set()
            await asyncio.get_running_loop().run_in_executor(None, self._release.wait)
            await conn.fetchval("SELECT pg_advisory_unlock($1)", self.key)
        except BaseException as exc:  # noqa: BLE001
            self._err = exc
        finally:
            self._ready.set()
            if conn is not None:
                await conn.close()

    def acquire(self) -> None:
        self._thread = threading.Thread(target=lambda: asyncio.run(self._main()), daemon=True)
        self._thread.start()
        self._ready.wait(self.timeout + 30)
        if self._err is not None:
            raise self._err

    def release(self) -> None:
        self._release.set()
        if self._thread is not None:
            self._thread.join(15)


# --------------------------------------------------------------------------- environment
@dataclass(frozen=True, repr=False)
class StressEnv:
    """No secret is printable: every secret field is a ``Secret`` and ``repr`` is fixed text."""

    admin_url: Secret = field(repr=False)  # SQLAlchemy form, database vulnscope
    app_url: Secret = field(repr=False)
    app_password: Secret = field(repr=False)
    admin_password: Secret = field(repr=False)
    admin_user: str
    admin_is_superuser: bool

    def __repr__(self) -> str:
        return f"StressEnv(<redacted>, admin_user={self.admin_user!r})"


@dataclass(repr=False)
class ScratchDb:
    name: str
    admin_url: Secret = field(repr=False)
    app_url: Secret = field(repr=False)
    admin_dsn: Secret = field(repr=False)
    app_dsn: Secret = field(repr=False)
    roles: list[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return f"ScratchDb(name={self.name!r}, <redacted>)"


def _secret_of(url: str) -> Secret:
    pw = Secret(urlsplit(reveal(url)).password or "")
    register_secret(pw)
    return pw


def _env_or_skip(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"{name} not set: needs the local disposable dev Postgres (docker-compose.dev.yml)")
    return value


@pytest.fixture(scope="session")
def stress_env() -> Iterator[StressEnv]:
    admin_url = Secret(_env_or_skip(ADMIN_ENV))
    app_url = Secret(_env_or_skip(APP_ENV))
    for u in (admin_url, app_url):
        try:
            assert_lab_url(u, allow_scratch=False)
        except UnsafeTarget as exc:
            pytest.fail(str(exc))
    marker = fetchval(to_dsn(admin_url), "SELECT current_setting('vulnscope.env', true)")
    if marker != MARKER:
        pytest.fail(f"shared database marker vulnscope.env={marker!r} != {MARKER!r}; refusing to run")
    who = fetch(
        to_dsn(admin_url),
        "SELECT current_user::text AS u, rolsuper FROM pg_roles WHERE rolname = current_user",
    )[0]
    if who["u"] == "vulnscope_app":
        pytest.fail(f"{ADMIN_ENV} connects as the app role; it must be the migrator")
    app_who = fetch(
        to_dsn(app_url),
        "SELECT current_user::text AS u, rolsuper FROM pg_roles WHERE rolname = current_user",
    )[0]
    if app_who["u"] != "vulnscope_app" or app_who["rolsuper"]:
        pytest.fail(f"{APP_ENV} is not the non-superuser vulnscope_app (got {app_who['u']!r})")
    lock = AdvisoryLock(to_dsn(admin_url), SESSION_LOCK_KEY, 10)
    try:
        lock.acquire()
    except LockUnavailable as exc:
        pytest.fail(str(exc))
    try:
        yield StressEnv(
            admin_url=admin_url,
            app_url=app_url,
            app_password=_secret_of(app_url),
            admin_password=_secret_of(admin_url),
            admin_user=who["u"],
            admin_is_superuser=bool(who["rolsuper"]),
        )
    finally:
        lock.release()


def assert_no_secret(env: StressEnv, *texts: str) -> None:
    for secret in (env.app_password, env.admin_password):
        plain = reveal(secret)
        if plain and any(plain in t for t in texts):
            pytest.fail("a database password appears in captured subprocess output")
    if any(scrub(t) != t for t in texts):
        pytest.fail("secret-shaped text (URL userinfo or a password fragment) in captured subprocess output")


class ScratchManager:
    def __init__(self, env: StressEnv) -> None:
        self.env = env
        self.dbs: list[ScratchDb] = []
        self.shared_dsn = to_dsn(env.admin_url)
        self.sweep()

    def sweep(self) -> None:
        """Drop leftover vulnscope_stress_* databases and roles (fixed regexes only)."""
        for r in fetch(self.shared_dsn, "SELECT datname FROM pg_database WHERE datname LIKE 'vulnscope\\_stress\\_%'"):
            if SCRATCH_DB_RE.fullmatch(r["datname"]):
                execute(self.shared_dsn, f'DROP DATABASE IF EXISTS "{r["datname"]}" WITH (FORCE)')
        for r in fetch(self.shared_dsn, "SELECT rolname FROM pg_roles WHERE rolname LIKE 'vulnscope\\_stress\\_%'"):
            if SCRATCH_ROLE_RE.fullmatch(r["rolname"]):
                execute(self.shared_dsn, f'DROP ROLE IF EXISTS "{r["rolname"]}"')

    def create(self, *, migrate: bool = True) -> ScratchDb:
        name = f"vulnscope_stress_{secrets.token_hex(6)}"
        assert SCRATCH_DB_RE.fullmatch(name)
        execute(self.shared_dsn, f'CREATE DATABASE "{name}"')
        execute(self.shared_dsn, f"ALTER DATABASE \"{name}\" SET vulnscope.env = '{MARKER}'")
        admin_url = with_db(self.env.admin_url, name)
        app_url = with_db(self.env.app_url, name)
        db = ScratchDb(name, admin_url, app_url, to_dsn(admin_url), to_dsn(app_url))
        self.dbs.append(db)
        marker = fetchval(db.admin_dsn, "SELECT current_setting('vulnscope.env', true)")
        if marker != MARKER:
            pytest.fail(f"scratch database {name} lacks the dev-disposable marker")
        if migrate:
            proc = alembic(self.env, db, "upgrade", "head")
            if proc.returncode != 0:
                pytest.fail(f"alembic upgrade head failed on scratch DB (rc={proc.returncode}): {proc.stderr[-1500:]}")
        return db

    def new_role(self, db: ScratchDb, *, login: bool = True, extra: str = "") -> tuple[str, Secret]:
        name = f"vulnscope_stress_{uuid.uuid4().hex[:8]}"
        assert SCRATCH_ROLE_RE.fullmatch(name)
        pw = Secret(secrets.token_hex(16))
        register_secret(pw)
        attrs = "LOGIN" if login else "NOLOGIN"
        execute(
            self.shared_dsn,
            f"CREATE ROLE \"{name}\" {attrs} PASSWORD '{reveal(pw)}' NOSUPERUSER NOCREATEDB NOCREATEROLE "
            f"NOBYPASSRLS NOREPLICATION {extra}",
        )
        db.roles.append(name)
        return name, pw

    def drop_role(self, db: ScratchDb, name: str) -> None:
        assert SCRATCH_ROLE_RE.fullmatch(name)
        execute(
            db.admin_dsn,
            f'REASSIGN OWNED BY "{name}" TO CURRENT_USER',
            f'DROP OWNED BY "{name}"',
        )
        execute(self.shared_dsn, f'DROP ROLE IF EXISTS "{name}"')
        if name in db.roles:
            db.roles.remove(name)

    def drop(self, db: ScratchDb) -> None:
        for role in list(db.roles):
            try:
                self.drop_role(db, role)
            except Exception:  # noqa: BLE001 - best effort; the database drop below still runs
                pass
        execute(self.shared_dsn, f'DROP DATABASE IF EXISTS "{db.name}" WITH (FORCE)')
        for role in list(db.roles):
            execute(self.shared_dsn, f'DROP ROLE IF EXISTS "{role}"')
        if db in self.dbs:
            self.dbs.remove(db)

    def close(self) -> None:
        for db in list(self.dbs):
            self.drop(db)


@pytest.fixture(scope="session")
def scratch_manager(stress_env: StressEnv) -> Iterator[ScratchManager]:
    mgr = ScratchManager(stress_env)
    try:
        yield mgr
    finally:
        mgr.close()


@pytest.fixture
def scratch_db_factory(scratch_manager: ScratchManager) -> Iterator[Callable[..., ScratchDb]]:
    created: list[ScratchDb] = []

    def make(*, migrate: bool = True) -> ScratchDb:
        db = scratch_manager.create(migrate=migrate)
        created.append(db)
        return db

    try:
        yield make
    finally:
        for db in created:
            scratch_manager.drop(db)


@pytest.fixture(scope="module")
def migrated_scratch(scratch_manager: ScratchManager) -> Iterator[ScratchDb]:
    db = scratch_manager.create(migrate=True)
    try:
        yield db
    finally:
        scratch_manager.drop(db)


@pytest.fixture(scope="session")
def shared_db_lock(stress_env: StressEnv) -> Iterator[None]:
    timeout = float(os.environ.get("VULNSCOPE_SHARED_LOCK_WAIT", "10"))
    lock = AdvisoryLock(to_dsn(stress_env.admin_url), SHARED_LOCK_KEY, timeout)
    try:
        lock.acquire()
    except LockUnavailable as exc:
        pytest.fail(str(exc))
    try:
        yield
    finally:
        lock.release()


@pytest.fixture
def oracle_dsn(request: pytest.FixtureRequest, stress_env: StressEnv) -> Secret:
    """Admin DSN the oracle reads catalogs through: scratch DB by default, shared DB read-only
    when VULNSCOPE_ORACLE_SHARED=1."""
    if os.environ.get("VULNSCOPE_ORACLE_SHARED") == "1":
        request.getfixturevalue("shared_db_lock")
        return to_dsn(stress_env.admin_url)
    return request.getfixturevalue("migrated_scratch").admin_dsn  # type: ignore[no-any-return]


# --------------------------------------------------------------------------- subprocess helpers
def _alembic_env(env: StressEnv, db: ScratchDb, extra: dict[str, str] | None) -> dict[str, str]:
    e = dict(os.environ)
    e[ADMIN_ENV] = reveal(db.admin_url)
    e["PYTHONPATH"] = str(REPO_ROOT / "src")
    e.update(extra or {})
    return e


def alembic(
    env: StressEnv,
    db: ScratchDb,
    *args: str,
    extra_env: dict[str, str] | None = None,
    cwd: Path = REPO_ROOT,
    timeout: float = 180,
) -> subprocess.CompletedProcess[str]:
    assert_lab_url(db.admin_url, allow_shared=False)
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=cwd,
        env=_alembic_env(env, db, extra_env),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    assert_no_secret(env, proc.stdout, proc.stderr)
    return proc


_WRAPPER = """
import sys
from vulnscope.db import migration_grants as mg
{patch}
from alembic.config import main
main(argv={argv!r})
"""


def alembic_patched(
    env: StressEnv,
    db: ScratchDb,
    patch: str,
    *args: str,
    timeout: float = 180,
) -> subprocess.CompletedProcess[str]:
    """Run alembic in-process in a child interpreter after executing ``patch`` (python source
    that may monkeypatch ``mg``). Child never touches the shared DB."""
    assert_lab_url(db.admin_url, allow_shared=False)
    code = _WRAPPER.format(patch=patch, argv=["-c", "alembic.ini", *args])
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        env=_alembic_env(env, db, None),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    assert_no_secret(env, proc.stdout, proc.stderr)
    return proc


def user_tables(db: ScratchDb) -> list[str]:
    rows = fetch(
        db.admin_dsn,
        "SELECT n.nspname || '.' || c.relname AS t FROM pg_class c JOIN pg_namespace n "
        "ON n.oid = c.relnamespace WHERE c.relkind IN ('r','p','v','m','S','f') AND n.nspname "
        "NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg\\_toast%' "
        "AND n.nspname NOT LIKE 'pg\\_temp\\_%' ORDER BY 1",
    )
    return [r["t"] for r in rows]


def record(kind: str, payload: dict[str, Any]) -> None:
    """Append one JSON line to .reports/stress-records.jsonl (git-ignored, inside the repo) so the
    post-gate can quote mutant/probe/timing results. Never contains secrets."""
    import json

    d = REPO_ROOT / ".reports"
    d.mkdir(exist_ok=True)
    with (d / "stress-records.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"kind": kind, "ts": time.time(), **payload}, default=str) + "\n")


# --------------------------------------------------------------------------- inventory
def load_inventory() -> list[str]:
    lines = INVENTORY_FILE.read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def inventory_matches(entry: str, nodes: set[str]) -> bool:
    if entry.endswith("[*]"):
        prefix = entry[:-3] + "["
        return any(n.startswith(prefix) for n in nodes)
    return entry in nodes


def collect_nodes(paths: list[str], *, integration_only: bool) -> set[str]:
    cmd = [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider"]
    if integration_only:
        cmd += ["-m", "integration"]
    cmd += paths
    e = {k: v for k, v in os.environ.items() if k != "VULNSCOPE_REQUIRE_INTEGRATION"}
    proc = subprocess.run(cmd, cwd=REPO_ROOT, env=e, capture_output=True, text=True, timeout=300)
    return {ln.strip() for ln in proc.stdout.splitlines() if "::" in ln and not ln.startswith(" ")}


# --------------------------------------------------------------------------- hooks
def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "integration: requires the local disposable Postgres")
    config._vs_outcomes = {}  # type: ignore[attr-defined]


def _covered(item: pytest.Item) -> bool:
    return item.get_closest_marker("integration") is not None or "stress/db/" in item.nodeid.replace("\\", "/")


def _scrub_report(rep: Any) -> None:
    """GR-STR-31 backstop: nothing secret-shaped may reach the terminal or the JUnit writer, whatever
    produced it (fixture values, assertion operands, exception text, captured output, properties)."""
    lr = rep.longrepr
    if isinstance(lr, tuple):
        new_t = tuple(scrub(x) if isinstance(x, str) else x for x in lr)
        if new_t != lr:
            rep.longrepr = new_t
    elif lr is not None:
        text = lr if isinstance(lr, str) else str(lr)
        clean = scrub(text)
        if clean != text:
            rep.longrepr = clean
    rep.sections = [(n, scrub(c)) for n, c in rep.sections]
    if hasattr(rep, "user_properties"):
        rep.user_properties = [(k, scrub(v) if isinstance(v, str) else v) for k, v in rep.user_properties]


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[Any]) -> Iterator[None]:
    outcome = yield
    rep = outcome.get_result()  # type: ignore[attr-defined]
    if rep.skipped and require_integration() and _covered(item):
        reason = rep.longrepr[2] if isinstance(rep.longrepr, tuple) else str(rep.longrepr)
        rep.outcome = "failed"
        rep.longrepr = f"SKIP FORBIDDEN under VULNSCOPE_REQUIRE_INTEGRATION=1: {reason}"
    _scrub_report(rep)


@pytest.hookimpl(hookwrapper=True)
def pytest_make_collect_report(collector: Any) -> Iterator[None]:
    outcome = yield
    _scrub_report(outcome.get_result())  # type: ignore[attr-defined]


def pytest_runtest_logreport(report: pytest.TestReport) -> None:
    cfg = _CONFIG.get("config")
    if cfg is None:
        return
    outcomes: dict[str, str] = cfg._vs_outcomes  # type: ignore[attr-defined]
    if report.when == "call" or (report.when == "setup" and report.outcome != "passed"):
        outcomes[report.nodeid] = report.outcome
    elif report.when == "teardown" and report.outcome == "failed":
        outcomes[report.nodeid] = "failed"


_CONFIG: dict[str, pytest.Config] = {}


@pytest.hookimpl(trylast=True)
def pytest_sessionstart(session: pytest.Session) -> None:
    _CONFIG["config"] = session.config


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if os.environ.get("VULNSCOPE_INVENTORY_ENFORCE") != "1" or not require_integration():
        return
    outcomes: dict[str, str] = session.config._vs_outcomes  # type: ignore[attr-defined]
    passed = {n for n, o in outcomes.items() if o == "passed"}
    missing = [e for e in load_inventory() if not inventory_matches(e, passed)]
    if missing:
        sys.stderr.write(
            "\nINVENTORY ENFORCE: %d inventory entr%s did not run and pass:\n  %s\n"
            % (len(missing), "y" if len(missing) == 1 else "ies", "\n  ".join(missing))
        )
        session.exitstatus = 1
