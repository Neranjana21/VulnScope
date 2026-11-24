#!/usr/bin/env python3
"""Run a command against a disposable per-task Postgres database (dev cluster only).

    python3 scripts/with_task_db.py --mode scratch --task b [--with-test-url] -- pytest ...
    python3 scripts/with_task_db.py --mode task    --task d                   -- pytest ...

Modes (docs/gates/slice0-parallel-plan.md section 4, task-b-design F14, task-d PD-17):
  scratch  child gets VULNSCOPE_MIGRATION_DATABASE_URL and VULNSCOPE_TEST_APP_DATABASE_URL
           (shared database ``vulnscope``, which the R1 plugin demands) plus
           VULNSCOPE_REQUIRE_INTEGRATION=1; with --with-test-url it also gets
           VULNSCOPE_TEST_DATABASE_URL for a fresh migrated ``vulnscope_task<letter>_<hex8>``.
  task     child gets ONLY the app-role VULNSCOPE_DATABASE_URL and VULNSCOPE_TEST_DATABASE_URL for
           the fresh per-task database. Admin credentials never reach the child (PD-17).

Guards, all boolean and checked before the child starts: host 127.0.0.1, port 5432, task database
name ^vulnscope_task[a-z]_[0-9a-f]{8}$ (never ``vulnscope``), exact child environment shape.
The whole session holds a repo-wide flock. Row counts of the shared ledger tables are compared
before and after; any difference fails the run.

The child environment is built from a small allowlist, never from the parent environment. Passwords
are read from the untracked .env (or the parent environment as a fallback), travel to the child
through its environment only and are never printed, logged or placed in argv. This script prints
fixed ``key=bool|int`` lines only; the child's own stdout/stderr pass through untouched.
Never targets anything but 127.0.0.1:5432. Not started by anything automatically.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import os
import re
import secrets
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import quote, unquote, urlsplit

HOST = "127.0.0.1"
PORT = 5432
SHARED_DB = "vulnscope"
MARKER = "dev-disposable"
ADMIN_USER = "vulnscope_migrator"
APP_USER = "vulnscope_app"
TASK_DB_RE = re.compile(r"^vulnscope_task[a-z]_[0-9a-f]{8}$")
TASK_LETTER_RE = re.compile(r"^[a-z]$")
SHARED_TABLES = ("ledger_entries", "chain_heads", "checkpoints")  # fixed identifiers, never input
_DIGEST_SQL = {  # fixed text; one md5 over every row's chain position and hash
    "ledger_entries": "SELECT md5(coalesce(string_agg(chain_id || ':' || seq || ':' || "
    "record_hash, ',' ORDER BY chain_id, seq), '')) FROM ledger_entries",
    "chain_heads": "SELECT md5(coalesce(string_agg(chain_id || ':' || seq || ':' || head_hash, "
    "',' ORDER BY chain_id), '')) FROM chain_heads",
    "checkpoints": "SELECT md5(coalesce(string_agg(id || ':' || chain_id || ':' || seq || ':' || "
    "head_hash || ':' || signature, ',' ORDER BY id), '')) FROM checkpoints",
}

ADMIN_ENV = "VULNSCOPE_MIGRATION_DATABASE_URL"
APP_ENV = "VULNSCOPE_DATABASE_URL"
TEST_APP_ENV = "VULNSCOPE_TEST_APP_DATABASE_URL"
TEST_DB_ENV = "VULNSCOPE_TEST_DATABASE_URL"
REQUIRE_ENV = "VULNSCOPE_REQUIRE_INTEGRATION"
PASSTHROUGH = ("PATH", "HOME", "LANG", "VIRTUAL_ENV")  # PYTHONPATH is pinned, not inherited

EXIT_USAGE = 2
EXIT_CONFIG = 66
EXIT_UNREACHABLE = 69
EXIT_GUARD = 70
EXIT_DB_ERROR = 71
EXIT_SHARED_CHANGED = 72
EXIT_MIGRATE = 73
EXIT_LOCK = 75
EXIT_NOT_FOUND = 127


# --------------------------------------------------------------------------- errors
class DbUnreachable(Exception):
    """The dev Postgres could not be reached. Carries no detail on purpose."""


class DbError(Exception):
    """Any other database failure. Carries no detail on purpose."""


class LockHeld(Exception):
    pass


def say(key: str, value: bool | int | str) -> None:
    """Only fixed keys and bool/int/validated-name values are ever printed."""
    if isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, int):
        text = str(value)
    else:
        if not TASK_DB_RE.fullmatch(value):
            raise ValueError("unprintable value")
        text = value
    sys.stderr.write(f"with_task_db: {key}={text}\n")


# --------------------------------------------------------------------------- credentials
@dataclass(frozen=True, repr=False)
class Credentials:
    admin_password: str = field(repr=False)
    app_password: str = field(repr=False)

    def __repr__(self) -> str:
        return "Credentials(<redacted>)"


def _parse_env_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key.strip()] = value
    return out


def _source_password(url: str | None, *, user: str) -> str | None:
    """Boolean-validate a source URL (loopback, 5432, shared db, expected role) and return only
    its password."""
    if not url:
        return None
    try:
        p = urlsplit(url)
        ok = (
            p.hostname == HOST
            and p.port == PORT
            and p.path.lstrip("/") == SHARED_DB
            and p.username == user
            and bool(p.password)
        )
        return unquote(p.password) if ok and p.password else None
    except ValueError:
        return None


def env_file_private(path: Path) -> bool:
    """The .env must be owned by the current user and not readable by group or others."""
    try:
        st = path.stat()
    except OSError:
        return False
    return st.st_uid == os.getuid() and (st.st_mode & 0o077) == 0


def load_credentials(env_file: Path | None, environ: Mapping[str, str]) -> Credentials | None:
    """File values win; the parent environment is a fallback for the same names."""
    if env_file is not None and not env_file_private(env_file):
        return None
    file_vals = _parse_env_file(env_file) if env_file is not None else {}

    def get(name: str) -> str | None:
        return file_vals.get(name) or environ.get(name)

    admin = _source_password(get(ADMIN_ENV), user=ADMIN_USER)
    app = _source_password(get(TEST_APP_ENV), user=APP_USER) or _source_password(
        get(APP_ENV), user=APP_USER
    )
    if admin is None or app is None:
        return None
    return Credentials(admin_password=admin, app_password=app)


def make_url(user: str, password: str, database: str) -> str:
    return f"postgresql+asyncpg://{user}:{quote(password, safe='')}@{HOST}:{PORT}/{database}"


# --------------------------------------------------------------------------- guards (pure)
def task_name_ok(name: str) -> bool:
    return bool(TASK_DB_RE.fullmatch(name)) and name != SHARED_DB


def _parts(url: str | None) -> tuple[str | None, str | None, int | None, str] | None:
    if not url:
        return None
    try:
        p = urlsplit(url)
        return p.username, p.hostname, p.port, p.path.lstrip("/")
    except ValueError:
        return None


def _url_ok(url: str | None, *, user: str, db: str | None, task_db: str | None) -> bool:
    parts = _parts(url)
    if parts is None:
        return False
    u, host, port, name = parts
    if u != user or host != HOST or port != PORT:
        return False
    if db is not None:
        return name == db
    return task_db is not None and task_name_ok(name) and name == task_db


def child_env_ok(
    mode: str, env: Mapping[str, str], *, task_db: str | None, with_test_url: bool, src: str
) -> bool:
    """Boolean check of the exact shape of the child environment before it starts."""
    vs_keys = {k for k in env if k.startswith("VULNSCOPE_")}
    if mode == "scratch":
        expected = {ADMIN_ENV, TEST_APP_ENV, REQUIRE_ENV}
        if with_test_url:
            expected.add(TEST_DB_ENV)
        shape = (
            _url_ok(env.get(ADMIN_ENV), user=ADMIN_USER, db=SHARED_DB, task_db=None)
            and _url_ok(env.get(TEST_APP_ENV), user=APP_USER, db=SHARED_DB, task_db=None)
            and env.get(REQUIRE_ENV) == "1"
            and (
                not with_test_url
                or _url_ok(env.get(TEST_DB_ENV), user=APP_USER, db=None, task_db=task_db)
            )
        )
    elif mode == "task":
        expected = {APP_ENV, TEST_DB_ENV}
        shape = (
            _url_ok(env.get(APP_ENV), user=APP_USER, db=None, task_db=task_db)
            and _url_ok(env.get(TEST_DB_ENV), user=APP_USER, db=None, task_db=task_db)
            and env.get(APP_ENV) == env.get(TEST_DB_ENV)
        )
    else:
        return False
    if not shape or vs_keys != expected or env.get("PYTHONPATH") != src:
        return False
    return set(env) <= set(PASSTHROUGH) | expected | {"PYTHONPATH"}


def build_child_env(
    mode: str,
    creds: Credentials,
    parent: Mapping[str, str],
    *,
    task_db: str | None,
    with_test_url: bool,
    src: str,
) -> dict[str, str]:
    env = {k: parent[k] for k in PASSTHROUGH if k in parent}
    env["PYTHONPATH"] = src
    if mode == "scratch":
        env[ADMIN_ENV] = make_url(ADMIN_USER, creds.admin_password, SHARED_DB)
        env[TEST_APP_ENV] = make_url(APP_USER, creds.app_password, SHARED_DB)
        env[REQUIRE_ENV] = "1"
        if with_test_url and task_db is not None:
            env[TEST_DB_ENV] = make_url(APP_USER, creds.app_password, task_db)
    elif mode == "task" and task_db is not None:
        url = make_url(APP_USER, creds.app_password, task_db)
        env[APP_ENV] = url
        env[TEST_DB_ENV] = url
    return env


# --------------------------------------------------------------------------- lock
@contextlib.contextmanager
def session_lock(path: Path, wait: float) -> Iterator[None]:
    """Repo-wide exclusive flock for the whole session. The fd is non-inheritable (PEP 446)."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise LockHeld from None
                time.sleep(0.2)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _git(args: Sequence[str], cwd: Path) -> str | None:
    try:
        proc = subprocess.run(
            ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=15, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = proc.stdout.strip()
    return out if proc.returncode == 0 and out else None


def detect_root() -> Path | None:
    """Repo root comes from this file's location, never from the CWD. It must hold alembic.ini
    and src/vulnscope, otherwise None."""
    root = Path(__file__).resolve().parent.parent
    ok = (root / "alembic.ini").is_file() and (root / "src" / "vulnscope").is_dir()
    return root if ok else None


def default_lock_path(root: Path) -> Path | None:
    common = _git(["rev-parse", "--git-common-dir"], root)
    if common is None:
        return None
    p = Path(common)
    p = p if p.is_absolute() else (root / p)
    return p.resolve() / "vulnscope-db.lock"


def default_env_file(root: Path) -> Path | None:
    own = root / ".env"
    if own.is_file():
        return own
    lock = default_lock_path(root)  # <common git dir>/..: the main checkout
    if lock is None:
        return None
    main_env = lock.parent.parent / ".env"
    return main_env if main_env.is_file() else None


# --------------------------------------------------------------------------- database operations
class DbOps(Protocol):
    def shared_marker_ok(self) -> bool: ...
    def snapshot(self) -> Mapping[str, int | str]: ...
    def create_task_database(self, name: str) -> None: ...
    def drop_task_database(self, name: str) -> None: ...


class AsyncpgOps:
    """Admin operations on the dev cluster through asyncpg (already a pinned dependency).
    Connection parameters are passed as keyword arguments, never as a URL. Exceptions are
    collapsed to DbUnreachable or DbError so no driver text (which could echo parameters) can
    escape."""

    def __init__(self, creds: Credentials) -> None:
        self._creds = creds

    def _run(self, fn: Callable[[Any], Any]) -> Any:
        import asyncio

        async def go() -> Any:
            try:
                import asyncpg

                conn = await asyncpg.connect(
                    host=HOST,
                    port=PORT,
                    user=ADMIN_USER,
                    password=self._creds.admin_password,
                    database=SHARED_DB,
                    timeout=10,
                )
            except (OSError, TimeoutError):
                raise DbUnreachable from None
            except Exception:
                raise DbError from None
            try:
                return await fn(conn)
            except Exception:
                raise DbError from None
            finally:
                await conn.close()

        return asyncio.run(go())

    def shared_marker_ok(self) -> bool:
        async def fn(conn: Any) -> bool:
            value = await conn.fetchval("SELECT current_setting('vulnscope.env', true)")
            return bool(value == MARKER)

        return bool(self._run(fn))

    def snapshot(self) -> Mapping[str, int | str]:
        """Row counts plus an md5 digest of every row's chain position and hash. Detective only:
        it cannot see DDL, grants, or a change that is reverted before the second snapshot."""

        async def fn(conn: Any) -> dict[str, int | str]:
            out: dict[str, int | str] = {}
            for table in SHARED_TABLES:  # fixed identifiers and fixed query text, never input
                exists = await conn.fetchval("SELECT to_regclass($1) IS NOT NULL", table)
                if not exists:
                    out[table] = -1
                    out[table + "_digest"] = ""
                    continue
                out[table] = int(await conn.fetchval(f"SELECT count(*) FROM {table}"))
                out[table + "_digest"] = str(await conn.fetchval(_DIGEST_SQL[table]))
            return out

        return self._run(fn)  # type: ignore[no-any-return]

    def create_task_database(self, name: str) -> None:
        if not task_name_ok(name):
            raise ValueError("bad task database name")

        async def fn(conn: Any) -> None:
            await conn.execute(f'CREATE DATABASE "{name}"')
            try:  # CREATE succeeded: undo it ourselves if the marker step fails
                await conn.execute(f"ALTER DATABASE \"{name}\" SET vulnscope.env = '{MARKER}'")
                marked = await conn.fetchval(
                    "SELECT count(*) FROM pg_db_role_setting s JOIN pg_database d "
                    "ON d.oid = s.setdatabase WHERE d.datname = $1 AND s.setrole = 0 "
                    "AND $2 = ANY(s.setconfig)",
                    name,
                    f"vulnscope.env={MARKER}",
                )
                if marked != 1:
                    raise DbError
            except BaseException:
                await conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
                raise

        self._run(fn)

    def drop_task_database(self, name: str) -> None:
        if not task_name_ok(name):
            raise ValueError("bad task database name")

        async def fn(conn: Any) -> None:
            await conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')

        self._run(fn)


def _minimal_env(parent: Mapping[str, str]) -> dict[str, str]:
    return {k: parent[k] for k in PASSTHROUGH if k in parent}


def migrate_task_database(
    creds: Credentials, name: str, root: Path, parent: Mapping[str, str]
) -> int:
    """alembic upgrade head against the task database as the migrator. Output is discarded."""
    if not task_name_ok(name):
        raise ValueError("bad task database name")
    if not (root / "alembic.ini").is_file():
        return 1
    env = _minimal_env(parent)
    env[ADMIN_ENV] = make_url(ADMIN_USER, creds.admin_password, name)
    env["PYTHONPATH"] = str(root / "src")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", "alembic.ini", "upgrade", "head"],
            cwd=root,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return 1
    return proc.returncode


def run_child_process(cmd: Sequence[str], env: Mapping[str, str]) -> int:
    try:
        proc = subprocess.run(list(cmd), env=dict(env), check=False)
    except FileNotFoundError:
        say("child_found", False)
        return EXIT_NOT_FOUND
    except OSError:
        say("child_started", False)
        return EXIT_NOT_FOUND
    rc = proc.returncode
    return 128 - rc if rc < 0 else rc


@dataclass
class Services:
    make_ops: Callable[[Credentials], DbOps] = AsyncpgOps
    migrate: Callable[[Credentials, str, Path, Mapping[str, str]], int] = migrate_task_database
    run_child: Callable[[Sequence[str], Mapping[str, str]], int] = run_child_process


# --------------------------------------------------------------------------- orchestration
def _parse(argv: Sequence[str]) -> tuple[argparse.Namespace, list[str]] | None:
    if "--" not in argv:
        return None
    split = list(argv).index("--")
    own, cmd = list(argv[:split]), list(argv[split + 1 :])
    if not cmd:
        return None

    class _Parser(argparse.ArgumentParser):
        def error(self, message: str) -> Any:  # fixed text: never echo argument values
            raise ValueError

    p = _Parser(prog="with_task_db", add_help=False)
    p.add_argument("--mode", choices=("scratch", "task"), required=True)
    p.add_argument("--task", required=True)
    p.add_argument("--keep", action="store_true")
    p.add_argument("--with-test-url", action="store_true")
    p.add_argument("--lock-wait", type=float, default=0.0)
    try:
        ns = p.parse_args(own)
    except (ValueError, SystemExit):
        return None
    if not TASK_LETTER_RE.fullmatch(ns.task) or ns.lock_wait < 0:
        return None
    if ns.mode == "task" and ns.with_test_url:
        return None  # task mode always sets the test URL; the flag is scratch-only
    return ns, cmd


def _locked(
    args: argparse.Namespace,
    cmd: list[str],
    *,
    services: Services,
    environ: Mapping[str, str],
    root: Path,
    env_file: Path | None,
) -> int:
    creds = load_credentials(env_file, environ)
    if creds is None:
        say("credentials_ok", False)
        return EXIT_CONFIG

    need_db = args.mode == "task" or args.with_test_url
    name: str | None = None
    if need_db:
        name = f"vulnscope_task{args.task}_{secrets.token_hex(4)}"
        if not task_name_ok(name):
            say("guard_ok", False)
            return EXIT_GUARD

    ops = services.make_ops(creds)
    try:
        if not ops.shared_marker_ok():  # fail closed before any CREATE/DROP/migrate (W-2)
            say("shared_marker_ok", False)
            return EXIT_GUARD
        before = dict(ops.snapshot())
    except DbUnreachable:
        say("database_reachable", False)
        return EXIT_UNREACHABLE
    except DbError:
        say("database_ok", False)
        return EXIT_DB_ERROR

    src = str(root / "src")
    result = 0
    created = False
    try:
        if need_db and name is not None:
            ops.create_task_database(name)  # undoes its own partial create on failure
            created = True  # only a database this run created may be dropped
            if services.migrate(creds, name, root, environ) != 0:
                say("migrate_ok", False)
                result = EXIT_MIGRATE
        if result == 0:
            env = build_child_env(
                args.mode, creds, environ, task_db=name, with_test_url=args.with_test_url, src=src
            )
            if not child_env_ok(
                args.mode, env, task_db=name, with_test_url=args.with_test_url, src=src
            ):
                say("guard_ok", False)
                result = EXIT_GUARD
            else:
                result = services.run_child(cmd, env)
                env.clear()
    except DbUnreachable:
        say("database_reachable", False)
        result = EXIT_UNREACHABLE
    except DbError:
        say("database_ok", False)
        result = EXIT_DB_ERROR
    finally:
        if created and name is not None:
            if args.keep:
                say("task_db_kept", True)
                say("task_db_name", name)
            else:
                try:
                    ops.drop_task_database(name)
                except (DbError, DbUnreachable):
                    say("task_db_dropped", False)
                    result = result or EXIT_DB_ERROR

    try:
        after = dict(ops.snapshot())
    except (DbError, DbUnreachable):
        say("shared_snapshot_after_ok", False)
        return EXIT_SHARED_CHANGED
    if after != before:
        say("shared_ledger_unchanged", False)
        return EXIT_SHARED_CHANGED
    return result


def run(
    argv: Sequence[str],
    *,
    services: Services | None = None,
    environ: Mapping[str, str] | None = None,
    root: Path | None = None,
    lock_path: Path | None = None,
    env_file: Path | None = None,
) -> int:
    parsed = _parse(argv)
    if parsed is None:
        say("usage_ok", False)
        return EXIT_USAGE
    args, cmd = parsed
    parent = os.environ if environ is None else environ
    repo = root if root is not None else detect_root()
    if repo is None:
        say("repo_root_ok", False)
        return EXIT_CONFIG
    lock = lock_path if lock_path is not None else default_lock_path(repo)
    if lock is None:
        say("lock_path_ok", False)
        return EXIT_CONFIG
    envf = env_file if env_file is not None else default_env_file(repo)
    try:
        with session_lock(lock, args.lock_wait):
            return _locked(
                args,
                cmd,
                services=services or Services(),
                environ=parent,
                root=repo,
                env_file=envf,
            )
    except LockHeld:
        say("lock_held", True)
        return EXIT_LOCK


def _on_sigterm(_signum: int, _frame: Any) -> None:
    raise SystemExit(128 + signal.SIGTERM)


def main() -> int:
    signal.signal(signal.SIGTERM, _on_sigterm)  # let finally-blocks drop the task database
    try:
        return run(sys.argv[1:])
    except Exception:  # fixed text only: a traceback could carry connection details
        say("internal_error", True)
        return EXIT_DB_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
