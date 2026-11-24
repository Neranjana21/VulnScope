"""Unit tests for scripts/with_task_db.py. No database, no network: services are fakes.

Boolean-only: a failing leak check calls pytest.fail with fixed text, never an operand.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "with_task_db.py"
_spec = importlib.util.spec_from_file_location("with_task_db_under_test", _SCRIPT)
assert _spec is not None and _spec.loader is not None
w: Any = importlib.util.module_from_spec(_spec)
sys.modules["with_task_db_under_test"] = w
_spec.loader.exec_module(w)

ADMIN_CANARY = "CANARYadminZZ9f3k2"
APP_CANARY = "CANARYappQQ7h1d8"
CANARIES = (ADMIN_CANARY, APP_CANARY)
BASE = {"PATH": "/usr/bin", "HOME": "/home/x", "LANG": "C", "VIRTUAL_ENV": "/v"}
SRC = "/srv/repo/src"


class FakeOps:
    def __init__(
        self, snapshots: list[dict[str, Any]] | None = None, *, raise_on: str = ""
    ) -> None:
        same = {"ledger_entries": 5, "chain_heads": 1, "checkpoints": 0}
        self.snapshots = snapshots or [same, dict(same)]
        self.calls: list[tuple[str, str]] = []
        self.raise_on = raise_on
        self.marker_ok = True
        self._n = 0

    def shared_marker_ok(self) -> bool:
        return self.marker_ok

    def snapshot(self) -> Mapping[str, Any]:
        if self.raise_on == "snapshot":
            raise w.DbUnreachable
        snap = self.snapshots[min(self._n, len(self.snapshots) - 1)]
        self._n += 1
        return snap

    def create_task_database(self, name: str) -> None:
        self.calls.append(("create", name))

    def drop_task_database(self, name: str) -> None:
        self.calls.append(("drop", name))


class Harness:
    def __init__(self, tmp_path: Path, ops: FakeOps | None = None, child_rc: int = 0) -> None:
        self.ops = ops or FakeOps()
        self.child_envs: list[dict[str, str]] = []
        self.child_cmds: list[list[str]] = []
        self.migrated: list[str] = []
        self.child_rc = child_rc
        self.migrate_rc = 0
        env_file = tmp_path / ".env"
        env_file.touch(mode=0o600)
        env_file.write_text(
            f"VULNSCOPE_MIGRATION_DATABASE_URL=postgresql+asyncpg://vulnscope_migrator:{ADMIN_CANARY}"
            "@127.0.0.1:5432/vulnscope\n"
            f"VULNSCOPE_TEST_APP_DATABASE_URL=postgresql+asyncpg://vulnscope_app:{APP_CANARY}"
            "@127.0.0.1:5432/vulnscope\n",
            encoding="utf-8",
        )
        env_file.chmod(0o600)
        self.env_file = env_file
        self.lock = tmp_path / "db.lock"
        self.root = tmp_path

        def migrate(creds: Any, name: str, root: Path, parent: Mapping[str, str]) -> int:
            self.migrated.append(name)
            return self.migrate_rc

        def run_child(cmd: Sequence[str], env: Mapping[str, str]) -> int:
            self.child_cmds.append(list(cmd))
            self.child_envs.append(dict(env))
            return self.child_rc

        self.services = w.Services(
            make_ops=lambda creds: self.ops, migrate=migrate, run_child=run_child
        )

    def go(self, *args: str, environ: Mapping[str, str] | None = None) -> int:
        return int(
            w.run(
                [*args, "--", "true"],
                services=self.services,
                environ=BASE if environ is None else environ,
                root=self.root,
                lock_path=self.lock,
                env_file=self.env_file,
            )
        )


@pytest.fixture
def h(tmp_path: Path) -> Harness:
    return Harness(tmp_path)


def _no_canary(capsys: pytest.CaptureFixture[str]) -> bool:
    cap = capsys.readouterr()
    return not any(c in cap.out or c in cap.err for c in CANARIES)


def _db_of(url: str) -> str:
    return url.rsplit("/", 1)[1]


# --------------------------------------------------------------------------- modes
def test_task_mode_child_env_has_only_app_urls(h: Harness) -> None:
    rc = h.go("--mode", "task", "--task", "b")
    env = h.child_envs[0]
    vs = {k for k in env if k.startswith("VULNSCOPE_")}
    assert rc == 0
    assert vs == {"VULNSCOPE_DATABASE_URL", "VULNSCOPE_TEST_DATABASE_URL"}
    assert "VULNSCOPE_MIGRATION_DATABASE_URL" not in env
    assert "VULNSCOPE_TEST_APP_DATABASE_URL" not in env
    assert not any(ADMIN_CANARY in v for v in env.values())
    assert env["VULNSCOPE_DATABASE_URL"] == env["VULNSCOPE_TEST_DATABASE_URL"]
    assert re.fullmatch(r"vulnscope_taskb_[0-9a-f]{8}", _db_of(env["VULNSCOPE_DATABASE_URL"]))
    assert "vulnscope_app:" in env["VULNSCOPE_DATABASE_URL"]


def test_scratch_mode_shared_urls_and_require_flag(h: Harness) -> None:
    rc = h.go("--mode", "scratch", "--task", "b")
    env = h.child_envs[0]
    vs = {k for k in env if k.startswith("VULNSCOPE_")}
    assert rc == 0
    assert vs == {
        "VULNSCOPE_MIGRATION_DATABASE_URL",
        "VULNSCOPE_TEST_APP_DATABASE_URL",
        "VULNSCOPE_REQUIRE_INTEGRATION",
    }
    assert env["VULNSCOPE_REQUIRE_INTEGRATION"] == "1"
    assert _db_of(env["VULNSCOPE_MIGRATION_DATABASE_URL"]) == "vulnscope"
    assert _db_of(env["VULNSCOPE_TEST_APP_DATABASE_URL"]) == "vulnscope"
    assert "VULNSCOPE_DATABASE_URL" not in env
    assert h.ops.calls == [] and h.migrated == []  # no task database without --with-test-url


def test_scratch_with_test_url_adds_task_database(h: Harness) -> None:
    rc = h.go("--mode", "scratch", "--task", "b", "--with-test-url")
    env = h.child_envs[0]
    assert rc == 0
    assert re.fullmatch(r"vulnscope_taskb_[0-9a-f]{8}", _db_of(env["VULNSCOPE_TEST_DATABASE_URL"]))
    assert "VULNSCOPE_DATABASE_URL" not in env
    assert [c[0] for c in h.ops.calls] == ["create", "drop"]
    assert h.migrated == [h.ops.calls[0][1]]


def test_task_database_dropped_unless_keep(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    h1 = Harness(tmp_path)
    h1.go("--mode", "task", "--task", "d")
    assert [c[0] for c in h1.ops.calls] == ["create", "drop"]
    assert h1.ops.calls[0][1] == h1.ops.calls[1][1]
    capsys.readouterr()
    sub = tmp_path / "k"
    sub.mkdir()
    h2 = Harness(sub)
    h2.go("--mode", "task", "--task", "d", "--keep")
    assert [c[0] for c in h2.ops.calls] == ["create"]
    assert "task_db_kept=true" in capsys.readouterr().err


def test_child_exit_code_propagated(tmp_path: Path) -> None:
    assert Harness(tmp_path, child_rc=7).go("--mode", "task", "--task", "b") == 7


def test_migration_failure_skips_child_and_drops(h: Harness) -> None:
    h.migrate_rc = 1
    rc = h.go("--mode", "task", "--task", "b")
    assert rc == w.EXIT_MIGRATE
    assert h.child_envs == []
    assert [c[0] for c in h.ops.calls] == ["create", "drop"]


# --------------------------------------------------------------------------- guards
@pytest.mark.parametrize(
    ("name", "ok"),
    [
        ("vulnscope_taskb_1a2b3c4d", True),
        ("vulnscope", False),
        ("vulnscope_stress_1a2b3c4d5e6f", False),
        ("vulnscope_taskb_1A2B3C4D", False),
        ("vulnscope_taskbb_1a2b3c4d", False),
        ("vulnscope_task1_1a2b3c4d", False),
        ("vulnscope_taskb_1a2b3c4", False),
        ("vulnscope_taskb_1a2b3c4d9", False),
        ("vulnscope_taskb_1a2b3c4d\n", False),
        ("other_taskb_1a2b3c4d", False),
    ],
)
def test_task_name_pattern(name: str, ok: bool) -> None:
    assert w.task_name_ok(name) is ok


@pytest.mark.parametrize("task", ["bb", "B", "1", "", "b;drop", "../b"])
def test_bad_task_letter_refused(h: Harness, task: str) -> None:
    assert h.go("--mode", "task", "--task", task) == w.EXIT_USAGE
    assert h.child_envs == [] and h.ops.calls == []


def test_missing_command_and_bad_mode_refused(h: Harness) -> None:
    assert w.run(["--mode", "task", "--task", "b"], services=h.services) == w.EXIT_USAGE
    assert w.run(["--mode", "task", "--task", "b", "--"], services=h.services) == w.EXIT_USAGE
    assert h.go("--mode", "prod", "--task", "b") == w.EXIT_USAGE
    assert h.go("--mode", "task", "--task", "b", "--with-test-url") == w.EXIT_USAGE


@pytest.mark.parametrize(
    "bad",
    [
        "postgresql+asyncpg://vulnscope_app:{p}@localhost:5432/vulnscope",
        "postgresql+asyncpg://vulnscope_app:{p}@10.0.0.5:5432/vulnscope",
        "postgresql+asyncpg://vulnscope_app:{p}@127.0.0.1:5433/vulnscope",
        "postgresql+asyncpg://vulnscope_app:{p}@127.0.0.1/vulnscope",
        "postgresql+asyncpg://vulnscope_app:{p}@127.0.0.1:5432/other",
        "postgresql+asyncpg://someone_else:{p}@127.0.0.1:5432/vulnscope",
    ],
)
def test_non_loopback_or_other_port_source_refused(tmp_path: Path, bad: str) -> None:
    hh = Harness(tmp_path)
    hh.env_file.write_text(
        f"VULNSCOPE_MIGRATION_DATABASE_URL=postgresql+asyncpg://vulnscope_migrator:{ADMIN_CANARY}"
        "@127.0.0.1:5432/vulnscope\n"
        f"VULNSCOPE_TEST_APP_DATABASE_URL={bad.format(p=APP_CANARY)}\n",
        encoding="utf-8",
    )
    assert hh.go("--mode", "task", "--task", "b") == w.EXIT_CONFIG
    assert hh.child_envs == [] and hh.ops.calls == []


def test_child_env_guard_rejects_wrong_shapes() -> None:
    creds = w.Credentials(admin_password="a", app_password="b")
    name = "vulnscope_taskb_1a2b3c4d"
    good = w.build_child_env("task", creds, BASE, task_db=name, with_test_url=False, src=SRC)
    assert w.child_env_ok("task", good, task_db=name, with_test_url=False, src=SRC)
    # admin URL smuggled in
    bad = dict(good, VULNSCOPE_MIGRATION_DATABASE_URL=w.make_url(w.ADMIN_USER, "a", name))
    assert not w.child_env_ok("task", bad, task_db=name, with_test_url=False, src=SRC)
    # shared database name in a task URL
    shared = w.make_url(w.APP_USER, "b", "vulnscope")
    bad = dict(good, VULNSCOPE_DATABASE_URL=shared, VULNSCOPE_TEST_DATABASE_URL=shared)
    assert not w.child_env_ok("task", bad, task_db=name, with_test_url=False, src=SRC)
    # wrong host
    wrong = good["VULNSCOPE_DATABASE_URL"].replace("127.0.0.1", "10.0.0.1")
    bad = dict(good, VULNSCOPE_DATABASE_URL=wrong, VULNSCOPE_TEST_DATABASE_URL=wrong)
    assert not w.child_env_ok("task", bad, task_db=name, with_test_url=False, src=SRC)
    # stray non-allowlisted variable
    extra = dict(good, AWS_SECRET="x")
    assert not w.child_env_ok("task", extra, task_db=name, with_test_url=False, src=SRC)
    # PYTHONPATH must be exactly the pinned src
    hostile = dict(good, PYTHONPATH="/hostile")
    assert not w.child_env_ok("task", hostile, task_db=name, with_test_url=False, src=SRC)
    # scratch: DATABASE_URL must be absent
    sc = w.build_child_env("scratch", creds, BASE, task_db=None, with_test_url=False, src=SRC)
    assert w.child_env_ok("scratch", sc, task_db=None, with_test_url=False, src=SRC)
    assert not w.child_env_ok(
        "scratch", dict(sc, VULNSCOPE_DATABASE_URL=good["VULNSCOPE_DATABASE_URL"]),
        task_db=None, with_test_url=False, src=SRC,
    )
    assert not w.child_env_ok("unknown", good, task_db=name, with_test_url=False, src=SRC)


def test_guard_failure_blocks_child_and_still_drops(
    h: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(w, "child_env_ok", lambda *a, **k: False)
    assert h.go("--mode", "task", "--task", "b") == w.EXIT_GUARD
    assert h.child_envs == []
    assert [c[0] for c in h.ops.calls] == ["create", "drop"]


# --------------------------------------------------------------------------- env scrubbing
def test_parent_env_outside_allowlist_absent_from_child(h: Harness) -> None:
    parent = {
        **BASE,
        "AWS_SECRET_ACCESS_KEY": "x",
        "VULNSCOPE_DATABASE_URL": "postgresql://elsewhere",
        "VULNSCOPE_MIGRATION_DATABASE_URL": "postgresql://elsewhere",
        "GITHUB_TOKEN": "y",
        "SECRET_CANARY": "z",
    }
    for mode in ("task", "scratch"):
        h.child_envs.clear()
        h.go("--mode", mode, "--task", "b", environ=parent)
        env = h.child_envs[0]
        assert not any(k in env for k in ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "SECRET_CANARY"))
        assert all(env[k] == BASE[k] for k in BASE)
        assert "elsewhere" not in "".join(env.values())


def test_task_mode_never_leaks_parent_migration_url(h: Harness) -> None:
    parent = {**BASE, "VULNSCOPE_MIGRATION_DATABASE_URL": "x"}
    h.go("--mode", "task", "--task", "b", environ=parent)
    assert "VULNSCOPE_MIGRATION_DATABASE_URL" not in h.child_envs[0]


def test_passwords_not_in_argv(h: Harness) -> None:
    h.go("--mode", "scratch", "--task", "b", "--with-test-url")
    assert not any(c in a for c in CANARIES for cmd in h.child_cmds for a in cmd)


# --------------------------------------------------------------------------- lock
def test_lock_contention_fails_fast_without_running(h: Harness) -> None:
    with w.session_lock(h.lock, 0):
        rc = h.go("--mode", "task", "--task", "b")
    assert rc == w.EXIT_LOCK
    assert h.child_envs == [] and h.ops.calls == []
    assert h.go("--mode", "task", "--task", "b") == 0  # released afterwards


def test_lock_released_after_child_failure(h: Harness) -> None:
    h.child_rc = 3
    assert h.go("--mode", "task", "--task", "b") == 3
    with w.session_lock(h.lock, 0):
        pass


def test_lock_wait_times_out(h: Harness) -> None:
    with w.session_lock(h.lock, 0):
        with pytest.raises(w.LockHeld):
            with w.session_lock(h.lock, 0.3):
                pass


# --------------------------------------------------------------------------- shared DB protection
def test_shared_count_diff_detected(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    before = {"ledger_entries": 5, "chain_heads": 1, "checkpoints": 0}
    for key in before:
        sub = tmp_path / key
        sub.mkdir()
        after = dict(before, **{key: before[key] + 1})
        hh = Harness(sub, FakeOps([before, after]))
        assert hh.go("--mode", "scratch", "--task", "b") == w.EXIT_SHARED_CHANGED
        assert "shared_ledger_unchanged=false" in capsys.readouterr().err


def test_shared_diff_overrides_child_success_and_equal_counts_pass(tmp_path: Path) -> None:
    same = {"ledger_entries": 5, "chain_heads": 1, "checkpoints": 0}
    assert Harness(tmp_path, FakeOps([same, dict(same)])).go("--mode", "task", "--task", "b") == 0


def test_after_snapshot_failure_is_failure(tmp_path: Path) -> None:
    class Flaky(FakeOps):
        def snapshot(self) -> Mapping[str, int]:
            self._n += 1
            if self._n > 1:
                raise w.DbError
            return {"ledger_entries": 1, "chain_heads": 1, "checkpoints": 1}

    assert Harness(tmp_path, Flaky()).go("--mode", "task", "--task", "b") == w.EXIT_SHARED_CHANGED


# --------------------------------------------------------------------------- unreachable
def test_database_unreachable_fixed_failure(h: Harness, capsys: pytest.CaptureFixture[str]) -> None:
    h.ops = FakeOps(raise_on="snapshot")
    assert h.go("--mode", "task", "--task", "b") == w.EXIT_UNREACHABLE
    assert "database_reachable=false" in capsys.readouterr().err
    assert h.child_envs == []


def test_real_ops_collapse_errors_to_fixed_types(monkeypatch: pytest.MonkeyPatch) -> None:
    # No connection is made: asyncpg is replaced, this only exercises exception collapsing.
    class _Boom:
        @staticmethod
        async def connect(**_: Any) -> Any:
            raise ConnectionRefusedError("detail that must not escape")

    monkeypatch.setitem(sys.modules, "asyncpg", _Boom)
    ops = w.AsyncpgOps(w.Credentials(admin_password="a", app_password="b"))
    with pytest.raises(w.DbUnreachable) as exc:
        ops.snapshot()
    assert exc.value.__suppress_context__ and not exc.value.args


# --------------------------------------------------------------------------- no secret in output
def test_no_canary_in_wrapper_output(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    scenarios: list[tuple[Harness, tuple[str, ...]]] = []
    for i, args in enumerate(
        [
            ("--mode", "task", "--task", "b"),
            ("--mode", "scratch", "--task", "b", "--with-test-url", "--keep"),
            ("--mode", "task", "--task", "bb"),
        ]
    ):
        sub = tmp_path / str(i)
        sub.mkdir()
        scenarios.append((Harness(sub), args))
    bad = tmp_path / "bad"
    bad.mkdir()
    hb = Harness(bad, FakeOps([{"ledger_entries": 1}, {"ledger_entries": 2}]))
    scenarios.append((hb, ("--mode", "task", "--task", "b")))
    unreachable = tmp_path / "unr"
    unreachable.mkdir()
    down = Harness(unreachable, FakeOps(raise_on="snapshot"))
    scenarios.append((down, ("--mode", "task", "--task", "b")))
    for hh, args in scenarios:
        hh.go(*args)
    if not _no_canary(capsys):
        pytest.fail("leak")


def test_credentials_repr_is_fixed() -> None:
    c = w.Credentials(admin_password=ADMIN_CANARY, app_password=APP_CANARY)
    text = repr(c) + str(c)
    if any(x in text for x in CANARIES):
        pytest.fail("leak")


def test_main_catches_unexpected_errors_with_fixed_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*_a: Any, **_k: Any) -> int:
        raise RuntimeError(APP_CANARY)

    monkeypatch.setattr(w, "run", boom)
    monkeypatch.setattr(sys, "argv", ["with_task_db.py"])
    monkeypatch.setattr(w.signal, "signal", lambda *a, **k: None)
    assert w.main() == w.EXIT_DB_ERROR
    assert _no_canary(capsys)


# --------------------------------------------------------------------------- fix round 1
def test_w1_root_derives_from_script_not_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import subprocess

    foreign = tmp_path / "foreign"
    (foreign / "src" / "vulnscope").mkdir(parents=True)
    (foreign / "alembic.ini").write_text("", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(foreign)], check=True)
    monkeypatch.chdir(foreign)
    root = w.detect_root()
    assert root == _SCRIPT.parent.parent
    assert root != foreign.resolve()
    assert (root / "alembic.ini").is_file() and (root / "src" / "vulnscope").is_dir()


def test_w1_missing_alembic_ini_refused(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake_dir = tmp_path / "scripts"
    fake_dir.mkdir()
    monkeypatch.setattr(w, "__file__", str(fake_dir / "with_task_db.py"))
    assert w.detect_root() is None


def test_w1_run_without_valid_root_exits_config(
    monkeypatch: pytest.MonkeyPatch, h: Harness
) -> None:
    monkeypatch.setattr(w, "detect_root", lambda: None)
    rc = w.run(["--mode", "task", "--task", "b", "--", "true"], services=h.services,
               environ=BASE, lock_path=h.lock, env_file=h.env_file)
    assert rc == w.EXIT_CONFIG and h.child_envs == [] and h.ops.calls == []


def test_w2_wrong_shared_marker_fails_closed(
    h: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    h.ops.marker_ok = False
    assert h.go("--mode", "task", "--task", "b") == w.EXIT_GUARD
    assert h.ops.calls == [] and h.migrated == [] and h.child_envs == []
    assert "shared_marker_ok=false" in capsys.readouterr().err


def test_w3_equal_counts_different_digest_detected(tmp_path: Path) -> None:
    a = {"chain_heads": 1, "chain_heads_digest": "aaa", "ledger_entries": 2}
    b = {"chain_heads": 1, "chain_heads_digest": "bbb", "ledger_entries": 2}
    hh = Harness(tmp_path, FakeOps([a, b]))
    assert hh.go("--mode", "scratch", "--task", "b") == w.EXIT_SHARED_CHANGED


def test_w3_digest_sql_covers_all_shared_tables() -> None:
    assert set(w._DIGEST_SQL) == set(w.SHARED_TABLES)
    assert all("md5(" in q and "ORDER BY" in q for q in w._DIGEST_SQL.values())


def test_w4_password_is_unquoted_and_roundtrips(tmp_path: Path) -> None:
    raw = "a%40b%25c"
    f = tmp_path / ".env"
    f.touch(mode=0o600)
    f.write_text(
        f"VULNSCOPE_MIGRATION_DATABASE_URL=postgresql+asyncpg://vulnscope_migrator:{raw}"
        "@127.0.0.1:5432/vulnscope\n"
        f"VULNSCOPE_TEST_APP_DATABASE_URL=postgresql+asyncpg://vulnscope_app:{raw}"
        "@127.0.0.1:5432/vulnscope\n",
        encoding="utf-8",
    )
    f.chmod(0o600)
    creds = w.load_credentials(f, {})
    assert creds is not None and creds.admin_password == "a@b%c"
    url = w.make_url("vulnscope_app", creds.app_password, "vulnscope")
    assert w.urlsplit(url).password == raw


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660])
def test_w6_group_or_world_readable_env_refused(tmp_path: Path, mode: int) -> None:
    hh = Harness(tmp_path)
    hh.env_file.chmod(mode)
    assert hh.go("--mode", "task", "--task", "b") == w.EXIT_CONFIG
    assert hh.child_envs == [] and hh.ops.calls == []


def test_w5_parent_pythonpath_replaced_by_repo_src(h: Harness) -> None:
    h.go("--mode", "task", "--task", "b", environ={**BASE, "PYTHONPATH": "/hostile"})
    assert h.child_envs[0]["PYTHONPATH"] == str(h.root / "src")
    h.child_envs.clear()
    h.go("--mode", "scratch", "--task", "b", environ={**BASE, "PYTHONPATH": "/hostile"})
    assert h.child_envs[0]["PYTHONPATH"] == str(h.root / "src")


def test_w7_failed_create_issues_no_drop(h: Harness) -> None:
    def boom(name: str) -> None:
        h.ops.calls.append(("create", name))
        raise w.DbError

    h.ops.create_task_database = boom  # type: ignore[method-assign]
    assert h.go("--mode", "task", "--task", "b") == w.EXIT_DB_ERROR
    assert [c[0] for c in h.ops.calls] == ["create"]
    assert h.child_envs == []


def test_w8_explicit_raises_survive_optimized_mode() -> None:
    with pytest.raises(ValueError):
        w.say("task_db_name", "not-a-task-db")
    with pytest.raises(ValueError):
        w.AsyncpgOps(w.Credentials("a", "b")).create_task_database("vulnscope")
    with pytest.raises(ValueError):
        w.AsyncpgOps(w.Credentials("a", "b")).drop_task_database("vulnscope")
    with pytest.raises(ValueError):
        w.migrate_task_database(w.Credentials("a", "b"), "vulnscope", Path("."), {})
    assert "assert " not in _SCRIPT.read_text(encoding="utf-8")
