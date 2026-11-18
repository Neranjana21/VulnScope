# ruff: noqa: E501
"""U1-U7 (docs/gates/slice0-plan.md 3.10.1): pure checks of ``vulnscope.db.migration_grants``.
No database. ``vulnscope.db.migration_grants`` is imported lazily inside each test body
(GR-STR-20), so before the fix every test here fails on its own with ``ModuleNotFoundError``
instead of one collection error aborting the session.
"""
from __future__ import annotations

import importlib
import os
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

REPO_ROOT = Path(__file__).resolve().parents[3]
CRUD = ("SELECT", "INSERT", "UPDATE", "DELETE")
IDENT = r"[a-z_][a-z0-9_]{0,62}"
FIXED = {
    "ledger_entries": {"SELECT", "INSERT"},
    "checkpoints": {"SELECT", "INSERT"},
    "chain_heads": {"SELECT", "INSERT", "UPDATE"},
    "alembic_version": set(),
}


def _mg() -> ModuleType:
    return importlib.import_module("vulnscope.db.migration_grants")


def _valid_map() -> dict[str, tuple[str, ...]]:
    return {
        "alembic_version": (),
        "orgs": CRUD,
        "ledger_entries": ("SELECT", "INSERT"),
        "checkpoints": ("SELECT", "INSERT"),
        "chain_heads": ("SELECT", "INSERT", "UPDATE"),
    }


def _revokes(table: str, role: str) -> list[str]:
    t = f'"public"."{table}"'
    return [f"REVOKE ALL ON TABLE {t} FROM PUBLIC", f'REVOKE ALL ON TABLE {t} FROM "{role}"']


# --------------------------------------------------------------------------- U1
def test_u1_exact_statements_for_a_three_table_map() -> None:
    mg = _mg()
    out = mg.grant_statements(
        "vulnscope_app",
        {"orgs": CRUD, "ledger_entries": ("SELECT", "INSERT"), "alembic_version": ()},
    )
    expected = [
        *_revokes("alembic_version", "vulnscope_app"),
        *_revokes("ledger_entries", "vulnscope_app"),
        'GRANT SELECT, INSERT ON TABLE "public"."ledger_entries" TO "vulnscope_app"',
        *_revokes("orgs", "vulnscope_app"),
        'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE "public"."orgs" TO "vulnscope_app"',
    ]
    assert out == expected


def test_u1_alembic_version_alone_yields_exactly_two_revokes() -> None:
    mg = _mg()
    assert mg.grant_statements("vulnscope_app", {"alembic_version": ()}) == _revokes(
        "alembic_version", "vulnscope_app"
    )


# --------------------------------------------------------------------------- U2
@pytest.mark.parametrize(
    "privs",
    [
        ("TRUNCATE",),
        ("ALL",),
        ("REFERENCES",),
        ("TRIGGER",),
        ("select",),
        ("SELECT; DROP TABLE x",),
        ("SELECT", "SELECT"),
    ],
    ids=["truncate", "all", "references", "trigger", "lowercase", "injection", "duplicate"],
)
def test_u2_rejects_bad_privileges_with_the_precondition_error(privs: tuple[str, ...]) -> None:
    mg = _mg()
    with pytest.raises(mg.MigrationPreconditionError):
        mg.grant_statements("vulnscope_app", {**_valid_map(), "orgs": privs})


BAD_IDENTIFIERS = ['a"b', "Orgs", "", "a\x00b", "a" * 64, "orgs\n", " orgs", "x;y", "ünï"]


@pytest.mark.parametrize("bad", BAD_IDENTIFIERS, ids=[f"id{i}" for i in range(len(BAD_IDENTIFIERS))])
def test_u2_rejects_unsafe_table_identifiers(bad: str) -> None:
    mg = _mg()
    with pytest.raises(mg.MigrationPreconditionError):
        mg.grant_statements("vulnscope_app", {**_valid_map(), bad: ("SELECT",)})


@pytest.mark.parametrize("bad", BAD_IDENTIFIERS, ids=[f"id{i}" for i in range(len(BAD_IDENTIFIERS))])
def test_u2_rejects_unsafe_role_identifiers(bad: str) -> None:
    mg = _mg()
    with pytest.raises(mg.MigrationPreconditionError):
        mg.grant_statements(bad, _valid_map())


def test_u2_a_63_character_identifier_is_accepted() -> None:
    mg = _mg()
    name = "a" * 63
    out = mg.grant_statements(name, {**_valid_map(), name: ("SELECT",)})
    assert f'GRANT SELECT ON TABLE "public"."{name}" TO "{name}"' in out


# --------------------------------------------------------------------------- U3
@pytest.mark.parametrize(
    ("table", "privs"),
    [
        ("ledger_entries", CRUD),
        ("ledger_entries", ("SELECT",)),
        ("ledger_entries", ("SELECT", "INSERT", "UPDATE")),
        ("checkpoints", CRUD),
        ("checkpoints", ("SELECT",)),
        ("checkpoints", ("SELECT", "INSERT", "UPDATE")),
        ("chain_heads", CRUD),
        ("chain_heads", ("SELECT", "INSERT")),
        ("alembic_version", ("SELECT",)),
    ],
)
def test_u3_fixed_privileges_cannot_be_changed_by_a_map(table: str, privs: tuple[str, ...]) -> None:
    mg = _mg()
    with pytest.raises(mg.MigrationPreconditionError):
        mg.grant_statements("vulnscope_app", {**_valid_map(), table: privs})


def test_u3_a_map_without_an_alembic_version_decision_raises() -> None:
    mg = _mg()
    no_decision = {k: v for k, v in _valid_map().items() if k != "alembic_version"}
    with pytest.raises(mg.MigrationPreconditionError):
        mg.grant_statements("vulnscope_app", no_decision)


def test_u3_fixed_privileges_constant_matches_the_plan() -> None:
    mg = _mg()
    assert {k: set(v) for k, v in mg.FIXED_PRIVILEGES.items()} == FIXED


@settings(deadline=None, print_blob=True)
@given(
    table=st.sampled_from(sorted(FIXED)),
    privs=st.lists(st.sampled_from(CRUD), unique=True, max_size=4),
)
def test_u3_property_any_privilege_set_other_than_the_fixed_one_raises(
    table: str, privs: list[str]
) -> None:
    mg = _mg()
    assume(set(privs) != FIXED[table])
    with pytest.raises(mg.MigrationPreconditionError):
        mg.grant_statements("vulnscope_app", {**_valid_map(), table: tuple(privs)})


# --------------------------------------------------------------------------- U4
@settings(deadline=None, print_blob=True)
@given(
    role=st.from_regex(IDENT, fullmatch=True),
    table=st.from_regex(IDENT, fullmatch=True),
    privs=st.lists(st.sampled_from(CRUD), unique=True, max_size=4),
)
def test_u4_property_statement_shapes_and_no_semicolon(role: str, table: str, privs: list[str]) -> None:
    mg = _mg()
    assume(table not in FIXED)
    out: list[str] = mg.grant_statements(role, {"alembic_version": (), table: tuple(privs)})

    expected: list[str] = []
    for name in sorted(["alembic_version", table]):
        expected += _revokes(name, role)
        if name == table and privs:
            expected.append(f'GRANT {", ".join(privs)} ON TABLE "public"."{name}" TO "{role}"')
    assert out == expected
    assert all(";" not in s for s in out)


# --------------------------------------------------------------------------- U5
def _rels(*items: tuple[str, str, str]) -> frozenset[tuple[str, str, str]]:
    return frozenset(items)


BEFORE = _rels(("public", "alembic_version", "r"))
MAP = {"alembic_version": (), "orgs": CRUD}


def test_u5_happy_path_passes() -> None:
    mg = _mg()
    mg.require_grant_decision_for_new_relations(BEFORE, BEFORE | _rels(("public", "orgs", "r")), MAP)
    mg.require_grant_decision_for_new_relations(BEFORE, BEFORE | _rels(("public", "orgs", "p")), MAP)


@pytest.mark.parametrize(
    "extra",
    [
        ("public", "rogue", "r"),
        ("public", "v1", "v"),
        ("public", "mv1", "m"),
        ("public", "seq1", "S"),
        ("public", "ft1", "f"),
        ("other", "orgs", "r"),
    ],
    ids=["table_without_entry", "view", "matview", "sequence", "foreign_table", "other_schema"],
)
def test_u5_new_relation_without_a_grant_decision_raises(extra: tuple[str, str, str]) -> None:
    mg = _mg()
    after = BEFORE | _rels(("public", "orgs", "r"), extra)
    with pytest.raises(mg.MigrationPreconditionError):
        mg.require_grant_decision_for_new_relations(BEFORE, after, MAP)


def test_u5_a_map_naming_a_missing_table_raises() -> None:
    mg = _mg()
    with pytest.raises(mg.MigrationPreconditionError):
        mg.require_grant_decision_for_new_relations(BEFORE, BEFORE, MAP)


# --------------------------------------------------------------------------- U6
def test_u6_app_role_constant_equals_the_role_in_init_roles_sql() -> None:
    mg = _mg()
    sql = (REPO_ROOT / "infra" / "postgres" / "init-roles.sql").read_text(encoding="utf-8")
    found = re.findall(r"(?im)^\s*create\s+role\s+([a-z_][a-z0-9_]*)", sql)
    assert mg.APP_ROLE == "vulnscope_app"
    assert found == ["vulnscope_app"]


def test_u6_no_command_line_seam_for_the_role_exists_under_alembic() -> None:
    offenders = [
        str(p.relative_to(REPO_ROOT))
        for p in (REPO_ROOT / "alembic").rglob("*")
        if p.is_file()
        and "__pycache__" not in p.parts
        and "get_x_argument" in p.read_text(encoding="utf-8", errors="replace")
    ]
    assert offenders == []


# --------------------------------------------------------------------------- U7
def test_u7_offline_sql_mode_is_refused() -> None:
    env: dict[str, Any] = {k: v for k, v in os.environ.items() if not k.startswith("VULNSCOPE_")}
    env["VULNSCOPE_MIGRATION_DATABASE_URL"] = "postgresql+asyncpg://migrator@127.0.0.1:5432/vulnscope"
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head", "--sql"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode != 0
    assert "cannot run with --sql" in proc.stderr
