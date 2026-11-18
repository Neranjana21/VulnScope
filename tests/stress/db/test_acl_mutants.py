# ruff: noqa: E501
"""Stress #3 (GR-STR-2): mutation harness for the ACL controls. R1.

Mutants are applied with PLAIN SQL on a scratch database, to a SCRATCH role
(vulnscope_stress_<uuid8>) that first receives the reference policy, so the shared cluster role
``vulnscope_app`` (cluster-global membership/attributes) is never altered. Within the scratch DB
``vulnscope_app`` is revoked everything first so that its real grants (post-fix) do not look like
foreign grantees.

Three detectors are exercised per mutant:
  * the independent oracle (stress_db_oracle)           -> green before the fix (tests the oracle itself)
  * the behavioural matrix as the scratch role          -> green before the fix; BLIND to TRIGGER,
    REFERENCES and GRANT OPTION mutants by construction (documented, not asserted)
  * the production helper (verify_effective_privileges / role_violations) -> RED before the fix
    (module does not exist), must raise/return non-empty after it.
A mutant left undetected by a detector that should see it is a FINDING (the test fails).
Results are appended to .reports/stress-records.jsonl.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

import asyncpg
import pytest
import stress_db_oracle as oracle
import vulnscope_db_plugin as kit

pytestmark = pytest.mark.integration


@dataclass(frozen=True)
class Mutant:
    id: str
    sql: tuple[str, ...]
    expect: str  # substring the oracle must report ({r} = scratch role)
    level: str  # "table" -> verify_effective_privileges, "role" -> role_violations
    behaviour: bool = False  # visible to the statement matrix?
    needs: tuple[str, ...] = ()  # extra scratch roles: "g" (third grantor), "grp" (group role)
    extra_probes: tuple[tuple[str, bool], ...] = field(default=())  # (statement, expected allowed)


MUTANTS = [
    Mutant("ledger_update", ('GRANT UPDATE ON TABLE public."ledger_entries" TO "{r}"',), "UNEXPECTED: ledger_entries", "table", True),
    Mutant("ledger_delete", ('GRANT DELETE ON TABLE public."ledger_entries" TO "{r}"',), "UNEXPECTED: ledger_entries", "table", True),
    Mutant("ledger_truncate", ('GRANT TRUNCATE ON TABLE public."ledger_entries" TO "{r}"',), "UNEXPECTED: ledger_entries", "table", True),
    Mutant("chain_heads_delete_truncate", ('GRANT DELETE, TRUNCATE ON TABLE public."chain_heads" TO "{r}"',), "UNEXPECTED: chain_heads", "table", True),
    Mutant("public_all_checkpoints", ('GRANT ALL ON TABLE public."checkpoints" TO PUBLIC',), "GRANTEE: checkpoints: PUBLIC", "table", True),
    Mutant("public_all_alembic_version", ('GRANT ALL ON TABLE public."alembic_version" TO PUBLIC',), "GRANTEE: alembic_version: PUBLIC", "table", True),
    Mutant("trigger_references_checkpoints", ('GRANT TRIGGER, REFERENCES ON TABLE public."checkpoints" TO "{r}"',), "UNEXPECTED: checkpoints", "table", False),
    Mutant(
        "column_update_ledger",
        ('GRANT UPDATE ("kind") ON TABLE public."ledger_entries" TO "{r}"',),
        "COLUMN-ACL: ledger_entries",
        "table",
        True,
        extra_probes=(('UPDATE public."ledger_entries" SET "kind" = "kind" WHERE false', False),),
    ),
    Mutant("grant_option_orgs", ('GRANT SELECT ON TABLE public."orgs" TO "{r}" WITH GRANT OPTION',), "GRANT-OPTION: orgs", "table", False),
    Mutant("missing_insert_ledger", ('REVOKE INSERT ON TABLE public."ledger_entries" FROM "{r}"',), "MISSING: ledger_entries", "table", True),
    Mutant(
        "third_grantor_update",
        (
            'GRANT UPDATE ON TABLE public."ledger_entries" TO "{g}" WITH GRANT OPTION',
            'SET ROLE "{g}"',
            'GRANT UPDATE ON TABLE public."ledger_entries" TO "{r}"',
            "RESET ROLE",
        ),
        "GRANTOR: ledger_entries",
        "table",
        True,
        needs=("g",),
    ),
    Mutant("member_pg_write_all_data", ('GRANT pg_write_all_data TO "{r}"',), "MEMBER-OF", "role"),
    Mutant("member_pg_read_all_data", ('GRANT pg_read_all_data TO "{r}"',), "MEMBER-OF", "role"),
    Mutant("member_pg_maintain", ('GRANT pg_maintain TO "{r}"',), "MEMBER-OF", "role"),
    Mutant("member_migrator", ('GRANT "{mig}" TO "{r}"',), "MEMBER-OF", "role"),
    Mutant("member_group_role", ('GRANT "{grp}" TO "{r}"',), "MEMBER-OF", "role", needs=("grp",)),
    Mutant("owns_chain_heads", ('ALTER TABLE public."chain_heads" OWNER TO "{r}"',), "OWNS", "role"),
    Mutant("attr_createdb", ('ALTER ROLE "{r}" CREATEDB',), "ATTRIBUTE", "role"),
    Mutant("attr_createrole", ('ALTER ROLE "{r}" CREATEROLE',), "ATTRIBUTE", "role"),
    Mutant("attr_bypassrls", ('ALTER ROLE "{r}" BYPASSRLS',), "ATTRIBUTE", "role"),
    Mutant("attr_replication", ('ALTER ROLE "{r}" REPLICATION',), "ATTRIBUTE", "role"),
    Mutant("attr_nologin", ('ALTER ROLE "{r}" NOLOGIN',), "ATTRIBUTE", "role"),
    Mutant("create_on_schema_public", ('GRANT CREATE ON SCHEMA public TO "{r}"',), "SCHEMA-CREATE", "role"),
    Mutant("create_on_database", ('GRANT CREATE ON DATABASE "{db}" TO "{r}"',), "DB-CREATE", "role"),
]
TABLE_MUTANTS = [m for m in MUTANTS if m.level == "table"]
BEHAVIOUR_MUTANTS = [m for m in MUTANTS if m.behaviour]


@pytest.fixture(scope="module")
def mutant_db(scratch_manager: kit.ScratchManager, stress_env: kit.StressEnv) -> Iterator[kit.ScratchDb]:
    if not stress_env.admin_is_superuser:
        pytest.skip("mutants need a superuser migrator (dev profile)")
    db = scratch_manager.create(migrate=True)
    # remove the real app role's grants inside this scratch DB only
    kit.execute(db.admin_dsn, 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM "vulnscope_app"')
    try:
        yield db
    finally:
        scratch_manager.drop(db)


@dataclass
class Armed:
    db: kit.ScratchDb
    role: str
    password: str
    mutant: Mutant | None
    params: dict[str, str]

    @property
    def role_dsn(self) -> str:
        return kit.to_dsn(kit.with_user(self.db.app_url, self.role, self.password))


@pytest.fixture
def armed_factory(
    mutant_db: kit.ScratchDb, scratch_manager: kit.ScratchManager, stress_env: kit.StressEnv
) -> Iterator[object]:
    made: list[str] = []

    def arm(mutant: Mutant | None) -> Armed:
        role, pw = scratch_manager.new_role(mutant_db)
        made.append(role)
        params = {"r": role, "db": mutant_db.name, "mig": stress_env.admin_user}
        for n in mutant.needs if mutant else ():
            other, _ = scratch_manager.new_role(mutant_db, login=False)
            made.append(other)
            params[n] = other
        kit.execute(mutant_db.admin_dsn, *oracle.reference_grant_sql(role))
        if mutant:
            kit.execute(mutant_db.admin_dsn, *[s.format(**params) for s in mutant.sql])
        return Armed(mutant_db, role, pw, mutant, params)

    try:
        yield arm
    finally:
        kit.execute(mutant_db.admin_dsn, 'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC')
        for name in reversed(made):
            if name in mutant_db.roles:
                scratch_manager.drop_role(mutant_db, name)


def _oracle(armed: Armed) -> list[str]:
    async def go(conn: asyncpg.Connection) -> list[str]:
        return await oracle.violations(conn, armed.role)

    return kit.with_conn(armed.db.admin_dsn, go)


def _matrix_mismatches_impl(armed: Armed) -> list[str]:
    admin_cols = {
        t: [
            r["attname"]
            for r in kit.fetch(
                armed.db.admin_dsn,
                "SELECT attname FROM pg_attribute WHERE attrelid = ('public.' || quote_ident($1))::regclass "
                "AND attnum > 0 AND NOT attisdropped ORDER BY attnum",
                t,
            )
        ]
        for t in oracle.ALL_TABLES
    }

    async def go(conn: asyncpg.Connection) -> list[str]:
        assert await conn.fetchval("SELECT current_user::text") == armed.role
        bad: list[str] = []
        for t in oracle.ALL_TABLES:
            for v in oracle.VERBS:
                state, detail = await oracle.run_probe(conn, oracle.probe_statement(t, v, admin_cols[t]))
                if state == "unexpected":
                    bad.append(f"{t} {v}: probe error {detail}")
                elif (state == "allowed") != oracle.expected_verb_allowed(t, v):
                    bad.append(f"{t} {v}: {state}")
        if armed.mutant:
            for stmt, want in armed.mutant.extra_probes:
                state, _ = await oracle.run_probe(conn, stmt)
                if (state == "allowed") != want:
                    bad.append(f"extra probe {stmt!r}: {state}")
        return bad

    return kit.with_conn(armed.role_dsn, go)


@pytest.mark.parametrize("mutant", MUTANTS, ids=[m.id for m in MUTANTS])
def test_oracle_detects_mutant(armed_factory: Callable[[Mutant | None], Armed], mutant: Mutant) -> None:
    armed = armed_factory(mutant)
    found = _oracle(armed)
    want = mutant.expect.replace("{r}", armed.role)
    kit.record("mutant", {"id": mutant.id, "detector": "oracle", "detected": any(want in v for v in found)})
    assert any(want in v for v in found), (
        f"MUTANT UNDETECTED by the oracle: {mutant.id}; expected a violation containing {want!r}, "
        f"got {found!r}"
    )


@pytest.mark.parametrize("mutant", BEHAVIOUR_MUTANTS, ids=[m.id for m in BEHAVIOUR_MUTANTS])
def test_behavioural_matrix_detects_mutant(armed_factory: Callable[[Mutant | None], Armed], mutant: Mutant) -> None:
    armed = armed_factory(mutant)
    bad = _matrix_mismatches_impl(armed)
    kit.record("mutant", {"id": mutant.id, "detector": "matrix", "detected": bool(bad)})
    assert bad, f"MUTANT UNDETECTED by the behavioural matrix: {mutant.id}"


@pytest.mark.parametrize("mutant", MUTANTS, ids=[m.id for m in MUTANTS])
def test_production_helper_detects_mutant(armed_factory: Callable[[Mutant | None], Armed], mutant: Mutant) -> None:
    mg = kit.lazy("vulnscope.db.migration_grants")
    rc = kit.lazy("vulnscope.db.role_checks")
    armed = armed_factory(mutant)
    if mutant.level == "table":
        with pytest.raises(mg.MigrationPreconditionError):
            kit.run_sync_helper(
                armed.db.admin_url,
                lambda conn: mg.verify_effective_privileges(conn, armed.role, oracle.expected_map()),
            )
        kit.record("mutant", {"id": mutant.id, "detector": "verify_effective_privileges", "detected": True})
    else:
        problems = kit.run_sync_helper(armed.db.admin_url, lambda conn: rc.role_violations(conn, armed.role))
        kit.record("mutant", {"id": mutant.id, "detector": "role_violations", "detected": bool(problems)})
        assert problems, f"MUTANT UNDETECTED by role_violations: {mutant.id}"


def test_reference_baseline_is_clean_for_oracle_and_matrix(armed_factory: Callable[[Mutant | None], Armed]) -> None:
    armed = armed_factory(None)
    assert _oracle(armed) == [], "baseline (no mutation) must have zero oracle violations"
    assert _matrix_mismatches_impl(armed) == [], "baseline must have zero behavioural mismatches"


def test_reference_baseline_is_clean_for_production_helper(armed_factory: Callable[[Mutant | None], Armed]) -> None:
    mg = kit.lazy("vulnscope.db.migration_grants")
    rc = kit.lazy("vulnscope.db.role_checks")
    armed = armed_factory(None)
    kit.run_sync_helper(
        armed.db.admin_url,
        lambda conn: mg.verify_effective_privileges(conn, armed.role, oracle.expected_map()),
    )
    assert kit.run_sync_helper(armed.db.admin_url, lambda conn: rc.role_violations(conn, armed.role)) == []
